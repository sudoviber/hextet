# ADR-0009：macOS 设备编排——boringtun 独占 utun、平台按名配装、up/daemon 的进程生命周期边界

- 状态：已接受
- 日期：2026-08-12
- 相关：`docs/adr/ADR-0007-gotatun-userspace-backend.md`（boringtun 无 `Tun`/`udp` trait、
  `set_peer_endpoint` 缺口）、`docs/adr/ADR-0008-macos-platform-networking.md`（net-route/getifaddrs/
  最小安全封装）、`docs/superpowers/specs/2026-08-06-hextet-design.md` §8 M4 / §9 / §10 / §13、
  `docs/superpowers/plans/2026-08-12-m4-macos-and-routers.md` Task 34「⚠️ 已知缺口」与 Task 35、
  `crates/wg-userspace/src/lib.rs`、`crates/platform/src/{lib,macos,tun,linux}.rs`、
  `crates/engine/src/spec.rs`、`crates/cli/src/commands/{up,down,status}.rs`

## 背景

M4 的目标（spec §8）是「macOS 上 gotatun 用户态数据面 + utun 建立 hextet0，`hextet up`/
`down`/`daemon` 可用」。三条已确认的硬事实在 macOS 上互相打架：

1. macOS 数据面是 boringtun（ADR-0007 过渡后端），其 `DeviceHandle::new(name, …)` **独占** utun
   设备并通过 `/var/run/wireguard/{name}.sock` 的 Unix socket 文本协议控制它；`UserspaceBackend`
   内部已经持有 `Mutex<HashMap<String, DeviceHandle>>` 这个注册表。**设备归后端所有，不归
   `platform::setup_interface`。**
2. `platform::setup_interface` 目前**自己再开一个** `TunHandle`（第二个、独立的设备），返回时
   把句柄 drop——开错了设备，而且那个 utun 一 drop 就自动销毁（Task 34「⚠️ 已知缺口」）。
3. boringtun 在 macOS 上要求接口名必须是 `utun`/`utunN`；hextet 的配置/`DeviceSpec.interface` 是
   `hextet0`。

本 ADR 要裁定六件事：设备所有权与职责切分、utun 命名映射、`setup_interface` 的最小诚实签名
变化、`hextet up` 的编排时序、`down`/`delete_interface` 的 macOS 语义、以及本设计之后仍被阻塞
的部分。硬约束：只做设计记录，不改 Rust 代码、不加依赖；boringtun 事实以
`~/.cargo/registry/src/*/boringtun-0.7.1/` 源码为准，查不到的写「未能验证」。

本轮在 boringtun 0.7.1 源码里**已确认**的事实（逐条给出出处）：

| 事实 | 出处 |
|---|---|
| `DeviceHandle::new(name, config)` 只接收**一个**名字，`Device::new` 直接把它当隧道名传给 `TunSocket::new(name)`；没有「wg 名字」与「tun 名字」之分 | `src/device/mod.rs:170`、`353–357` |
| macOS 上 `TunSocket::new` 先 `parse_utun_name`，任何不以 `utun` 开头的名字直接返回 `Error::InvalidTunnelName`（所以传 `hextet0` 必失败） | `src/device/tun_darwin.rs:69–86`、`118–119` |
| `parse_utun_name("utun")`（裸名字）→ 0，内核选最低可用 index；`parse_utun_name("utunN")` → N+1 作为 `sc_unit`，内核精确分配 `utunN` | `src/device/tun_darwin.rs:74–85`、`137–154` |
| **`get=1` 响应不包含 tun/设备名**：`api_get` 只输出 `own_public_key`/`listen_port`/`fwmark` + 每 peer 的 `public_key`/`preshared_key`/`persistent_keepalive_interval`/`endpoint`/`allowed_ip`/`last_handshake_time_sec`/`last_handshake_time_nsec`/`rx_bytes`/`tx_bytes`，最后 `errno=0` | `src/device/api.rs:157–202` |
| `Device`/`DeviceHandle` **没有**对外暴露真实 tun 名的公开访问器：`Device.iface`（`Arc<TunSocket>`）是私有字段，`TunSocket::name()`（`getsockopt(UTUN_OPT_IFNAME)`）只被内部使用 | `src/device/mod.rs:132–161`、`src/device/tun_darwin.rs:173–191` |
| 真实名字唯一的上报机制是 **`WG_TUN_NAME_FILE` 环境变量**：macOS 专属、且**仅当请求名 == `"utun"`** 时，`Device::new` 把 `device.iface.name()` 写进该变量指向的文件；文件名也用于 `cleanup_paths` | `src/device/mod.rs:396–405` |
| API socket 路径是 `/var/run/wireguard/{iface.name()}.sock`，即 socket 文件名本身编码了真实名字（`register_api_handler` 用 `self.iface.name()`） | `src/device/api.rs:40–47` |
| `DeviceConfig` **没有 mtu 字段**（只有 `n_threads`/`use_connected_socket`/linux 的 `use_multi_queue`/`uapi_fd`），boringtun 不能设置 MTU，只读 `iface.mtu()`（utun 默认 1500） | `src/device/mod.rs:109–130`、`357–358` |

## 决策

### 决策 1：设备所有权——backend 是 utun 的唯一 owner，platform 只按名配装

确认 boringtun/`UserspaceBackend` 是 macOS 上 utun 的**唯一** owner：它创建设备、持有
`DeviceHandle`、跑数据面（加密/解密 + UDP + TUN 读写）、并对设备生命周期负责。修正后的职责切分：

- **backend（`wg-userspace`）**：创建 + 独占 utun + 数据面 + 上报真实设备名。
- **platform（`macos.rs`）**：只做「按名」配装——`assign_ipv6(name, …)`（配 overlay 地址）、
  `add_route`/`remove_route(name, …)`（路由）、`list_global_ipv6`（读）。**绝不自己开第二个设备。**

`platform::setup_interface` 的 macOS 实现必须删掉 `open_tun` 那一步（macos.rs:204 当前在开自己的
`TunHandle`），改为与 Linux 同构的「对已存在设备按名配地址」语义。Linux 版 `setup_interface` 本就
不开设备（内核 WG 持有设备，它只 `link_index` 找名字 + 配地址/MTU/up），所以这条是把 macOS 拉到
与 Linux 相同的语义，而不是发明新语义。

### 决策 2：utun 命名——加一层 `hextet0 → utun` 映射，用裸 `utun` 让内核选名、用 `WG_TUN_NAME_FILE` 读回

三个备选的取舍：

- **(a) 把配置名 `hextet0` 原样传给 boringtun**：被 `parse_utun_name` 拒绝（`InvalidTunnelName`），
  **否决**（现有 `wg-userspace` 的 doc 注释已如实上报这个错误，本 ADR 补齐解法）。
- **(c) 要求用户在 macOS 上把接口名写成 `utun`/`utunN`**：改动用户可见配置、破坏「配置文件跨
  平台同名」的诉求（Linux 上接口就是 `hextet0`），**否决**。
- **(b) 映射层（采纳）**：config 名 `hextet0` 是用户/`DeviceSpec` 层的名字；backend 内部把它映射
  成裸 `utun`（内核选最低可用 index，避免与 Tailscale 等既有 utun 冲突），并**读回真实名字**
  `utunN` 上报给平台配装。

读回真实名字用 boringtun 官方的 `WG_TUN_NAME_FILE` 机制：`DeviceHandle::new` **之前**把该环境变量
指向一个临时文件，创建后用裸 `utun`（内核选名），再读该文件得到 `utunN`。这也是 wireguard-go 的
同款行为（boringtun README 明确写了这条）。**代价/坑**见「代价与再评估」与「未能验证」——核心是
`std::env::set_var` 在 Rust 2024 + 工具链 ≥1.88 下是 `unsafe`，而本工作区 `edition = "2024"` 且
`unsafe_code = "deny"`，需要一处刻意、收窄的 allow（镜像 ADR-0008 的「最小安全封装」先例），或退到
决策 2 的备选：由编排层挑一个确定且空闲的 `utunN`（此时真实名 == 请求名，无需读回）。

### 决策 3：签名变化——`WgBackend::apply` 改返回真实设备名；macOS `setup_interface` 只改体、不改签名

最小诚实的签名变化只有一处 trait：让 `apply` 返回 OS 层真实设备名，供调用方随后按名配地址/路由。
Linux 恒返回 `spec.interface.clone()`（语义不变），macOS/boringtun 返回读回/挑定的 `utunN`。

```rust
// crates/wg/src/lib.rs
pub trait WgBackend {
    /// 幂等地把设备调到 spec 状态，并返回 OS 层真实设备名（供平台按名配地址/路由）。
    /// Linux：恒等于 spec.interface（内核 WG 设备名即配置名）；
    /// macOS/boringtun：真实 utunN（配置名 hextet0 经决策 2 的映射层得到）。
    fn apply(&self, spec: &DeviceSpec) -> Result<String, WgError>;
    // status / set_peer_endpoint / add_peer / remove_peer 签名不变
}
```

平台侧 `setup_interface` **签名不变**（`(name, address, prefix_len, mtu) -> Result<(), PlatformError>`），
只改 macOS 函数体：删掉 `open_tun`，改为 `assign_ipv6(name, address, prefix_len)`；`mtu` 在 macOS
boringtun 上无法经其设置（决策「未能验证」），第一片先按 no-op 处理并如实标注，必要时补
`SIOCSIFMTU` 按名 ioctl。`name` 的语义从「我们想开的名字」变成「backend 上报的真实名字」。

同步要改的调用点：`crates/wg/src/kernel.rs`、`crates/wg/src/mock.rs` 的 `apply` 返回
`Ok(spec.interface.clone())`；`crates/engine/src/daemon.rs` 与 `crates/cli/src/commands/up.rs` 接住
返回值再传给 `setup_interface`。

### 决策 4：`hextet up` 编排时序（macOS）

从配置到「设备就位 + 地址 + 路由」的伪代码（macOS；Linux 路径行为不变，只是 `apply` 多返回一个
恒等名字）：

```text
(cfg, id)       = load_config_and_identity()
own             = derive_node_addr(cfg.prefix, id.public())          // 本节点 overlay 地址
spec            = build_device_spec(&cfg, &id)                       // spec.interface == "hextet0"

backend         = platform_default_backend()                         // macOS → UserspaceBackend
real_name       = backend.apply(&spec)                               // 内部 hextet0→utun；返回 "utunN"
setup_interface(real_name, own.address, PREFIX_LEN /*48*/, cfg.node.mtu)  // 只按名配地址，不开设备
add_route(real_name, cfg.prefix.network(), 48)                       // 显式加 overlay /48（见下）
println!("up: hextet0 -> {real_name} {own}")                         // 上报真实名字给用户
```

关于路由的两点诚实说明：

- **/48 overlay 路由**：Linux 上「给 wg 接口配 `node_addr/48`」由内核自动下一条直连 /48 路由；
  macOS 上用 `SIOCAIFADDR_IN6` 配带前缀掩码的地址同样会由内核自动下直连路由，但为了与 Linux 语义
  明确对齐、也为了不依赖这个未真机验证的自动行为，本 ADR **显式** `add_route(real_name, prefix, 48)`。
- **per-peer / site-to-site 通告路由**：不进 `up`，仍由 daemon 的 `RouteManager` 在 `Connected` 时
  按需 `add_route`/`remove_route`（与 Linux 一致，`engine/src/daemon.rs` 的 `sync_peer_routes`）。

`status`/`doctor`（只读）在 macOS 上经同一 `backend.status(real_name)` / `platform::list_global_ipv6`
完成，不碰设备创建，无生命周期问题。

### 决策 5：`delete_interface`/`hextet down`——macOS 上「设备随 handle drop 自动销毁」，down 落在 backend + 移除路由

macOS 的 utun 在**所有 fd 关闭时自动销毁**（`tun` crate 与 boringtun 的 `TunSocket::drop` 都 `close(fd)`）。
因此 `delete_interface` **不需要**也**没有**一个「按名删设备」的 ioctl（Linux 的 `ip link del` 没有
macOS 等价物）：

- `crates/platform/src/macos.rs::delete_interface` 保持 `Unsupported`（诚实），并改写 doc：不是能力
  缺口，而是「设备归 backend、随句柄销毁，平台无删设备的落点」。
- macOS 的 `down` = **backend 从注册表 drop 对应 `DeviceHandle`**（设备随进程内句柄释放而消失）+
  **平台 `remove_route`** 清掉 /48 与通告路由。落点建议：给 `WgBackend` 增加
  `fn down(&self, interface: &str) -> Result<(), WgError>`（macOS 后端从 `devices` map 移除句柄；
  Linux 内核后端返回 `WgError::Backend("use platform::delete_interface")` 或直接委托 rtnetlink——实现
  时定，不在本 ADR 定死），`hextet down` 在 CLI 里按平台分派：Linux 走 `platform::delete_interface`，
  macOS 走 `backend.down` + `remove_route`。

**关键诚实点（与决策 6 联动）**：macOS 上设备生命周期 == 持有 `DeviceHandle` 的进程生命周期。一个
one-shot 的 `hextet up` 进程一退出，`UserspaceBackend` 就析构、utun 立即消失——所以 macOS 上没有
Linux 那种「`up` 之后设备常驻、`down` 再来拆」的模型。真正的 `down` 只对**长驻进程**（daemon /
launchd 托管的 daemon）有意义。

### 决策 6：本设计之后仍被阻塞的部分（诚实边界）

1. **`hextet daemon`（打洞循环）仍被 boringtun 的 `set_peer_endpoint` 缺口挡住**（ADR-0007 已记）：
   `update_peer` 对已存在 peer 直接 `panic!`、`set=1` 无「只改 endpoint」的增量操作，macOS 后端诚实
   返回 `WgError::Backend`。这一条**不因本 ADR 而解除**，须等 boringtun→gotatun 切换（ADR-0007 再评估
   触发 1）。
2. **`hextet up` 的 macOS 持久性弱于 Linux**：即便本 ADR 的编排全部落地，one-shot `hextet up` 只能
   「创建 + 配装 + 上报」，进程退出设备即消失。要让 hextet0 常驻，必须是长驻的 `hextet daemon`
   （再由 Task 33 的 launchd 托管）。这是用户态数据面的固有语义，不是 bug，要写进安装文档。
3. **本机（dev 机）无法真跑**：`hextet up` 的编排**可以现在实现并通过 `cargo build` 编译验证**，但
   运行时路径需要 root + 真实 utun（`sudo`），本机 macOS 环境不提供（与 ADR-0007/0008 的 root 分层
   测试口径一致）。真实 macOS 端到端（utun + 地址 + 路由 + boringtun 握手 + 互 ping）须在真机/CI 跑。
   今晚可交付的边界：**代码 + 编译验证 + ADR/计划文档**；**不可交付**：真机运行验证。

## 理由（决策 1/2/3 的取舍对照）

- **决策 1 为什么是「backend 独占、platform 按名」而不是让 platform 持有句柄**：boringtun 的
  `DeviceHandle` 已经把「TUN 设备 + 事件循环 + UDP socket + API socket」绑成一个对象，句柄一丢整套
  数据面就停。让 `platform` 再持一份 TUN 句柄（甚至再开一个设备）只会制造两个设备、两套生命周期，
  与「用户态数据面由 backend 跑」的架构（ADR-0007 决策 1/3）直接冲突。platform 的职责收敛为
  「按名配地址/路由」，与 Linux 侧的既有语义完全同构。
- **决策 2 为什么选裸 `utun` + `WG_TUN_NAME_FILE` 而不是固定 `utunN`**：裸 `utun` 让内核选最低可用
  index，天然避开 Tailscale/其他 VPN 已经占用的 utun；固定 `utunN` 要么撞 index、要么自己扫空闲
  index（多一段脆弱逻辑）。`WG_TUN_NAME_FILE` 是 boringtun/wireguard-go 官方承认的读回通道，代价是
  那个 `unsafe` 的 env 设置（见下），用一处收窄 allow 换一个标准机制，值得。若团队对「再多一处
  allow」零容忍，退到「编排层挑确定空闲 `utunN`」备选，此时 `apply` 返回值退化为恒等但签名不变。
- **决策 3 为什么是改 `apply` 返回名、而不是拆 `create_device` + `assign_address_and_routes`**：
  设备创建已经内聚在 `apply`（幂等），拆成 `create_device` 会把「创建 + 配 WG」这一原子操作劈成两半、
  还要处理「设备已存在」的重入；返回真实名字只是给 `apply` 的返回值加一点信息，Linux 侧零语义变化。
  `setup_interface` 签名保持 `(name, addr, prefix, mtu)`——它**已经是**「按名」语义，只是 macOS 实现
  错加了一步 `open_tun`，改体即对齐，无需改名拆函数。
- **决策 5 为什么 `delete_interface` 保持 `Unsupported` 而非伪造**：与 ADR-0007/0008 的一贯立场一致，
  「没有等价物就不假装支持」；把「删设备」的责任明确归还给唯一拥有设备的 backend，比在 platform 里
  放一个永远无操作的桩更诚实。

## 代价与再评估

- **`WG_TUN_NAME_FILE` 的 `unsafe`**：`std::env::set_var` 在 Rust 2024 + 工具链 ≥1.88 下是 `unsafe fn`，
  本工作区 `edition = "2024"`、`unsafe_code = "deny"`。要读回真实名字，要么在 backend 侧新增一处
  `#![allow(unsafe_code)]` 的小封装（镜像 ADR-0008 对 `SIOCAIFADDR_IN6` 的「被迫且最小」例外，只包
  `set_var`/`get_var` 各一次），要么改用决策 2 备选（编排层挑空闲 `utunN`，零 unsafe）。**触发重新
  评估的条件**：团队决定「零新增 unsafe 点」，或实测发现多进程并发设 `WG_TUN_NAME_FILE` 出现覆盖竞态。
- **裸 `utun` 的读回时序**：`WG_TUN_NAME_FILE` 只有在「请求名 == `utun`」时才会写文件；若 future 切
  到显式 `utunN`，此机制自动失效，需回归到「请求名即真实名」的恒等路径。已在决策 2 写明。
- **MTU 缺口**：boringtun `DeviceConfig` 无 mtu，`cfg.node.mtu`（1400）无法经后端施加；utun 默认
  1500 会造成与 Linux 1400 的不一致（overlay 分片/PMTUD 行为差异）。第一片先 no-op + 文档标注；
  若真机测出问题，补 `SIOCSIFMTU` 按名 ioctl（进 platform 的 macOS 最小封装，仍是收窄 unsafe）。
- **one-shot `up` 的持久性误导风险**：用户可能以为 macOS `hextet up` 和 Linux 一样会留下一个常驻
  接口。必须在 `docs/guides/install.md` 的 macOS 章节明确写「macOS 设备随进程存在，常驻请用
  `hextet daemon`（launchd）」，否则会是一个文档级的事故。
- **`set_peer_endpoint` / `daemon` 仍阻塞**：见决策 6，与 ADR-0007/0008 的排序一致，本 ADR 不解除。

### 重新评估的触发条件

1. **gotatun 发布 1.0 或 2026 审计通过**（ADR-0007 触发 1）→ 切 gotatun，届时重估设备所有权（gotatun
   有自己的 `tun` trait，`platform::tun` 适配器才真正用得上）与 `set_peer_endpoint`/`daemon` 的可用性。
2. **团队拒绝新增 unsafe 点 / 多进程 `WG_TUN_NAME_FILE` 竞态实锤** → 决策 2 退到「编排层挑空闲
   `utunN`」备选。
3. **真机测出 MTU 不一致导致 overlay 分片/连接问题** → 补 `SIOCSIFMTU` 按名 ioctl（platform 最小封装）。

## 未能验证（落地前须确认）

- **boringtun 是否还有其他公开 API 能上报 tun 名**：已通读 `Device`/`DeviceHandle`/`TunSocket` 公开面，
  结论是没有（`iface` 私有、无 getter、`get=1` 无名字字段）；唯一通道是 `WG_TUN_NAME_FILE`（macOS +
  裸 `utun`）或 socket 文件名。**须在实现时再核对一次 0.7.1 是否有我漏掉的 re-export 或 feature 门**。
- **`std::env::set_var` 在「工作区实际工具链」下的 safe/unsafe 状态**：工作区 `rust-version = "1.85"`、
  `edition = "2024"`；`set_var` 的 unsafe 化随工具链版本（≥1.88）与 edition 2024 生效。本机实际工具链
  未在本文查证——须在实现时确认，决定是否要 `#![allow(unsafe_code)]` 小封装。
- **`SIOCAIFADDR_IN6` 带 `/48` 掩码在 utun 上是否自动下直连 /48 路由**：未真机验证（ADR-0008 已列
  `ifra_dstaddr`/`ifra_lifetime` 的同类未验证项）。决策 4 因此显式 `add_route(prefix, 48)` 兜底，不依赖
  自动行为。
- **`net-route` 的「无网关仅出接口」IPv6 路由真机落表**：ADR-0008「未能验证」延续，决策 4/5 里的
  `add_route`/`remove_route` 均依赖它，真机验证失败即触发 ADR-0008 的 fork/vendor 预案。
- **`hextet down` 在 macOS 的最终分派形态**：决策 5 提出 `WgBackend::down`，但 Linux 内核后端是否把它
  做成「委托 `platform::delete_interface`」还是「直接返回错误让 CLI 分派」留待实现时定；本文不假装已定。
