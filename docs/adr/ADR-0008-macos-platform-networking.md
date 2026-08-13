# ADR-0008：macOS 平台网络能力——路由走 net-route、枚举走 getifaddrs、地址配装走最小安全封装

- 状态：已接受
- 日期：2026-08-12
- 相关：`docs/superpowers/specs/2026-08-06-hextet-design.md` §9 / §10 / §13、
  `docs/adr/ADR-0007-gotatun-userspace-backend.md`（「代价与再评估」里的 macOS 地址/路由缺口）、
  `crates/platform/src/lib.rs`（非 Linux 桩）、`crates/platform/src/linux.rs`（需镜像的语义）、
  `crates/platform/src/tun.rs`（TUN 设备抽象）、`crates/platform/Cargo.toml`、
  `deny.toml`、`crates/discovery/Cargo.toml`（`mainline = "=8.0.0"` 精确锁定先例）

## 背景

M4 要让 `hextet up`/`daemon` 在 macOS（arm64/x86_64）真正跑起来。`crates/platform` 是
「接口/地址/路由/服务化」的平台抽象层，但 `lib.rs` 里对非 Linux 平台只有 `stub`：四个
能力——`setup_interface`、`add_route`/`remove_route`、`list_global_ipv6`、
`watch_ipv6_addresses`——全部返回 `PlatformError::Unsupported`（`delete_interface` 与
`list_multicast_interfaces` 也在桩里，属同一批缺口）。ADR-0007 已把 TUN **设备**的
打开/读写/关闭用 `tun` crate 落地，并明确记录：`open_tun` 只给设备，utun 的地址与路由
仍需要 macOS 侧的 `setup_interface`/`add_route`——这是 Task 32 的隐含后续，需单独评估
`net-route`（spec §13 已列「net-route 维护弱，mac/Win 保留 fork 预案」）。

本 ADR 要裁定的四件事：地址配装与路由怎么实现、地址枚举与变化监听怎么实现、第一片做到
哪、与 ADR-0007 的 `set_peer_endpoint` 缺口的先后关系。硬约束：`Cargo.toml` 根上的
`[workspace.lints.rust] unsafe_code = "deny"`（edition 2024、`rust-version = "1.85"`），
即**我们自己的代码里不许出现 `unsafe`**；ADR-0007 已据此拒绝手写 utun/ioctl unsafe，把
unsafe 内聚进第三方 crate。

本轮查证到的外部事实（截至 2026-08-12，来自 crates.io / docs.rs / GitHub API / 仓库
源码，未在本机下载或安装任何东西）：

| crate | 最新版 | 许可证 | 关键点 |
|---|---|---|---|
| `net-route` | **0.4.6**（2025-04-16 发布） | **MIT** | repo `github.com/johnyburd/net-route`，最近一次 push **2026-04-03**，20 个 open issue、31 star、64 commit。安全 API：`Handle::new()` + `Handle::add(&Route)` / `Handle::delete(&Route)`（async）；`Route { destination: IpAddr, prefix: u8, gateway: Option<IpAddr>, ifindex: Option<u32> }`，构造 `Route::new(prefix, prefix_len)` + builder `with_ifindex`/`with_gateway`。macOS 实现走 **PF_ROUTE `RTM_ADD`/`RTM_DELETE`**（不是 `SIOCADDRT`），IPv6 支持（`sockaddr_in6`/`AF_INET6`），macOS 额外 re-export `ifname_to_index`。**只做路由，不做地址配装**。 |
| `getifaddrs` | **0.6.2**（2026-05-10 发布） | **MIT OR Apache-2.0** | 安全 API：`getifaddrs()` 返回 `Interface { name, flags, address }`，`address.ip_addr()`/`netmask()`/`mac_addr()`，另有 `if_nametoindex`/`if_indextoname`。枚举接口+地址用，公开面零 unsafe。 |
| `system-configuration` | **0.8.0**（2026-08-11 发布） | **MIT OR Apache-2.0** | repo `github.com/mullvad/system-configuration-rs`，57 star、11 open issue，最近 push 2026-08-11。SCDynamicStore 通知是**回调式**（`SCDynamicStoreCallBackContext` / `SCDynamicStoreCallBackT`），未确认有 tokio/channel 的异步订阅面，runloop/dispatch 集成未验证。 |
| `nix` | **0.31.3**（2026-05-11 发布） | **MIT** | MSRV 1.69。关键事实：`ioctl_readwrite!` 等宏生成的函数签名是 **`pub unsafe fn(FUNCTION)(fd: libc::c_int, data: *mut T) -> Result<libc::c_int>`**——即 nix 的 ioctl 包装**仍是 unsafe**，不是安全 API。 |
| `tun`（meh/rust-tun） | 0.8.14（ADR-0007 已锁） | WTFPL | macOS 模块（`src/platform/macos/sys.rs`）的地址配装只有 **`ioctl_write_ptr!(siocaifaddr, b'i', 26, ifaliasreq)`**——`SIOCAIFADDR` + `ifaliasreq` 是 **IPv4 专用**；全文件**没有** `sockaddr_in6` / `SIOCAIFADDR_IN6` / `in6_aliasreq`。即 `tun` crate 在 macOS 上**不能给 utun 配 IPv6 地址**。 |

RUSTSEC 结论：`net-route`、`getifaddrs`、`system-configuration` 在 rustsec/advisory-db
下均无对应目录 → **无已知公开 advisory**；`nix` 有一条 `RUSTSEC-2021-0119`
（`getgrouplist` 越界写，影响 `<0.23.0`，0.23.0+ 已修复——若用 nix 也是 0.31.3，不受影响）。
以上以 CI 的 `cargo-deny check` / `cargo-audit` 为最终事实来源，与 `CONTRIBUTING.md`
立场一致。

## 决策

### 决策 1：路由走 `net-route`，地址配装走「最小安全封装」新 crate

- **路由（`add_route`/`remove_route`）**：用 `net-route`，锁死 `net-route = "=0.4.6"`，
  放 `crates/platform/Cargo.toml` 的 `[target.'cfg(target_os = "macos")'.dependencies]`。
  它的 macOS 实现（PF_ROUTE + IPv6）是安全 API，调用方零 unsafe，与 Linux 的 rtnetlink
  实现形成同构替代。`Route { destination, prefix, gateway: None, ifindex: Some(ifname_to_index(name)?) }`
  对应 Linux 侧「只设 oif、不设网关」的语义（WG 隧道是点到多点链路，网关由 AllowedIPs 决定）。
  **风险与 fork 预案**：net-route 维护确实偏弱（0.4.5→0.4.6 隔 5 个月，最近 push 距今
  约 4 个月，20 个 open issue），spec §13「维护弱，mac/Win 保留 fork 预案」**成立但未到
  弃养**。若真机验证发现其 macOS「无网关、仅出接口」路由编码不对（见「未能验证」），
  按 §13 预案把它 ~200 行的 PF_ROUTE 路径 vendor 进我们自己的 crate——`crates/platform`
  是唯一接触点，切换不波及其他 crate。

- **地址配装（`setup_interface` 的地址部分）**：**没有维护中的安全 crate 可承接**。三个
  都查证过：`tun` crate 的 macOS 地址配装是 IPv4 专用（`SIOCAIFADDR` + `ifaliasreq`，
  无 `sockaddr_in6`）；`nix` 的 ioctl 宏生成的仍是 `unsafe fn`；`net-route` 只做路由。
  因此唯一能落地地址配装的路径是**我们自己写一个最小安全封装**——新建 crate
  `crates/platform-macos`（或 `crates/platform/src/macos.rs` + 模块级
  `#![allow(unsafe_code)]`，二选一，实现时定），只封装两到三个 ioctl：
  `if_nametoindex` + `SIOCAIFADDR_IN6`（`in6_aliasreq`，配地址+前缀）/ `SIOCDIFADDR_IN6`
  （删地址），MTU 已由 `tun` crate 在 `open_tun` 时用 `config.mtu()` 设置，无需再动。
  对外只暴露安全 API（如 `assign_ipv6(name, addr, prefix_len)` / `unassign_ipv6(name, addr)`），
  unsafe 被圈在 ~30 行内。依赖仅 `libc`（工作区已有 `libc = "0.2"`，稳定版 0.2.189）。

  **这是对 ADR-0007「不手写 unsafe」的一条刻意、收窄的例外**，理由见「理由」。若团队
  决定「零手写 unsafe」这条线一步不退，则回退到决策 1 的变体：路由仍走 `net-route`，
  地址配装**推迟**（option c），`hextet up` 在 macOS 上只「建 utun + 加路由」，overlay
  地址需手工 `ifconfig utun0 inet6 fdXX::…/48` 后测试——这条回退路径本 ADR 一并写明，
  不静默吞掉。

- **`delete_interface`**：macOS 上 utun 在所有 fd 关闭时自动销毁（`tun` crate 的
  `close_tun` 已覆盖），`delete_interface` 映射为关闭设备句柄，无需额外 ioctl。
- **`list_multicast_interfaces`**：同 `list_global_ipv6` 用 `getifaddrs`，按 `IFF_UP | IFF_MULTICAST`
  且排除 loopback/hextet 接口过滤即可（属同一批 getifaddrs 实现，随决策 2 一并落地）。

### 决策 2：枚举与监听都用 `getifaddrs`，监听先轮询、SCDynamicStore 留作再评估

- **`list_global_ipv6`**：用 `getifaddrs`（锁 `getifaddrs = "=0.6.2"`，放
  `crates/platform/Cargo.toml` 的 macOS target 依赖）。过滤复用 `hextet_core::addr::is_usable_endpoint_addr`
  （排除 ULA / 链路本地 / loopback / 组播 / unspecified）+ 排除 hextet 自己的接口。
  **诚实差异**：Linux 侧额外用 netlink 的 `scope == Universe` 与
  `Deprecated/Tentative/Dadfailed` 标志过滤；`getifaddrs` 拿不到每个地址的
  Deprecated/Tentative 标志（那是 `SIOCGIFAFLAG_IN6` / 路由套接字才有的，unsafe），
  只能拿到接口级 `IFF_*`。好在 `is_usable_endpoint_addr` 已经把链路本地/loopback/ULA 都
  排了，实际剩余差异只有「Deprecated/Tentative 旧地址也会短暂出现在结果里」——代价是
  endpoint 探测偶尔会试一个即将失效的地址，engine 的候选轮换本就容忍，**不作为第一片
  阻塞项**；若要补足，属后续 unsafe 封装的范围，本 ADR 明确推迟。
- **`watch_ipv6_addresses`**：**先轮询 `getifaddrs`**，推荐周期 **2s**，与上一帧做差集、
  发 `AddrEvent`（Added/Removed），去抖交给 daemon（`AddrEvent` 的文档已声明调用方自去抖）。
  选轮询而非 `SCDynamicStore` 通知：后者是回调+runloop 模型，`system-configuration` crate
  未提供 tokio/channel 的异步订阅面（未能验证其 runloop 集成成本），引入它比一个 2s 的
  `tokio::time::interval` 轮询重得多；2s 也落在 spec「恢复 <5s」目标内。SCDynamicStore
  作为再评估项写进下节。

### 决策 3：第一片 = `list_global_ipv6` + 地址配装 + 路由；监听留作跟进

- 最小诚实增量：`list_global_ipv6`（getifaddrs，无需 root）+ `add_route`/`remove_route`
  （net-route，需 root）+ `setup_interface` 的地址配装（最小安全封装，需 root）。这样
  `hextet up`（建 utun + 配地址 + 加 overlay /48 路由）与 `status`/`doctor`（读地址、
  读路由）在 macOS 上闭环。
- **macOS 上可测**（`sudo -E cargo test -p hextet-platform -- --ignored`，同 linux.rs 的
  root 分层惯例）：`list_global_ipv6` 无 root 也能跑（断言结果都过
  `is_usable_endpoint_addr`）；真实 utun 的地址配装 + 路由增删用 `--ignored` root 测试
  （配一个 `fd00:dead:beef::1/48` 到临时 utun、加一条到该 utun 的 ULA 路由、再删）。
- **仍需真机验证**：真实 `hextet up` 端到端（utun + 地址 + 路由 + boringtun 握手 + 互 ping）、
  前缀轮换的恢复时序、net-route 的「无网关仅出接口」路由在真实 macOS 上是否正确落表。
- **跟进**：`watch_ipv6_addresses`（2s 轮询）与 `delete_interface`/`list_multicast_interfaces`
  的 getifaddrs 实现作为紧随其后的第二片（`daemon` 需要它们，但 `up`/`status`/`doctor` 不需要）。

### 决策 4：本 ADR 只解锁 one-shot + 读，`daemon` 仍被 boringtun 挡着

- 即使本 ADR 全部落地，macOS 的 `hextet daemon`（打洞循环）**仍然不可用**：ADR-0007 已
  记录 boringtun 0.7.1 的 `Device::update_peer` 对已存在 peer 直接 `panic!`、`set=1`
  协议无「只改 endpoint」的增量操作，`WgBackend::set_peer_endpoint` 只能诚实返回
  `WgError::Backend`。诚实排序是：**本 ADR 解锁 `hextet up`/`status`/`doctor`（一次性 +
  只读）在 macOS 的运行；`hextet daemon`（打洞循环）等 boringtun→gotatun 切换**
  （ADR-0007 再评估触发条件 1：gotatun 发布 1.0 或 2026 审计通过）。

## 理由（决策 1 的取舍对照）

- **路由用 `net-route` vs 手写 PF_ROUTE**：`net-route` 是现成安全封装（unsafe 内聚在
  crate 内），MIT 干净，PF_ROUTE + IPv6 覆盖我们的 oif 路由需求。代价是维护弱（见决策 1），
  但代码量小（macOS 模块 ~600 行）、可 fork。手写 PF_ROUTE 会多出一块 fiddly 的 unsafe
  （`rt_msghdr2` 构造、sockaddr 排序），在没有现成 crate 时才值得；有 `net-route` 顶住，
  不必要。若 `net-route` 的 oif 路由真机验证失败，再按 §13 fork 预案 vendor，风险可控。
- **地址配装为什么破例手写 unsafe**：查证表明**没有**安全 crate 能配 macOS IPv6 地址——
  `tun` crate 是 IPv4 专用（`SIOCAIFADDR`）、`nix` ioctl 宏是 `unsafe fn`、`net-route`
  不做地址。不破例就等于「macOS `hextet up` 永远起不来」，与本 ADR 存在的目的直接冲突。
  破例的边界收得很窄：只 `SIOCAIFADDR_IN6`/`SIOCDIFADDR_IN6` 两个 ioctl，~30 行 unsafe，
  放独立 crate、`#![allow(unsafe_code)]`、root 门控测试覆盖，并写清「一旦出现维护中的
  安全 crate（或 `net-route` 补上地址配装）即删掉本封装」。这与 ADR-0007 的精神不矛盾——
  那里拒绝手写 unsafe 是因为 `tun` crate 已提供安全封装；这里没有等价物，是「被迫且最小」
  的例外，而不是「顺手开 unsafe」。
- **枚举/监听用 `getifaddrs` 而非 `system-configuration`**：`getifaddrs` 安全、无 root、
  纯读、同步快；`system-configuration` 的 SCDynamicStore 是回调+runloop，async 集成成本高、
  且未验证其订阅面。对「地址变化 → 重新握手」这个需求，2s 轮询的简洁性与 spec 的 <5s
  目标都满足，SCDynamicStore 带来的只是延迟从 2s 降到毫秒级——对当前里程碑是过度工程。
- **锁版本**：全部沿用 `mainline = "=8.0.0"` / `boringtun = "=0.7.1"` / `tun = "=0.8.14"`
  的精确锁定先例：`net-route = "=0.4.6"`、`getifaddrs = "=0.6.2"`，类型不外泄出
  `crates/platform`。

## 与 spec 的偏离记录

- spec §13 已列「net-route 维护弱，mac/Win 保留 fork 预案」，本 ADR 决定先采用 `net-route`
  并把 fork/vendor 预案落成文字（决策 1），不构成方向偏离。
- spec 未单独提 macOS 地址配装的实现载体；本 ADR 新增「最小安全封装」crate 是 ADR-0007
  「macOS 地址/路由配装缺口」的落地，属范围细化，不偏离 spec 方向。
- spec §5 写「监听 netlink/RA 事件」；macOS 侧本 ADR 用 `getifaddrs` 轮询替代（2s），
  是跨平台等价实现，如实记录。

## 代价与再评估

- **net-route 维护弱（§13 已列）**：0.4.6 距今 16 个月、最近 push 距今约 4 个月、20 个
  open issue。缓解：锁版本 + `crates/platform` 唯一接触点 + fork 预案（vendor PF_ROUTE
  路径）。触发 vendor 的条件：真机上「无网关仅出接口」路由加不进去，或 net-route 被
  弃养/出 RUSTSEC。
- **最小安全封装是 workspace 内唯一允许 unsafe 的地方**：这是本 ADR 最大的一处「破例」。
  必须配套：独立 crate（或模块级 allow）+ 显著文档 + root 门控测试 + `cargo deny` 常开。
  若团队决定收回这条例外，回退路径是决策 1 的变体（地址配装推迟，`up` 只能建 utun+路由）。
- **地址枚举少了 Deprecated/Tentative 过滤**：`getifaddrs` 拿不到逐地址标志，端点探测
  可能偶尔试到即将失效的旧地址。代价是探测噪声，非正确性破坏；补足需 unsafe 封装
  `SIOCGIFAFLAG_IN6`，明确推迟。
- **监听从 push 降级为 2s poll**：相比 Linux netlink 的毫秒级推送，macOS 有最多 2s 延迟。
  落在 spec「恢复 <5s」内，可接受；若实测前缀轮换恢复超时或需要毫秒级响应，再评估
  `system-configuration` 的 SCDynamicStore 通知。
- **`daemon` 仍被 boringtun 挡住（ADR-0007）**：本 ADR 无法也不试图解决
  `set_peer_endpoint` 缺口。macOS 的 `hextet daemon`（打洞循环）须等 boringtun→gotatun
  切换（ADR-0007 再评估触发条件 1）。

### 重新评估的触发条件

1. **gotatun 发布 1.0 或 2026 审计通过**（ADR-0007 触发 1）→ 切 gotatun，届时重估
   `set_peer_endpoint` 与 `daemon` 在 macOS 的可用性。
2. **出现维护中的 macOS IPv6 地址配装安全 crate**（或 `net-route` 补上地址配装）→ 删除
   本 ADR 的最小安全封装，改引第三方。
3. **net-route 被弃养 / 出 RUSTSEC / 真机 oif 路由失败** → 按 §13 fork 预案 vendor 其
   PF_ROUTE 路径。
4. **实测前缀轮换恢复 > 5s 或需要毫秒级地址变化响应** → 评估 `system-configuration` 的
   SCDynamicStore 通知替代 2s 轮询。

## 未能验证（落地前须确认）

- **net-route 的 MSRV**：未查到其 `rust-version`，须确认能编译于工作区 1.85（CI 会兜底）。
- **net-route macOS「无网关、仅出接口」路由的实际落表**：其 macOS 实现把
  `RTA_GATEWAY` 在 add 时无条件置位、`ifindex` 追加 `sockaddr_dl`，与 `route add -interface`
  语义方向一致，但「`gateway: None` + `ifindex: Some`」组合是否真能在真机正确加进
  IPv6 路由表**未在真机验证**——这是决策 1 是否需触发 fork 预案的关键实测点。
- **`system-configuration` 的 SCDynamicStore 异步/runloop 集成面**：crate 文档只显示回调
  context，未确认有无 tokio/channel 订阅，也未验证 runloop 集成成本（目前不采用，故不影响
  第一片）。
- **`in6_aliasreq` 在 utun 上的 dstaddr/lifetime 语义**：utun 是点到多点，`SIOCAIFADDR_IN6`
  的 `ifra_dstaddr`/`ifra_lifetime` 具体填法（留 `::` 还是填 site 地址）需真机确认，属实现细节。
