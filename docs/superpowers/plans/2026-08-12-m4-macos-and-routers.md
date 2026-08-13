# hextet M4（macOS + 路由器）实现计划

> 本计划覆盖 spec §8 M4 行的交付，并记录已完成部分。M4 其余 Task 按序做，每个
> Task 独立提交、带自己的文档与 CHANGELOG 行。

**Goal:** 让 hextet 在 macOS 与路由器（OpenWrt）上可用。macOS 走用户态 gotatun
数据面 + launchd；OpenWrt 走内核 WireGuard + procd/uci；子网路由（site-to-site）
让任意节点能把自己背后的 IPv6 网段通告给全网。

**设计依据:** `docs/superpowers/specs/2026-08-06-hextet-design.md` §8 M4 行、§9 平台
支持矩阵、§10 项目结构（`openwrt/` 目录）、§13 风险表（gotatun 年轻、审计 2026 进行中）。

**M4 的验收（spec §8）:**
1. macOS 上 gotatun 用户态数据面 + utun 建立 hextet0，`hextet up`/`down`/`daemon` 可用；
2. launchd root daemon 服务化（直装，不走 App Store/NE）；
3. OpenWrt feed 包（Makefile + procd init + uci）+ site-to-site 子网路由 + LuCI 骨架。

---

## 进度（2026-08-13）

| 切片 | 状态 | 交付 |
|---|---|---|
| **site-to-site 子网路由** | ✅ 已完成 | `Ipv6Route` 模型 + `allowed_ips_for`、`[[peers]] routes` 配置、平台 `add_route`/`remove_route`、engine `route_manager`、CLI `peer add --route` + `status` routes 列、`scripts/netns-e2e-site.sh` + `cargo xtask e2e site` + CI `e2e-site`、`docs/guides/site-to-site.md`、`ADR-0006` |
| **OpenWrt feed + procd/uci + LuCI** | ✅ 已完成 | `openwrt/hextet`（cargo 交叉编译 Makefile + procd init + uci 默认 + 示例配置）、`openwrt/luci-app-hextet`（只读状态视图 + menu + rpcd ACL）、`docs/guides/openwrt.md`、`openwrt/README.md` |
| **Linux systemd 服务** | ✅ 已完成 | `packaging/systemd/hextet.service` + `docs/guides/install.md`（与 OpenWrt procd 同路径约定） |
| **gotatun 用户态后端（macOS utun + Linux TUN）** | 🔶 部分完成 | `ADR-0007` 已写；`hextet-platform::tun` TUN 抽象（utun/TUN，`tun` crate 安全封装）+ `hextet-wg-userspace`（boringtun `=0.7.1` 实现 `WgBackend` 全五方法）+ 进程内握手与 IPv6 数据往返测试已完成；macOS 地址/路由配装、`hextet up`/`daemon` 在 macOS 上运行、launchd 仍待做（阻塞点有二：macOS `setup_interface`/`add_route`/`list_global_ipv6` 缺口，以及 boringtun 0.7.1 不支持增量改 endpoint——`set_peer_endpoint` 无法忠实实现，见 ADR-0007「代价与再评估」） |
| **launchd 服务（macOS）** | 🔶 打包就绪 / 运行时阻塞 | `packaging/launchd/com.hextet.daemon.plist` + `docs/guides/install.md` macOS 章节（`plutil -lint` 通过）；plist 为「死打包」——macOS daemon 运行时仍被 boringtun `set_peer_endpoint` 缺口阻塞，待 boringtun→gotatun |

**依赖顺序**：systemd 服务独立可做（纯打包，无 Rust 依赖）；gotatun 后端是 macOS
可用性的前置，且 spec §13 明示其「审计 2026 进行中」——先落地 TUN 抽象与 ADR 决策，
再实现用户态后端；launchd 服务必须在 gotatun 后端能 `up` 之后才有意义，放最后。

---

## Task 31: Linux systemd 服务（纯打包）

**为什么先做它**：Linux 是 M1–M3 的主平台，`hextet daemon` 已是常驻进程，但仓库里
至今没有 systemd 单元（spec §9 Linux 行承诺 `systemd (CAP_NET_ADMIN)`）。零 Rust 依赖、
零新 crate，是最低风险的补齐。

**交付:**
- `packaging/systemd/hextet.service`（或 `deploy/systemd/`）：`ExecStart=/usr/sbin/hextet daemon -c /etc/hextet/hextet.toml`，`Restart=on-failure`，`AmbientCapabilities=CAP_NET_ADMIN`，`ProtectSystem=strict` 等最小权限；**不含任何密钥**（密钥只在 hextet.toml 里）。
- `docs/guides/install.md`：二进制安装、`/etc/hextet/hextet.toml` 放置、`systemctl enable --now hextet`、与 `hextet up` 的关系（daemon 常驻 vs 一次性 up）、日志查看。
- `CHANGELOG.md` 一行。

**验收:** `systemd-analyze verify` 通过（macOS 上不可用则 `bash -n` + 结构复核并诚实标注）。

## Task 32: gotatun 用户态后端（macOS utun + Linux TUN）

**前置决策（写 ADR-0007）**：gotatun 是 Mullvad 的 boringtun 后继，spec §13 标为
「年轻（审计 2026 进行中）」。落地前须先裁定：
1. 依赖形态：crates.io 已发布版本 / git 依赖 / 或先封装在独立 crate（沿用
   `mainline` 锁版本 + 独立 crate 的隔离策略）；
2. TUN 设备抽象放哪：`crates/platform` 新增 `tun` 能力（utun on macOS、tun on Linux），
   `unsafe_code = "deny"` 意味着 ioctl/utun 的原生访问必须包在安全 crate 里（如 `tun` crate），
   不能手写 unsafe；
3. 特性开关：`wg` 后端在 kernel（Linux）与 userspace-gotatun（macOS）之间按
   `cfg(target_os)` 选择，还是运行时可选（spec §7「WgBackend trait 隔离，可换
   NepTUN/boringtun」暗示 trait 隔离即可，首选 `cfg` 编译期选择，减少运行时分支）。

**交付:** `crates/platform` 的 TUN 设备抽象（创建/配置/销毁，非 Linux 桩返回
`Unsupported`）；`crates/wg` 的 userspace 后端（实现现有 `WgBackend` trait 全部方法）；
`ADR-0007` 记录依赖与 TUN 抽象决策。

**验收:** `cargo xtask ci` 全绿（macOS 上 gotatun 后端与 Linux 交叉 target 均编译通过）；
两条本机 gotatun 实例经 loopback 互发 WG 握手并 ping 通 overlay（若 gotatun API 支持
in-process 测试）；`hextet up` 在 macOS 上建立 hextet0 且 `hextet status` 可读。

**诚实边界**：gotatun 尚未被广泛生产验证，本 Task 是「可用」而非「生产成熟」——
写进 ADR 与 `docs/guides/install.md`，不暗示 macOS 数据面已达到与 Linux 内核 WG 同等的
成熟度。

## Task 33: launchd 服务（macOS）

**交付:** `packaging/launchd/com.hextet.daemon.plist`（`RunAtLoad`、`KeepAlive`、
root 运行、`-c/--config` 参数），`docs/guides/install.md` 的 macOS 章节
（`launchctl bootstrap/bootout`、日志、卸载）。

**验收:** plist 语法 `plutil -lint` 通过；文档与实际行为一致（依赖 Task 32 完成后
才能在真机走通 `up`，否则如实标注）。

> **进度（2026-08-13）：✅ 打包完成，运行时仍阻塞。** plist 与 macOS 章节已落地，
> `plutil -lint` 通过。实际 daemon 参数为 `-c/--config` 与 `-v/--verbose`（**无
> `--key-file`**——节点密钥由配置 `[node] key_file` 指定，非 CLI 参数），故 plist 用
> `-c /usr/local/etc/hextet/hextet.toml`；日志级别由 `-v` 决定（daemon 用 tracing、
> 不读 `RUST_LOG`）。**这是「死打包」**：macOS `hextet daemon` 运行时仍被 boringtun
> 0.7.1 的 `set_peer_endpoint` 缺口挡住（ADR-0007/0009 决策 6），one-shot `hextet up`
> 又因 utun 随进程销毁无法常驻（ADR-0009 决策 5）；须等 boringtun→gotatun 切换后本
> 单元才真正可跑。plist 与指南里均已如实标注，不暗示可用。

---

## Task 34: macOS 平台网络能力（ADR-0008 的落地）

**前置决策：** `docs/adr/ADR-0008-macos-platform-networking.md` 已写（2026-08-12）。
它把 macOS 侧 `crates/platform` 的四个「非 Linux 桩返回 `Unsupported`」能力裁定为：
路由走 `net-route = "=0.4.6"`、枚举/监听走 `getifaddrs = "=0.6.2"`、IPv6 地址配装走
一个**最小安全封装**（`macos.rs` + 模块级 `#![allow(unsafe_code)]`，只封
`SIOCAIFADDR_IN6`/`SIOCDIFADDR_IN6` 两个 ioctl——这是 workspace 内唯一允许 unsafe 的
刻意例外，理由见 ADR）。

**第一片（解锁 `hextet up`/`status`/`doctor`）:** ✅ 已完成（2026-08-13）：
`list_global_ipv6`（getifaddrs，无 root，复用 `is_usable_endpoint_addr` 过滤 + 排除
hextet 接口，doc 注释诚实记录缺 Deprecated/Tentative 标志过滤）+ `add_route`/`remove_route`
（net-route PF_ROUTE，`Route { destination, prefix, gateway: None, ifindex: Some(ifname_to_index(name)?) }`，
镜像 Linux「仅 oif、无网关」语义）+ `setup_interface` 的地址配装（`open_tun` 建 utun + 设 MTU，
再 `assign_ipv6` 配 overlay 地址）。真实 utun 的地址配装 + 路由增删用 `--ignored` root 测试
覆盖（配 `fd00:dead:beef::1/48` 到临时 utun）。
**⚠️ 已知缺口（第一片未解决，须记录）**：macOS 的 utun 在**所有 fd 关闭时自动销毁**，而
`setup_interface` 是一次性 `(name, addr, prefix_len, mtu) -> Result<(), PlatformError>` 签名——
函数返回时 `TunHandle` 被 drop、设备随即消失。这与 Linux（内核 WG 持有设备、`setup_interface`
返回后设备常驻）存在**签名语义不对称**：平台抽象层当前「建 + 配」的返回类型无法让 macOS 设备
跨进程生命周期存活。因此「解锁 `hextet up`」在 macOS 上**尚未真正成立**——要真正跑起来，
`setup_interface` 需改为返回可持有的设备句柄（或由 boringtun 后端持有 utun fd），这是一处
跨 platform/engine/cli 的架构调整，单独列作 Task 35，不在本片强推。`status`/`doctor` 的只读
部分（`list_global_ipv6`）已真正可用。

**第二片（`hextet daemon` 需要）:** ✅ 部分完成（2026-08-13）：
`watch_ipv6_addresses`（2s `getifaddrs` 轮询 + 差集发 `AddrEvent`，SCDynamicStore 留作再评估）
与 `list_multicast_interfaces`（getifaddrs：`IFF_UP|IFF_MULTICAST` 非 loopback、排除 hextet
接口）已落地；`delete_interface` **仍为 `Unsupported`**——macOS 的 utun 在所有 fd 关闭时
自动销毁，而 `setup_interface` 是一次性「建 + 配」、不返回可持有的句柄，因此「按名字删除
接口」没有可操作的落点，阻塞于 Task 35 的设备句柄生命周期架构（与第一片的已知缺口同源），
**不假装**支持。

**验收:** `sudo -E cargo test -p hextet-platform -- --ignored` 的真实 utun 地址配装 + 路由
增删测试通过；`list_global_ipv6` 无 root 单测通过（断言结果都过 `is_usable_endpoint_addr`）；
`cargo xtask ci` 全绿。**诚实边界**：即便本 Task 全部落地，macOS `hextet daemon`（打洞循环）
仍不可用——被 boringtun 0.7.1 的 `set_peer_endpoint` 缺口挡住（见 ADR-0007/ADR-0008 决策 4），
须等 boringtun→gotatun 切换。

## Task 35: macOS 设备编排——backend 独占 utun、platform 按名配装（handle-lifetime 架构调整）

**设计已定（`docs/adr/ADR-0009-macos-device-orchestration.md`，实现待做）**

> **进度**：决策 3 的 `apply -> Result<String>` 签名改动已落地（kernel/mock/wg-userspace
> 恒等返回；macOS `setup_interface` 不再开自己的设备、只按名配地址）。决策 2（utun 映射读回）、
> 决策 4（`hextet up` 编排）、决策 5（`down`/`delete_interface` 分派）**已实现，仅编译验证**
> （`cargo build`/`cargo test`/`cargo clippy`/`cargo fmt` 全绿）；真实 utun 运行时路径需要
> root + 真实 utun，本机未真机跑，留待真机/CI。

Task 34 的「⚠️ 已知缺口」与 `delete_interface` 的 `Unsupported` 都指向同一个根因：macOS 上
utun 归 boringtun 后端所有（`DeviceHandle::new` 独占设备，`/var/run/wireguard/{name}.sock`
控制面），而 `platform::setup_interface` 自己开 `TunHandle`、返回即 drop、设备随即消失——
开错设备 + 无法跨进程存活。本 Task 把它按 ADR-0009 六条决策落地：

1. **设备所有权**：`UserspaceBackend` 是 utun 唯一 owner；`platform` 只按名配地址/路由，不再开设备。
2. **utun 命名**：加 `hextet0 → utun` 映射层——backend 内部请求裸 `utun`（内核选最低可用 index），
   用 `WG_TUN_NAME_FILE` 读回真实 `utunN`（`unsafe` 点按 ADR-0008「最小安全封装」先例收窄；
   备选：编排层挑空闲 `utunN`，零 unsafe）。
3. **签名变化**：`WgBackend::apply(&self, spec) -> Result<String, WgError>`（返回真实设备名；
   Linux 恒返回 `spec.interface.clone()`）；`kernel.rs`/`mock.rs` 同步改返回值，`daemon.rs`/`up.rs`
   接住返回值再传 `setup_interface`。`setup_interface` 签名不变，只改 macOS 体（删 `open_tun`，
   改 `assign_ipv6`；`mtu` 第一片 no-op + 文档标注）。
4. **`hextet up` 编排（macOS）**：`backend.apply` → 拿到 `utunN` → `setup_interface(utunN, own, 48, mtu)`
   → 显式 `add_route(utunN, prefix, 48)` → 上报 `hextet0 -> utunN`。`status`/`doctor` 只读，经
   `backend.status(utunN)` / `list_global_ipv6`。
5. **`down`/`delete_interface`**：macOS `delete_interface` 保持 `Unsupported`（设备随句柄销毁，无删设备
   ioctl）；`down` = backend drop 句柄 + `remove_route`，建议新增 `WgBackend::down`（Linux 分派给
   `platform::delete_interface`）。
6. **诚实边界**：`hextet up` 可**实现 + `cargo build` 编译验证**，但真跑需 root + 真实 utun，本机不提供，
   留待真机/CI；macOS 设备随进程存活（one-shot `up` 退出即消失），常驻靠 `daemon`（Task 33 launchd）；
   `daemon` 仍被 `set_peer_endpoint` 缺口挡住（ADR-0007）。

**交付:** 改 `WgBackend::apply` 返回值 + `wg-userspace` 的命名映射/读回 + `platform` macOS
`setup_interface` 去 `open_tun` + `up.rs`/`daemon.rs` 接新返回值 + `docs/guides/install.md` macOS
章节写「设备随进程存活、常驻用 daemon」。

**验收:** `cargo build`（macOS target）全绿；`cargo xtask ci` 全绿；Linux 路径行为不变（netns E2E 不回归）。
真机 `sudo hextet up` 建 `utunN` + 配地址 + 加 /48 路由 + `hextet status` 可读，列为后续真机/CI 项，
本机不谎称已验证。

---

## 风险与缓解（M4 特有）

| 风险 | 缓解 |
|---|---|
| gotatun 年轻、审计未完成 | WgBackend trait 隔离（spec §7）+ 锁版本/独立 crate + ADR-0007 写明「可换 NepTUN/boringtun」 |
| macOS utun 需要 unsafe（ioctl） | 用安全 crate 封装；仅地址配装无安全 crate 可承接，ADR-0008 收窄为「最小安全封装」单点例外（~30 行、独立 crate + `#![allow(unsafe_code)]` + root 门控测试） |
| `net-route` 维护弱（spec §13） | ADR-0008 锁版本 + `crates/platform` 唯一接触点 + fork/vendor 预案 |
| OpenWrt SDK 无法在 macOS 上构建验证 | 打包层对 rust-package.mk/luci.mk 变量名做了假设并在文件内注释；真机构建靠 OpenWrt SDK CI（后续 Task） |
| launchd 服务在 gotatun 后端未落地前是死打包 | Task 顺序强制：launchd 最后做 |
| macOS `daemon` 被 boringtun 增量 endpoint 缺口挡住 | 诚实排序：ADR-0008 只解锁 `up`/`status`/`doctor`，`daemon` 等 boringtun→gotatun（ADR-0007 触发 1） |
