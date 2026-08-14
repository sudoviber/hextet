# ADR-0010：Windows 平台网络能力——TUN 走 tun crate 的 wintun、路由走 net-route、枚举走 ipconfig、地址配装走 netsh、服务化走 windows-service

- 状态：已接受（`hextet-platform` 已 `cargo check --target x86_64-pc-windows-gnu` 通过；完整 build/link 未验证，见「未能验证」）
- 日期：2026-08-13
- 相关：`docs/superpowers/specs/2026-08-06-hextet-design.md` §9（Windows 行：gotatun + wintun、Windows service (LocalSystem)、CLI/Tauri）与 §10（项目结构）、
  `docs/superpowers/plans/2026-08-12-m6-windows-and-release.md` 切片 D（明确要求：Windows 需**新 ADR** 裁决 wintun-vs-tun-crate 与 service 分支）、
  `docs/adr/ADR-0007-gotatun-userspace-backend.md`（TUN 抽象与 unsafe 内聚进第三方 crate 的先例）、
  `docs/adr/ADR-0008-macos-platform-networking.md`（本 ADR 镜像其结构与「决策/理由/未能验证」诚实度）、
  `crates/platform/src/lib.rs`（非 Linux/macOS 的 `stub`）、`crates/platform/src/macos.rs`（需镜像的函数面）、
  `crates/platform/src/tun.rs`（TUN 抽象，`tun` crate 的 Windows 模块）、`crates/platform/Cargo.toml`、
  `deny.toml`、`crates/cli/src/commands/daemon.rs`（服务要接的守护进程）

## 背景

M6 要让 `hextet` 在 Windows 10+ 落地数据面与服务化（spec §9：数据面 gotatun + wintun、服务化 Windows
service (LocalSystem)、UI 为 CLI/Tauri）。`crates/platform` 是「接口/地址/路由/服务化」的平台抽象层，
但 `lib.rs` 对非 Linux/macOS 平台只有 `stub`：`setup_interface`/`add_route`/`remove_route`/
`list_global_ipv6`/`list_multicast_interfaces`/`watch_ipv6_addresses` 全部返回
`PlatformError::Unsupported`。ADR-0008 已把 macOS 用 `net-route`（路由）+ `getifaddrs`（枚举）+
最小 unsafe 封装（地址配装）落地；本 ADR 要裁定 Windows 的对应四件事：TUN 设备、路由、地址枚举与
监听、地址配装与服务化。

硬约束（与 ADR-0008 相同，但本任务**更严**）：`Cargo.toml` 根上的 `[workspace.lints.rust]
unsafe_code = "deny"`（edition 2024、`rust-version = "1.85"`）。ADR-0008 曾对 macOS 地址配装
「被迫」破例写了 `#![allow(unsafe_code)]` 的最小封装；**本切片明确要求 Windows 侧零 unsafe**，即
unsafe 只能内聚进第三方 crate（wintun、windows-service 等），hextet 自己的 `windows.rs` 一行
`unsafe` 都不能有。这直接决定了下面地址配装的选型（决策 2）。

本轮查证到的外部事实（截至 2026-08-13，来自 crates.io / docs.rs / GitHub 仓库源码，未在本机
Windows 真机验证）：

| crate | 版本（已发布） | 许可证 | 关键点 |
|---|---|---|---|
| `tun`（meh/rust-tun） | 0.8.14（ADR-0007 已锁） | WTFPL | README 明确「Supported Platforms: Windows」；Windows 模块的 `Device` 是「A TUN device using the wintun driver」。`Device::new` 内部 `unsafe { load_from_path(wintun_file) }` 加载 wintun.dll、`Adapter::create`，即 **unsafe 全部内聚在 crate 内**。但注意：其 `set_address`/`set_netmask`/`set_destination` 在 Windows 上**仍为 IPv4 专用**（`unimplemented!("do not support IPv6 yet")`）；唯一的 IPv6 配装路径是 `config.address(IpAddr::V6)` + `config.netmask(IpAddr::V6)` 在 `Device::new` 里走 `set_network_addresses_tuple`（内部是 `netsh interface ipv6 set address ...`，见下），**只发生在设备创建时刻**。要求把 wintun.dll 放到可执行文件同目录 + 以管理员运行。 |
| `net-route` | 0.4.6（ADR-0008 已锁） | MIT | **有 Windows 支持**（依赖 `windows-sys ^0.59`）。`src/platform_impl/windows.rs` 用 `CreateIpForwardEntry2`/`DeleteIpForwardEntry2`/`GetIpForwardTable2` + `NotifyRouteChange2`。`Route` 的 `with_ifindex(u32)` 是**跨平台**（无 cfg 门控）方法，Windows 侧把 `ifindex` 写进 `MIB_IPFORWARD_ROW2.InterfaceIndex`；另有 `#[cfg(windows)] with_luid(u64)`。即「仅出接口、无网关」的路由在 Windows 上走 `with_ifindex` 即可，与 macOS/Linux 同构。 |
| `ipconfig` | 0.3.4（2026-07 发布） | MIT/Apache-2.0 | `get_adapters() -> Result<Vec<Adapter>>`（内部 `GetAdaptersAddresses`，unsafe 内聚 crate 内）。`Adapter { friendly_name(), adapter_name(), ip_addresses() -> &[IpAddr], ipv6_if_index() -> u32, if_type() -> IfType, oper_status() -> OperStatus, ... }`。**无 `luid()`**、**无逐地址 Deprecated/Tentative 标志**、**无 `NO_MULTICAST` 标志**（`GetAdaptersAddresses` 的 `Flags` 有 `IP_ADAPTER_NO_MULTICAST`，但 ipconfig 未暴露）。是 getifaddrs 的 Windows 等价物。 |
| `windows`（microsoft/windows-rs） | 0.61.3 | MIT OR Apache-2.0 | `CreateUnicastIpAddressEntry` / `InitializeUnicastIpAddressEntry` / `DeleteUnicastIpAddressEntry` / `CreateIpForwardEntry2` 等 IP Helper 函数在 crate 里是 **`unsafe fn`**（firezone/tun-rs/EasyTier 的调用点全部包在 `unsafe { }` 里，见 firezone `tun_device_manager/windows.rs`）。即它只是 raw binding，不是安全封装。 |
| `wintun`（nulldotblack/wireguard-wintun） | 0.x | MIT | 有安全方法 `Adapter::set_network_addresses_tuple(address: IpAddr, mask, gateway)`（内部 shell 出 `netsh`），但**加载 DLL 的 `Wintun::load` / `load_from_path` 是 `unsafe fn`**；`Adapter::open` 前必须先 unsafe 加载 DLL。且其 IPv6 `set_network_addresses_tuple` 拼的是 `netsh interface ipv6 set address ... mask=<IpAddr>`——与本 ADR 查证的微软官方 `add address` 语法不一致（见下）。 |
| `windows-service` | 0.8.1（2026-05 发布） | MIT OR Apache-2.0 | Mullvad 维护（617 star、生产用于 Mullvad VPN、firezone 同款）。`define_windows_service!` + `service_dispatcher::start` + `service_control_handler::register` + `service_manager::{ServiceManager, ServiceInfo}`（`create_service`/`delete_service`）。unsafe 全部内聚 crate 内。 |

`netsh` 官方语法（微软 docs「netsh interface ipv6」）：
- 加地址：`netsh interface ipv6 add address "<接口名>" <IPv6地址>/<前缀长度> [store=persistent]`
- 删地址：`netsh interface ipv6 delete address "<接口名>" <IPv6地址>`

（据此可见 `wintun` crate 的 IPv6 路径拼的是 `set address ... mask=`，与官方 `add address` 语法不符，
疑似未经验证的 IPv6 分支——本 ADR 不采用它，直接用官方 `add/delete address`。）

RUSTSEC 结论：`net-route` 沿用 ADR-0008 的「无已知 advisory」；`ipconfig`、`windows-service` 在
rustsec/advisory-db 下无对应目录（以 CI 的 `cargo-deny`/`cargo-audit` 为最终事实来源）。`windows`
crate 若引入需核对 `windows-core`/`windows-result` 等子 crate 版本，本 ADR **不引入**（见决策 2）。

## 决策

### 决策 1：TUN 走 `tun` crate 的 wintun 模块（扩展 `tun.rs` 的 cfg 门控），不直引 `wintun` crate

- `crates/platform/src/tun.rs` 现有 `imp` 模块的 cfg 门控是 `#[cfg(any(target_os = "macos",
  target_os = "linux"))]`，其余平台（含 Windows）落到「返回 `Unsupported`」的桩。本决策把门控
  扩成 `#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]`，让 `tun`
  crate 的 **wintun 模块**承接 Windows 的 TUN 设备打开/读写/关闭。
- 理由：`tun` crate 已把 wintun 的 DLL 加载（`unsafe { load_from_path }`）、`Adapter::create`、
  session/ring 的 unsafe 全部内聚在 crate 内，调用方零 unsafe——与 ADR-0007「TUN 抽象用 tun crate」
  同构，且满足本任务的「不写 unsafe」。直引 `wintun` crate 则必须在我们代码里写
  `unsafe { wintun::load() }`（`load_from_path` 是 `unsafe fn`），**违反硬约束**，故排除。
- 风险与成本：wintun.dll 是运行时外部依赖（须与 exe 同目录或 `PlatformConfig::wintun_file` 指定），
  `open_tun` 需管理员（LocalSystem 服务天然满足）。`tun` crate 的 `name()` 在 Windows 上返回 wintun
  adapter 的 friendly name，与 `ipconfig` 的 `friendly_name()` 是否逐字一致需真机确认（见「未能验证」）。
- **不解决**：`tun` crate 在 Windows 上的 IPv6 地址配装仍只有「创建时刻 `config.address` 路径」，与本
  项目「backend 建设备、platform 按名后配地址」的既有流程（ADR-0009）不一致，故地址配装**不**走 tun
  crate，另见决策 2。

### 决策 2：地址配装走 `netsh`（零 unsafe），枚举走 `ipconfig`，监听走 2s 轮询

- **地址配装（`assign_ipv6`/`unassign_ipv6`，供 `setup_interface` 调用）**：Windows 上**没有**零
  unsafe 的安全 crate 能按名配 IPv6 地址——`windows` crate 的 `CreateUnicastIpAddressEntry` 是
  `unsafe fn`（raw binding）；`wintun` crate 加载 DLL 是 `unsafe fn` 且 IPv6 分支语法可疑；`tun`
  crate 只在设备创建时刻、且 `set_address` 仍 IPv4 专用。因此唯一「零 unsafe、按名、不依赖句柄」的
  路径是 **shell 出 `netsh`**（`std::process::Command`，完全安全）：
  - 加地址：`netsh interface ipv6 add address "<name>" <addr>/<prefix_len> store=persistent`
  - 删地址：`netsh interface ipv6 delete address "<name>" <addr>`
  这是 ADR-0008 macOS 最小 unsafe 封装的**零 unsafe 对应物**——本任务禁止写 unsafe，于是连 macOS 那
  ~30 行 ioctl 封装都不需要：`netsh` 就是现成的、按名、零 unsafe 的封装。`wintun` crate 自己
  （`set_network_addresses_tuple`）也 shell 出 `netsh`，说明「netsh 兜底配地址」是被维护中的 crate
  认可的既定做法。
- **代价**：netsh 每次 spawn 一个进程（慢、输出 locale 相关、须解析退出码），比 ioctl/FFI 重。对
  `setup_interface` 这种一次性、低频的调用可接受；若真机发现 netsh 输出/退出码不稳定，回退路径是
  引入一个**独立 crate** 级别的 `#![allow(unsafe_code)]` 最小封装（镜像 ADR-0008 的 macOS 先例），
  把 `CreateUnicastIpAddressEntry` 圈进 ~20 行——此回退一并写明，不静默吞掉。
- **枚举（`list_global_ipv6`）**：`ipconfig::get_adapters()`（锁 `ipconfig = "=0.3.4"`），过滤复用
  `hextet_core::addr::is_usable_endpoint_addr` + 排除 hextet 自己的接口（按 `friendly_name()` 或
  `adapter_name()` 匹配）。**诚实差异**（同 ADR-0008 决策 2 的 getifaddrs 差异）：ipconfig 拿不到
  逐地址的 Deprecated/Tentative 标志，只剩「Deprecated/Tentative 旧地址短暂出现」的探测噪声；此外
  也不暴露 `IP_ADAPTER_NO_MULTICAST` 标志（`list_multicast_interfaces` 用「非 loopback 且 Up」近似，
  见决策 3）。
- **监听（`watch_ipv6_addresses`）**：**2s `ipconfig` 轮询 + 差集发 `AddrEvent`**，去抖交给 daemon
  （`AddrEvent` 文档已声明调用方自去抖）。选轮询而非 `NotifyIpInterfaceChange`/`NotifyAddrChange`：
  后者在 `windows` crate 里同样是 `unsafe fn` + 回调，引入成本高、且本任务零 unsafe；2s 轮询与 macOS
  侧一致、落在 spec「恢复 <5s」内。`AddrEvent::if_index` 镜像 macOS 填 `0`（daemon 只当「地址变了」
  信号用，不读 if_index）。

### 决策 3：路由走 `net-route`（`with_ifindex`），删除接口仍 `Unsupported`

- **路由（`add_route`/`remove_route`）**：用 `net-route`（锁 `=0.4.6`，Windows 依赖已含在
  `[target.'cfg(target_os = "windows")'.dependencies]`）。查证其 Windows 实现把 `with_ifindex(u32)`
  写进 `MIB_IPFORWARD_ROW2.InterfaceIndex`，即「仅 oif、无网关」路由与 macOS/Linux 同构
  （`Route::new(IpAddr::V6(prefix), prefix_len).with_ifindex(ifindex)`）。ifindex 取自 `ipconfig`
  的 `ipv6_if_index()`。**风险与预案**：net-route 维护弱（ADR-0008 §13 已列）；其 Windows 分支
  是否有独立于 macOS/Linux 的 bug 未知。若真机「无网关仅出接口」IPv6 路由加不进去，按 §13 预案
  vendor 或改用 `windows` crate 的 `CreateIpForwardEntry2`（firezone 同款，~20 行，但需 `#![allow(unsafe_code)]`
  ——届时一并评估）。
- **`delete_interface`**：Windows 的 wintun adapter 在**所有 session 关闭后仍持久**（须显式
  `WintunDeleteAdapter` 或注册表删除），与 macOS 的「fd 全关即自动销毁」不同；`tun` crate 的
  `close_tun`（drop）只关 handle 不删 adapter。故 `delete_interface` 在 Windows 上**仍诚实返回
  `Unsupported`**，与 macOS 侧一致（镜像 macos.rs），把「wintun adapter 显式删除」列为后续片
  （须 backend 暴露设备 GUID/luid 或专用删除路径）。

### 决策 4：服务化走 `windows-service` crate，新增 `hextet service install|uninstall|run`

- 用 `windows-service = "=0.8.1"`（Mullvad 维护、MIT/Apache-2.0、unsafe 内聚 crate 内），新增
  `crates/cli/src/commands/service.rs`（`#[cfg(target_os = "windows")]` 门控）：
  - `hextet service run [--config <path>]`：`service_dispatcher::start` + `define_windows_service!`
    入口 + `service_control_handler::register`（处理 Stop/Interrogate）→ 报告 `Running` → 在
    spawn 线程里跑 `hextet_engine::daemon::run(&config)`。
  - `hextet service install`：`service_manager::ServiceManager` 注册服务，`binPath = "<exe> service run --config C:\ProgramData\hextet\hextet.toml"`（LocalSystem）。
  - `hextet service uninstall`：删除服务。
  - 手动兜底：`sc.exe create hextet binPath="...\hextet.exe service run" start=auto`（写入文档）。
- 相比 `sc.exe` 清单：`windows-service` 把「作为服务运行」所需的 dispatcher/control-handler 生命周期
  圈进 crate，`hextet` 二进制自带 `install`，用户无需手敲易错的 `sc.exe`；`sc.exe` 仅作为文档里的
  手动等价命令保留。**诚实边界**：服务 Stop 的优雅关停（把 SCM 的 Stop 转成 daemon 的 tokio 信号）
  依赖 engine 在 Windows 上的信号处理，本切片不碰 `crates/engine`（本 session 另一 agent 持有），
  `service run` 在 Stop 时报告 `StopPending` 后退出进程，**非优雅**关停如实标注。

### 决策 5：第一片 = 全函数面落地 + ADR + service；交叉编译「类型检查通过、链接未验证」

- 本切片交付 `windows.rs` 全函数面（`setup_interface`/`delete_interface`/`add_route`/
  `remove_route`/`list_global_ipv6`/`list_multicast_interfaces`/`watch_ipv6_addresses` +
  `assign_ipv6`/`unassign_ipv6`），外加 `tun.rs` wintun 门控、service wrapper、文档。
- **交叉编译的实际结果（本机 aarch64-apple-darwin）**：`rustup target add
  x86_64-pc-windows-gnu` 成功后，`cargo check -p hextet-platform --target
  x86_64-pc-windows-gnu` **通过（exit 0）**——即 `windows.rs`/`tun.rs`/`lib.rs` 的 Windows
  分支已过**类型检查/借用检查**。但 `cargo build`（codegen + link）**失败**：缺 mingw-w64
  工具链（`x86_64-w64-mingw32-dlltool`）；`hextet-cli` 的 `cargo check` 更早地卡在某个 C
  依赖的 build.rs（缺 `x86_64-w64-mingw32-gcc`）。因此「类型检查已验证、完整链接未验证」
  是本 ADR 的诚实状态；CI Windows runner 是第一处完整编译验证点。

## 理由（决策取舍对照）

- **TUN 走 `tun` crate vs 直引 `wintun` crate**：`tun` crate 已把 wintun DLL 加载的 unsafe 内聚
  crate 内、且是 ADR-0007 既定选型，扩一个 cfg 门控即可；直引 `wintun` crate 必须 `unsafe { load() }`，
  违反本任务「零 unsafe」。前者成本最小、与 macOS/Linux 同构。
- **地址配装为什么 `netsh` 而非 `windows`/`wintun` crate**：查证表明 Windows 上**没有**零 unsafe 的
  安全 crate 能按名配 IPv6 地址——`windows` crate 的 `CreateUnicastIpAddressEntry` 是 `unsafe fn`、
  `wintun` crate 的 DLL 加载是 `unsafe fn` 且 IPv6 分支语法可疑。`netsh` 是唯一「零 unsafe、按名、
  不依赖句柄」的路径，且 `wintun` crate 自己都 shell 出 netsh。这与 ADR-0008 的精神不矛盾——那里
  破例写 unsafe 是因为 macOS **没有**任何现成路径；Windows 有 `netsh`，于是连破例都不需要。
- **枚举/监听用 `ipconfig` 而非 `windows` crate 的 `GetAdaptersAddresses`**：`ipconfig` 安全、无
  root、纯读、同步快，且已把 `GetAdaptersAddresses` 的 unsafe 内聚；`windows` crate 直接调
  `GetAdaptersAddresses` 是 `unsafe fn`。`ipconfig` 拿不到 luid/逐地址标志，但本切片的路由（`with_ifindex`）
  与地址配装（netsh 按名）都不需要 luid，故用 `ipconfig` 足够，少引一个重依赖。
- **监听从 push 降级为 2s poll**：与 macOS 侧一致（ADR-0008 决策 2），`NotifyIpInterfaceChange` 在
  `windows` crate 里是 `unsafe fn`，本任务零 unsafe 前提下不采用。
- **锁版本**：沿用 `net-route = "=0.4.6"`（已锁）、新增 `ipconfig = "=0.3.4"`、`windows-service =
  "=0.8.1"` 精确锁定，类型不外泄出 `crates/platform`/`crates/cli`。

## 与 spec 的偏离记录

- spec §9 写「数据面 gotatun + wintun」：gotatun 尚未发布/审计（ADR-0007），数据面实际仍走
  boringtun（用户态后端）经 `tun` crate 的 wintun 打开设备，与 ADR-0007 的「先用 boringtun 过渡」
  一致；本 ADR 只落地「wintun TUN」这一半，gotatun 切换等 ADR-0007 再评估触发条件 1。
- spec §9 写「Windows service (LocalSystem)」：本 ADR 决策 4 用 `windows-service` crate +
  `hextet service install`（默认 LocalSystem），一致。
- spec §5 写「监听 netlink/RA 事件」：Windows 侧用 `ipconfig` 轮询替代（2s），跨平台等价实现，如实记录。

## 代价与再评估

- **`netsh` 慢且 locale 相关**：每地址一次进程 spawn；对一次性配装可接受。若真机发现不稳定，回退
  到独立 crate 的 `#![allow(unsafe_code)]` 最小封装（镜像 ADR-0008 macOS 先例）。
- **`net-route` Windows 分支维护弱**：0.4.6 的 Windows 实现（`CreateIpForwardEntry2`）与 macOS/Linux
  分支并列但更少被使用；若真机「无网关仅出接口」IPv6 路由失败，回退到 `windows` crate 直调（firezone
  同款，需重新评估 unsafe 例外）。
- **`delete_interface` 与 wintun adapter 持久性**：Windows 的 wintun adapter 不随 fd 关闭自动销毁，
  `delete_interface` 第一片诚实 `Unsupported`，需 backend 暴露显式删除路径后才能补。
- **service 优雅关停依赖 engine**：本切片不碰 engine（另一 agent 持有），`service run` 的 Stop 是
  非优雅退出，须 engine Windows 信号处理落地后再接优雅关停。
- **`daemon` 在 Windows 仍被 boringtun + engine 挡住**：`crates/engine` 的 `backend::platform_default()`
  只有 Linux/macOS 分支（本 session 另一 agent 持有），Windows 上 `hextet` 二进制**尚不能整体编译**，
  `windows.rs`/service 是「为那个编译做好平台层准备」，与 ADR-0008 决策 4 的「daemon 仍被 boringtun
  挡着」同构。

### 重新评估的触发条件

1. **gotatun 发布 1.0 或 2026 审计通过**（ADR-0007 触发 1）→ 切 gotatun，届时重估 wintun TUN 与
   地址配装路径。
2. **出现维护中的 Windows IPv6 地址配装安全 crate**（真正零 unsafe 的 `CreateUnicastIpAddressEntry`
   封装）→ 删除 netsh 兜底，改引第三方。
3. **`netsh` 在真机不稳定（locale/退出码）** → 引入独立 crate 级 `#![allow(unsafe_code)]` 最小封装
   （ADR-0008 macOS 先例）。
4. **`net-route` Windows 分支真机 oif 路由失败 / 出 RUSTSEC / 弃养** → vendor 或 `windows` crate 直调。
5. **engine 落地 Windows 后端（`platform_default()`）** → 接 `service run` 的优雅关停，并让 `hextet`
   二进制真正在 Windows 上编译通过。

## 未能验证（落地前须确认）

- **完整链接未做**：`cargo check -p hextet-platform --target x86_64-pc-windows-gnu` **通过**（类型/
  借用检查已验证）；但 `cargo build` 的 codegen+link 失败于缺 mingw-w64（`x86_64-w64-mingw32-dlltool`），
  `hextet-cli` 的 `cargo check` 卡在 C 依赖 build.rs（缺 `x86_64-w64-mingw32-gcc`）。故
  `windows.rs`/`tun.rs` 是「类型检查验证、链接未验证」，`service.rs` 与 `hextet` 二进制完全未验证。
  CI 的 Windows runner（`release.yml` 已含 Windows 目标）是第一处完整编译验证点；本 ADR 不声称
  「链接通过」。
- **`tun` crate 的 `name()`（wintun friendly name）与 `ipconfig::friendly_name()` 是否逐字一致**：
  决定 `setup_interface(name, ...)` 里「按名找 ifindex」能否命中 wintun adapter。代码同时匹配
  `friendly_name()` 与 `adapter_name()` 提高命中率，但真机未验证。
- **`ipconfig::ipv6_if_index()`（`IP_ADAPTER_ADDRESSES.Ipv6IfIndex`）与 `MIB_IPFORWARD_ROW2.InterfaceIndex`
  的数值一致性**：Windows 10+ 上二者通常相等，但未真机验证；若不等，`net-route` 的 `with_ifindex`
  路由会挂到错误接口。备选：引入 `windows` crate 取 luid + `with_luid`（需 unsafe，触触发条件 4）。
- **`netsh interface ipv6 add address "<name>" <addr>/<prefix>` 的退出码与 locale**：命令语法来自
  微软官方 docs，但退出码判定（`status.success()` + stderr）与中文/其他 locale 下的输出未验证。
- **wintun.dll 的分发**：`tun` crate 默认从工作目录找 `wintun.dll`；作为 LocalSystem 服务运行时工作
  目录是 `C:\Windows\System32`，须在 install 文档里明确 wintun.dll 的放置路径（或经
  `PlatformConfig::wintun_file` 指定）。cargo-dist 是否随包分发 wintun.dll 未定，属发布工程后续。
- **`windows-service` 0.8.1 与 `service_manager` 的 `ServiceInfo` 字段**：install 路径的字段名
  （`description`/`dependencies`/`account` 等）按 0.8.1 文档编写，未在 Windows 上编译验证。
