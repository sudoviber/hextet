# ADR-0011：Windows 网络能力与数据面——`tun` crate（wintun）+ 平台网络能力 + `windows-service` crate（数据面 blocked on gotatun）

- 状态：已接受
- 日期：2026-08-14
- 相关：`docs/superpowers/specs/2026-08-06-hextet-design.md` §3 D1 / §8 M6 / §9、
  `docs/superpowers/plans/2026-08-12-m6-windows-and-release.md`（切片 D）、
  ADR-0007（gotatun→boringtun）、ADR-0008（macOS 平台网络能力）

## 背景

spec §9 把 Windows 定为「gotatun + wintun + Windows service (LocalSystem)」；M6 计划
切片 D 要落地 wintun + Windows service，并留下一个待决问题：**`tun` crate 的 windows
模块 vs 直接接 `wintun` crate**。本 ADR 补齐这个决策，并把数据面、服务化、平台能力
三件事一起定下来，作为切片 D 实现的依据。

## 决策

1. **TUN 设备用 `tun` crate 的 Windows 分支，不直引 `wintun`**。`tun` crate 已有
   `x86_64-pc-windows-msvc` 目标支持（底层就是 wintun），与 `crates/platform/src/tun.rs`
   现有的 Linux `/dev/net/tun`、macOS utun 两条分支同一抽象、同一 `TunHandle` 语义——
   `cfg(windows)` 加第三个分支即可，`crates/platform` 的 TUN 抽象在三个桌面平台保持
   一致。直引 `wintun` 能拿到更细的控制，但要多维护一层 `wintun` FFI 封装，收益不足以
   抵消与既有 `tun` 抽象分裂的代价。**无论哪条路，wintun.dll 都必须随安装器分发**：
   wintun 以 LoadLibrary 在运行时加载，cargo-dist 的 MSI/NSIS 安装器要把 wintun.dll
   打进安装目录（wintun 许可证允许再分发，见代价与风险）。
2. **数据面被 boringtun 0.7.1 阻塞，不能直接上 boringtun**（本 ADR 相对初稿的修订，
   2026-08-14 实锤）。boringtun 0.7.1 的 `device` 特性（`DeviceHandle`）是 **Unix-only**：
   它只有 `tun_darwin.rs`（macOS/iOS/tvOS）与 `tun_linux.rs`（Linux）两个 TUN 后端、
   `kqueue.rs`/`epoll.rs` 两种 poll，且直接 `use std::os::unix::io::AsRawFd`——**没有
   `tun_windows.rs`、没有 Windows 编译路径**。因此 `crates/wg-userspace` 的 boringtun
   后端在 Windows 上**编译不过**，ADR-0007 的「boringtun 过渡后端」在 Windows 上失效。
   Windows 数据面只能走 spec §9 原定的 **gotatun**（Mullvad 跨平台重写，带 wintun 后端），
   但 gotatun MSRV 1.95 > 工作区 1.85（ADR-0007 阻塞项）未解除。结论：**平台网络能力
   （决策 4）先落地并编译验证，数据面/daemon/service 整体 blocked on gotatun**，如实
   标注，不硬塞一个 Unix-only 后端。
3. **服务化用 `windows-service` crate（crates.io），LocalSystem 账户**。它提供
   `ServiceDispatcher`/`ServiceControl`/事件日志的最小 SCM 封装，是本领域事实标准；
   若它不够（例如需要更细的恢复/依赖配置），Mullvad 的 `windows-service-rs` 是备选。
   服务直接跑既有的 `hextet daemon -c <config>` 命令：特权 daemon + 无特权 UI 的架构
   不变（Tauri 壳仍是无特权客户端，经 HTTP 状态服务取数）。
4. **平台能力在 `crates/platform` 加 `cfg(windows)` 分支**，镜像 Linux/macOS、沿用
   ADR-0008 的「最小 unsafe、如实标注」纪律：地址枚举（`GetAdaptersAddresses`）、
   路由增删（`GetIpForwardTable2`/`CreateIpForwardEntry2`/`DeleteIpForwardEntry2`）、
   IPv6 地址配装（`SetUnicastIpAddressEntry`/`DeleteUnicastIpAddressEntry`）、地址变化
   监听（`NotifyIpInterfaceChange`/`NotifyUnicastIpAddressChange` 或 2s 轮询兜底）。
   非 Windows 目标仍返回 `Unsupported`，与既有 stub 惯例一致。
5. **验证姿态：CI Windows runner 编译验证 + 运行时如实标注**。本机是 macOS，无法运行
   Windows；`windows-latest` 的 CI job 负责 `cargo build`/clippy/单测的编译级验证，
   wintun 握手/服务化/真实路由的运行时验证留真机（与 macOS daemon「仅编译验证」同一
   诚实边界）。

## 与 spec 的偏离记录

- spec §9 写「gotatun + wintun」。数据面**未偏离 spec**——仍指向 gotatun，只是 gotatun
  被 ADR-0007 的 MSRV 1.95 阻塞；初稿曾误判「Windows 可用 boringtun 过渡」，2026-08-14
  核实 boringtun 0.7.1 `device` 特性 Unix-only 后更正（见决策 2）。wintun.dll 需随
  安装器分发是 spec 未写明的运维事实，如实记录。
- spec §10 把服务化归在 `crates/daemon` 进程壳。Windows service 包装不新增 crate，
  作为 `crates/cli`（或 `crates/daemon`，实现时定）里的 `cfg(windows)` 服务入口，
  不改变既有的「daemon 进程壳」归属。

## 代价与风险

- **新依赖**：`windows-service` 与 `windows`/`windows-sys` 系（平台能力 FFI）。MSVC
  工具链 + wintun.dll 分发 + 代码签名是新增的发布工程负担；cargo-dist 的 Windows
  安装器需把 wintun.dll 打进包（wintun 允许再分发，签名状态随官方发布物）。
- **无法从 macOS 交叉编译**：Windows 目标依赖 MSVC，本地只做代码审查与
  `cfg(windows)` 之外的回归；编译正确性交给 CI `windows-latest`。
- **数据面 blocked on gotatun**：boringtun 0.7.1 无 Windows 编译路径（见决策 2），
  gotatun MSRV 1.95 未解除前 Windows 无法跑数据面；这是切片 D 的**硬阻塞**，不是
  「验证未完成」。
- **tun crate Windows 分支成熟度**：比 Linux/macOS 分支新，若发现句柄生命周期/读写
  语义不满足，再评估直引 `wintun`（重新评估条件见下）。

## 重新评估的条件

- **gotatun 落地**：工作区抬 MSRV 到 1.95 的决策已由 ADR-0012 定案；gotatun 集成
  （`crates/wg-userspace` 的 boringtun→gotatun 迁移）落地后，Windows 数据面随之解锁。
- 若出现带 wintun 后端的 boringtun 派生/升级 → 重新评估「boringtun 替代 gotatun」。
- `tun` crate 的 Windows 分支出现难以修复的缺陷 → 直引 `wintun` crate，用新 ADR 覆盖
  决策 1。
- `windows-service` crate 无法表达所需的恢复/依赖策略 → 换 Mullvad `windows-service-rs`。
