# ADR-0012：抬升工作区 MSRV 到 1.95，启用 gotatun 作为 Windows/Android 数据面

- 状态：已接受
- 日期：2026-08-14
- 相关：ADR-0007（gotatun→boringtun 过渡）、ADR-0011（Windows 数据面 blocked on gotatun）、
  `docs/superpowers/specs/2026-08-06-hextet-design.md` §3 D1 / §8 M6/M7 / §9

## 背景

ADR-0007 因为「gotatun MSRV 1.95 会抬工作区 MSRV 1.85 + 审计未完」把数据面暂时落在
boringtun 0.7.1（过渡后端）。ADR-0011 进一步核实：boringtun 0.7.1 的 `device` 特性是
**Unix-only**（只有 `tun_darwin.rs`/`tun_linux.rs`，`use std::os::unix::io::AsRawFd`），
Windows 数据面因此 blocked。本 ADR 核实 gotatun 现状并拍板 MSRV 抬升，解锁 Windows
（M6 D）与 Android（M7）两个数据面。

## 事实核实（2026-08-14，`cargo info gotatun`）

- **版本 0.8.1**，`rust-version = 1.95`，许可证 **MPL-2.0**（已在 `deny.toml`
  `[licenses].allow` 放行）。
- **跨平台**：features 含 `device`（数据面设备）、`tun`（`dep:tun`——就是本项目已在用的
  `tun` crate，其 Windows 分支走 wintun）、`windows-gro`（Windows Generic Receive
  Offload）、`ring` / `aws-lc-rs`（crypto 提供方二选一）。这正是 spec §9 的
  「gotatun + wintun」原定目标，与 Android 的「gotatun（in-process，Mullvad Android
  生产同款）」一致。
- 当前本机/CI 工具链是 `stable`（1.97.1），`rust-toolchain.toml` 锁 `stable`；工作区
  的 `rust-version = "1.85"` 是一个**已不再被实际工具链约束的保守下限**。

## 决策

1. **工作区 MSRV 从 1.85 抬到 1.95**（`Cargo.toml` 的 `[workspace.package] rust-version`）。
   理由：gotatun 0.8.1 要求 1.95；实际工具链已 1.97；1.85 的下限是 ADR-0007 时为迁就
   boringtun 而定，现已无绑定价值。
2. **数据面改用 gotatun 0.8.1（锁死版本），替换 boringtun 过渡**：`crates/wg-userspace`
   的 boringtun 后端迁到 gotatun，用 `default-features = false, features = ["device",
   "tun", "ring"]`（**ring 提供方**，避开 aws-lc-rs 的交叉编译坑，spec §13；`tun` 复用
   `crates/platform` 已接的 `tun` crate wintun 分支）。Linux 仍走内核 WireGuard
   （`KernelBackend`），gotatun 只用于 macOS（继续替代 boringtun）/Windows/Android。
3. **`rust-version` 的抬升随 gotatun 集成一起落地**：boringtun→gotatun 的 `WgBackend`
   实现迁移是一个独立大项（API 完全不同、需逐平台运行时验证），单独立项推进；在
   gotatun 真正进入 `crates/wg-userspace` 之前，`rust-version` 保持 1.85（声明的下限
   与实际依赖一致），迁移 PR 里一并抬到 1.95。本 ADR 只解除阻塞、把方向定死。
4. **诚实边界不变**：gotatun 集成后的 Windows/Android 运行时验证仍需真机/CI，编译验证
   走既有 `check-windows`（MSVC）与未来的 Android CI。

## 代价与风险

- **MSRV 抬升**：任何在 Rust 1.85–1.94 上的构建将失效。实际影响面小——`rust-toolchain.toml`
  锁 `stable`，本地/CI 都 ≥1.95；OpenWrt feed 与 Android NDK 的 Rust 交叉工具链跟随
  上游 stable，1.95 均已覆盖（MIPS 本就 Tier 3 不支持）。
- **gotatun 是新实现**（ADR-0007 的「审计未完」仍在）：用 ring 提供方 + 锁死版本
  `=0.8.1` 隔离，`cargo deny check`（含 yanked/advisories）常开兜底；与 boringtun 一样
  封装在 `crates/wg-userspace` 内、不向外部暴露 gotatun 类型。
- **迁移成本**：gotatun 与 boringtun 的 API 不同，`set_peer_endpoint`/`status` 等语义
  要逐项重接；这是 ADR-0007 早已预留的「过渡后端」出口。

## 重新评估的条件

- gotatun 出现 RUSTSEC / yanked / 审计结论负面 → 回退 boringtun（macOS）并重新评估
  Windows/Android 的替代（wireguard-go / NepTUN）。
- 若 OpenWrt 某目标在 1.95 无可用 toolchain → 针对性回退该目标的 MSRV 承诺，其余平台
  不受影响。
