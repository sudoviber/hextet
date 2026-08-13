//! 平台默认后端工厂（ADR-0007 决策 3 / ADR-0009 决策 4 / ADR-0012）。
//!
//! 后端按编译期 `cfg(target_os)` 选择，零运行时分支、无 `Box<dyn WgBackend>` 间接层，
//! 每个平台只编译自己的后端（与 `crates/wg` 里 `kernel` 模块 `#[cfg(target_os = "linux")]`
//! 的既定模式一致）。工厂放在 `crates/engine` 而非 `crates/wg`：`hextet-wg-userspace`
//! 依赖 `hextet-wg`，把返回 `UserspaceBackend` 的工厂放进 `hextet-wg` 会形成依赖环
//! （镜像 `crates/cli/src/commands/backend.rs` 的同款理由）。
//!
//! 定义于 Linux、macOS、Windows；其余平台（Android M7）未实现——`daemon` 只在这三个
//! 平台上编译（Linux 走内核后端、macOS/Windows 走 gotatun 用户态后端，ADR-0012），
//! 调用方无需再 `#[cfg]` 门控。

use hextet_wg::WgBackend;

/// 返回当前平台的默认后端（可塞进 `Arc<dyn WgBackend + Send + Sync>` 供打洞循环与
/// HTTP 状态服务共享）。
///
/// Linux → 内核 WireGuard（netlink，`KernelBackend` 是零大小单元结构，廉价 `Copy`）。
#[cfg(target_os = "linux")]
pub(crate) fn platform_default() -> impl WgBackend + Send + Sync + 'static {
    hextet_wg::kernel::KernelBackend
}

/// 返回当前平台的默认后端。
///
/// macOS → gotatun 用户态后端（ADR-0012：boringtun 已迁移到 gotatun 0.8.1）。
#[cfg(target_os = "macos")]
pub(crate) fn platform_default() -> impl WgBackend + Send + Sync + 'static {
    hextet_wg_userspace::UserspaceBackend::new()
}

/// 返回当前平台的默认后端。
///
/// Windows → gotatun 用户态后端（ADR-0012：gotatun 跨平台，经 `tun` crate 的 wintun
/// 分支 + `windows-gro`；`UserspaceBackend` 内嵌 tokio runtime，跨平台可编译）。
#[cfg(target_os = "windows")]
pub(crate) fn platform_default() -> impl WgBackend + Send + Sync + 'static {
    hextet_wg_userspace::UserspaceBackend::new()
}
