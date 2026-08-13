//! 平台默认后端工厂（ADR-0007 决策 3 / ADR-0009 决策 4 / ADR-0012）。
//!
//! 后端按编译期 `cfg(target_os)` 选择，零运行时分支、无 `Box<dyn WgBackend>` 间接层，
//! 每个平台只编译自己的后端（与 `crates/wg` 里 `kernel` 模块 `#[cfg(target_os = "linux")]`
//! 的既定模式一致）。工厂放在 `crates/cli` 而非 `crates/wg`：`hextet-wg-userspace`
//! 依赖 `hextet-wg`，把返回 `UserspaceBackend` 的工厂放进 `hextet-wg` 会形成依赖环。
//!
//! 定义于 Linux、macOS、Windows；其余平台（Android M7）未实现，调用方须自行 `#[cfg]`
//! 门控（`up.rs` 已这么做）。

use hextet_wg::WgBackend;

/// 返回当前平台的默认后端。
///
/// Linux → 内核 WireGuard（netlink）。
#[cfg(target_os = "linux")]
pub(crate) fn platform_default() -> impl WgBackend {
    hextet_wg::kernel::KernelBackend
}

/// 返回当前平台的默认后端。
///
/// macOS → gotatun 用户态后端（ADR-0012）。
#[cfg(target_os = "macos")]
pub(crate) fn platform_default() -> impl WgBackend {
    hextet_wg_userspace::UserspaceBackend::new()
}

/// 返回当前平台的默认后端。
///
/// Windows → gotatun 用户态后端（ADR-0012，经 `tun` crate 的 wintun 分支）。
#[cfg(target_os = "windows")]
pub(crate) fn platform_default() -> impl WgBackend {
    hextet_wg_userspace::UserspaceBackend::new()
}
