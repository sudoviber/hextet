//! 平台默认后端工厂（ADR-0007 决策 3 / ADR-0009 决策 4）。
//!
//! 后端按编译期 `cfg(target_os)` 选择，零运行时分支、无 `Box<dyn WgBackend>` 间接层，
//! 每个平台只编译自己的后端（与 `crates/wg` 里 `kernel` 模块 `#[cfg(target_os = "linux")]`
//! 的既定模式一致）。工厂放在 `crates/engine` 而非 `crates/wg`：`hextet-wg-userspace`
//! 依赖 `hextet-wg`，把返回 `UserspaceBackend` 的工厂放进 `hextet-wg` 会形成依赖环
//! （镜像 `crates/cli/src/commands/backend.rs` 的同款理由）。
//!
//! 只对 Linux、macOS 与 Android 定义 [`platform_default`]；其余平台未实现——`daemon`
//! 只在这三个平台上编译（Linux 走内核后端、macOS 走 boringtun 用户态后端、Android 走
//! gotatun 用户态后端，ADR-0007 决策 3 / ADR-0013 D1 / ADR-0014 D2），调用方无需再
//! `#[cfg]` 门控。

use hextet_wg::WgBackend;

/// 返回当前平台的默认后端（可塞进 `Arc<dyn WgBackend + Send + Sync>` 供打洞循环与
/// HTTP 状态服务共享）。
///
/// Linux → 内核 WireGuard（netlink，`KernelBackend` 是零大小单元结构，廉价 `Copy`）；
/// macOS → boringtun 用户态后端（`UserspaceBackend::new()` 持有 `Mutex` 注册表与
/// `DeviceHandle`，**不** `Clone`——必须共享同一实例）。
#[cfg(target_os = "linux")]
pub(crate) fn platform_default() -> impl WgBackend + Send + Sync + 'static {
    hextet_wg::kernel::KernelBackend
}

/// 返回当前平台的默认后端（可塞进 `Arc<dyn WgBackend + Send + Sync>` 供打洞循环与
/// HTTP 状态服务共享）。
///
/// Linux → 内核 WireGuard（netlink）；macOS → boringtun 用户态后端（ADR-0007 决策 1）。
#[cfg(target_os = "macos")]
pub(crate) fn platform_default() -> impl WgBackend + Send + Sync + 'static {
    hextet_wg_userspace::UserspaceBackend::new()
}

/// 返回当前平台的默认后端（可塞进 `Arc<dyn WgBackend + Send + Sync>` 供打洞循环与
/// HTTP 状态服务共享）。
///
/// Android → gotatun 用户态后端（ADR-0013 D1）；其余平台见上（Linux 内核 / macOS
/// boringtun）。Android 的 VpnService fd 由 slice D 的 JNI glue 经
/// `GotatunBackend::set_tun_fd` 预注入，`apply` 时接线（ADR-0014 D2）。
#[cfg(target_os = "android")]
pub(crate) fn platform_default() -> impl WgBackend + Send + Sync + 'static {
    hextet_wg_userspace::GotatunBackend::new()
}
