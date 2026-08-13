//! hextet 可嵌入引擎：打洞状态机、端点缓存、运行时状态快照与守护进程主循环。
//!
//! 分层原则——本 crate 里除了 `daemon` 与探针的 socket 部分，全部是**纯逻辑**
//! （无 I/O、无 root、无平台依赖），因此能在任何开发机上被 `cargo test` 完整覆盖；
//! `daemon` 只做接线，由 `scripts/netns-e2e-*.sh` 覆盖。M7 的 Android FFI 直接
//! 复用本 crate，不要在这里假设"自己是一个进程"以外的东西。
//!
//! `daemon` 在 Linux 与 macOS 上可用：Linux 走内核 WireGuard 后端
//! （`hextet_wg::kernel::KernelBackend`），macOS 走 boringtun 用户态后端
//! （`hextet_wg_userspace::UserspaceBackend`），后端由 [`backend::platform_default`] 按
//! `cfg(target_os)` 选择（ADR-0007 决策 3 / ADR-0009 决策 4）。其余平台（Android M7 /
//! Windows M6 的 wintun 尚未落地）保留 `daemon` 占位桩，保证本 crate 仍可交叉编译。
#![deny(missing_docs)]

pub mod atomic;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) mod backend;
pub mod cache;
pub mod candidates;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod daemon;
pub mod ddns;
pub mod dht;
pub mod doctor_client;
pub mod fsm;
pub mod gossip;
pub mod http;
pub mod lan;
pub mod members;
pub mod probe_responder;
pub mod relay_client;
pub mod relay_server;
pub mod route_manager;
pub mod spec;
pub mod state;
pub mod status;

/// 非 Linux/macOS 平台的守护进程占位：后端（内核 / boringtun 用户态）尚未落地，
/// 但保持 `daemon::run` 的公开签名不变，让本 crate 在 Android（M7）/ Windows（M6）
/// 等 target 上仍可交叉编译。诚实返回不支持，而非假装可用。
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub mod daemon {
    use std::path::Path;

    /// 非 Linux/macOS 平台暂不支持守护进程（后端尚未落地）。
    pub fn run(_config_path: &Path) -> anyhow::Result<()> {
        anyhow::bail!("hextet daemon 目前仅支持 Linux 与 macOS")
    }

    /// 守护进程控制句柄的非 Linux/macOS 占位。
    ///
    /// 与 linux/macos 上的真实 `DaemonHandle` 同构（同样的字段类型 + `stop`/`wait`
    /// 方法），保证公开 API 面跨 target 对称。但本平台后端尚未落地，`run`/`spawn_on`
    /// 都直接 `bail`，此结构体永远不会被构造。
    pub struct DaemonHandle {
        /// 停机信号发送端（占位，永不被使用）。
        _shutdown: tokio::sync::watch::Sender<bool>,
        /// 主循环任务句柄（占位，永不被使用）。
        _join: tokio::task::JoinHandle<()>,
    }

    impl DaemonHandle {
        /// 占位：非 Linux/macOS 平台没有可停的守护进程。
        pub fn stop(&self) {}

        /// 占位：非 Linux/macOS 平台没有可等的守护进程。
        pub async fn wait(self) {}
    }

    /// 非 Linux/macOS 平台暂不支持守护进程（后端尚未落地）。
    ///
    /// 占位桩：与 [`run`] 一样诚实返回不支持，保持公开 API 面在跨 target 时对称
    /// （Android 后端由 M7 后续片落地后替换为本片在 linux/macos 上的真实实现）。
    pub fn spawn_on(
        _handle: tokio::runtime::Handle,
        _config_path: &Path,
    ) -> anyhow::Result<DaemonHandle> {
        anyhow::bail!("hextet daemon 目前仅支持 Linux 与 macOS")
    }
}
