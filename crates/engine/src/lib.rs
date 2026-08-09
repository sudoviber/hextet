//! hextet 可嵌入引擎：打洞状态机、端点缓存、运行时状态快照与守护进程主循环。
//!
//! 分层原则——本 crate 里除了 `daemon` 与探针的 socket 部分，全部是**纯逻辑**
//! （无 I/O、无 root、无平台依赖），因此能在任何开发机上被 `cargo test` 完整覆盖；
//! `daemon` 只做接线，由 `scripts/netns-e2e-*.sh` 覆盖。M7 的 Android FFI 直接
//! 复用本 crate，不要在这里假设"自己是一个进程"以外的东西。
#![deny(missing_docs)]

pub mod atomic;
pub mod cache;
pub mod candidates;
pub mod doctor_client;
pub mod fsm;
pub mod probe_responder;
pub mod spec;
pub mod state;

#[cfg(target_os = "linux")]
pub mod daemon;

#[cfg(not(target_os = "linux"))]
pub mod daemon {
    //! 非 Linux 平台的守护进程占位（M4 起支持 macOS）。

    use std::path::Path;

    /// 非 Linux 平台暂不支持守护进程。
    pub fn run(_config_path: &Path) -> anyhow::Result<()> {
        anyhow::bail!("hextet daemon 目前仅支持 Linux（macOS 在 M4）")
    }
}
