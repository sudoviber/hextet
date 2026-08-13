//! FFI 错误：把 engine 的富错误（`anyhow` / `WgError`）折叠成扁平错误（ADR-0012 决策 3）。

/// engine 控制面 FFI 的扁平错误。
///
/// 与 `core-ffi` 同一条折叠纪律：engine 侧的错误是携带结构化字段的富错误（`anyhow` 链、
/// `hextet_wg::types::WgError`），直接映射到 UniFFI 会生成带字段的异常类且 `io::Error`
/// 等 `#[source]` 字段本身不可 FFI。因此折叠成扁平枚举：变体名供 Kotlin 匹配异常类型，
/// `Display` 文本携带完整人类可读细节。
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum FfiError {
    /// 句柄未注册（backend 未 `create_backend`，或已被 `stop_daemon` 移除）。
    #[error("unknown backend handle: {0}")]
    UnknownHandle(u64),
    /// 该句柄上已启动 daemon（不允许重复 spawn）。
    #[error("daemon already spawned for handle: {0}")]
    AlreadySpawned(u64),
    /// 创建 tokio runtime 失败。
    #[error("failed to create tokio runtime: {0}")]
    Runtime(String),
    /// spawn daemon / 启动 runtime 线程失败。
    #[error("failed to spawn daemon: {0}")]
    Spawn(String),
    /// 后端操作失败（fd 注入、注册表锁中毒等）。
    #[error("backend error: {0}")]
    Backend(String),
    /// 当前平台不支持（fd 注入仅在 Android `VpnService` 上可用）。
    #[error("unsupported on this platform: {0}")]
    Unsupported(String),
}
