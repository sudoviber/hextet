//! FFI 错误：把 core 的 `thiserror` 错误枚举折叠成一个扁平的错误枚举（ADR-0013 决策 3）。

use hextet_core::error::{AddrError, ConfigError, IdentityError};

/// hextet core FFI 的扁平错误。
///
/// core 的错误枚举（[`ConfigError`] / [`IdentityError`] / [`AddrError`]）是携带结构化字段的
/// 富枚举，直接映射到 UniFFI 会生成一堆带字段的异常类，且嵌套的 `#[source]` 字段（如
/// `io::Error`）本身不可 FFI。因此本片把错误折叠成一个**扁平**枚举：变体名供 Kotlin 匹配
/// 异常类型，`Display` 文本（thiserror 生成）携带完整人类可读细节（哪个 peer、哪个字段）。
///
/// ADR-0013 决策 3 记录了取舍：放弃结构化错误字段的可编程性，换取简单、稳定、可匹配的
/// 异常面。若后续 Android 侧需要按字段做精细处理，再按 ADR 重新评估。
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum FfiError {
    /// 入参非法（base64 解码失败、长度错误、非法公钥点等）。
    #[error("invalid input: {0}")]
    InvalidInput(String),
    /// 文件/路径 I/O 失败。
    #[error("I/O error: {0}")]
    Io(String),
    /// 配置解析/校验失败（含 peer 校验、subnet 碰撞、路由冲突等）。
    #[error("invalid config: {0}")]
    InvalidConfig(String),
    /// 地址派生失败（退化 interface id、subnet id 碰撞）。
    #[error("address derivation failed: {0}")]
    AddressDerivation(String),
}

impl From<IdentityError> for FfiError {
    fn from(e: IdentityError) -> Self {
        match e {
            IdentityError::Io { path, source } => {
                FfiError::Io(format!("{}: {source}", path.display()))
            }
            other => FfiError::InvalidInput(other.to_string()),
        }
    }
}

impl From<AddrError> for FfiError {
    fn from(e: AddrError) -> Self {
        FfiError::AddressDerivation(e.to_string())
    }
}

impl From<ConfigError> for FfiError {
    fn from(e: ConfigError) -> Self {
        match &e {
            ConfigError::Io { path, source } => {
                FfiError::Io(format!("{}: {source}", path.display()))
            }
            _ => FfiError::InvalidConfig(e.to_string()),
        }
    }
}
