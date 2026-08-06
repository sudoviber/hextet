//! 核心错误类型。

/// 身份/密钥相关错误。
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    /// 密钥文件 I/O 失败。
    #[error("key file {path}: {source}")]
    Io {
        /// 出错的文件路径。
        path: std::path::PathBuf,
        /// 底层 I/O 错误。
        #[source]
        source: std::io::Error,
    },
    /// base64 或长度不合法。
    #[error("invalid key encoding")]
    InvalidEncoding,
    /// 不是合法的 ed25519 公钥点。
    #[error("invalid ed25519 public key")]
    InvalidPublicKey,
}
