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

/// 地址派生错误。
#[derive(Debug, thiserror::Error)]
pub enum AddrError {
    /// 派生出全零 interface ID（概率 2^-64，视为密钥不可用）。
    #[error("degenerate interface id derived from public key")]
    DegenerateIid,
    /// 两个节点派生出相同的 16-bit subnet id。
    #[error("subnet id collision between {a} and {b}; one node must regenerate its key")]
    SubnetCollision {
        /// 冲突节点甲。
        a: String,
        /// 冲突节点乙。
        b: String,
    },
}

/// 配置错误。
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// 文件读取失败。
    #[error("config {path}: {source}")]
    Io {
        /// 配置文件路径。
        path: std::path::PathBuf,
        /// 底层 I/O 错误。
        #[source]
        source: std::io::Error,
    },
    /// TOML 语法/结构错误。
    #[error("config parse error: {0}")]
    Parse(#[from] toml::de::Error),
    /// 网络密钥或 peer 公钥编码非法。
    #[error("peer {name}: {source}")]
    BadKey {
        /// peer 名。
        name: String,
        /// 底层错误。
        #[source]
        source: crate::error::IdentityError,
    },
    /// endpoint 不是 IPv6。hextet 是 IPv6-only 的。
    #[error("peer {name}: endpoint {endpoint} is IPv4; hextet is IPv6-only")]
    Ipv4Endpoint {
        /// peer 名。
        name: String,
        /// 违规 endpoint 原文。
        endpoint: String,
    },
    /// endpoint 无法解析。
    #[error("peer {name}: invalid endpoint {endpoint}")]
    BadEndpoint {
        /// peer 名。
        name: String,
        /// 违规 endpoint 原文。
        endpoint: String,
    },
    /// 两个 peer 用了同一把公钥。
    #[error("peers {a} and {b} share the same public key")]
    DuplicatePeer {
        /// peer 甲。
        a: String,
        /// peer 乙。
        b: String,
    },
    /// subnet id 碰撞。
    #[error(transparent)]
    Addr(#[from] AddrError),
    /// 网络密钥缺失/非法。
    #[error("invalid network key")]
    BadNetworkKey,
    /// `key_file` 指向的身份文件不可读或格式非法。
    #[error("identity {path}: {source}")]
    Identity {
        /// 身份文件路径。
        path: std::path::PathBuf,
        /// 底层身份错误。
        #[source]
        source: crate::error::IdentityError,
    },
}

/// doctor 探针报文错误。
#[derive(Debug, thiserror::Error)]
pub enum ProbeError {
    /// 数据报短于固定长度。
    #[error("probe packet too short")]
    TooShort,
    /// magic 不是 `HXTP`。
    #[error("probe packet has wrong magic")]
    BadMagic,
    /// 协议版本不认识。
    #[error("unsupported probe version {0}")]
    BadVersion(u8),
    /// 报文类型不认识。
    #[error("unknown probe kind {0}")]
    BadKind(u8),
    /// MAC 校验失败（密钥不对或报文被篡改）。
    #[error("probe packet MAC verification failed")]
    BadMac,
}
