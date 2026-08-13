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

/// 子网路由（site-to-site）解析错误。
#[derive(Debug, thiserror::Error)]
pub enum RouteError {
    /// 不是合法的 `前缀/长度` CIDR。
    #[error("invalid IPv6 CIDR {0}")]
    Invalid(String),
    /// 是 IPv4。hextet 是 IPv6-only 的。
    #[error("{0} is IPv4; hextet is IPv6-only")]
    Ipv4(String),
    /// 前缀长度越界。
    #[error("prefix length {0} out of range 1..=128")]
    BadPrefixLen(u8),
    /// host 位非零：前缀必须是网络地址。
    #[error("host bits are non-zero in {0}; a route prefix must be a network address")]
    HostBitsSet(String),
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
    /// 标了 `relay = true` 的 peer 没有任何 endpoint。
    #[error("peer {name}: relay = true but no endpoints; 中继地址未知等于没配")]
    RelayWithoutEndpoint {
        /// peer 名。
        name: String,
    },
    /// `[node] http_addr` 与 `http_port` 必须成对出现（要么都有、要么都没有）。
    #[error("[node] http_addr/http_port must be set together (both or neither)")]
    HttpAddrPortMismatch,
    /// `[ddns]` 启用了但没给 `update_url`。
    #[error("[ddns] enabled but update_url is missing")]
    DdnsMissingUpdateUrl,
    /// `[ddns] update_url` 缺少 `{address}` 占位符。
    #[error("[ddns] update_url must contain the {{address}} placeholder")]
    DdnsBadTemplate,
    /// `key_file` 指向的身份文件不可读或格式非法。
    #[error("identity {path}: {source}")]
    Identity {
        /// 身份文件路径。
        path: std::path::PathBuf,
        /// 底层身份错误。
        #[source]
        source: crate::error::IdentityError,
    },
    /// 通告路由无法解析。
    #[error("peer {name}: invalid route {route}: {source}")]
    BadRoute {
        /// peer 名。
        name: String,
        /// 违规路由原文。
        route: String,
        /// 底层错误。
        #[source]
        source: crate::error::RouteError,
    },
    /// 同一个 peer 通告了重复的路由。
    #[error("peer {name}: duplicate route {route}")]
    DuplicateRoute {
        /// peer 名。
        name: String,
        /// 重复的路由。
        route: String,
    },
    /// 一条通告路由与 overlay /48 或本节点自己的 /64 site 冲突。
    #[error("peer {name}: route {route} overlaps the overlay /48 or the local node's /64 site")]
    RouteConflict {
        /// peer 名。
        name: String,
        /// 冲突路由。
        route: String,
    },
    /// 两个 peer 通告了互相重叠的路由。
    #[error("peers {a} and {b} advertise overlapping routes ({route_a} vs {route_b})")]
    RouteOverlap {
        /// peer 甲。
        a: String,
        /// peer 乙。
        b: String,
        /// 甲的路由。
        route_a: String,
        /// 乙的路由。
        route_b: String,
    },
}

/// invite token 错误。
#[derive(Debug, thiserror::Error)]
pub enum InviteError {
    /// 不是以 `hxi1.` 开头。
    #[error("not a hextet invite token (expected the hxi1. prefix)")]
    BadPrefix,
    /// 段数不对、base64 非法、或签名长度不对。
    #[error("malformed invite token")]
    Malformed,
    /// 载荷 JSON 结构非法。
    #[error("invalid invite payload: {0}")]
    BadJson(String),
    /// 协议版本不认识。
    #[error("unsupported invite version {0}")]
    BadVersion(u32),
    /// 签名校验失败（token 被篡改或签名不属于 issuer）。
    #[error("invite signature verification failed")]
    BadSignature,
    /// 用来签名的身份不是 token 里声明的 issuer。
    #[error("signing identity does not match the invite issuer")]
    IssuerMismatch,
    /// token 已过期。
    #[error("invite expired at {expires_unix} (now {now_unix})")]
    Expired {
        /// 过期时刻（Unix 秒）。
        expires_unix: u64,
        /// 当前时刻（Unix 秒）。
        now_unix: u64,
    },
    /// 没有引导节点的 token 无法用来入网。
    #[error("invite has no bootstrap peer")]
    NoBootstrap,
    /// 引导节点数量超过上限。
    #[error("invite has {0} bootstrap peers, more than allowed")]
    TooManyBootstrap(usize),
    /// endpoint 不是 IPv6。hextet 是 IPv6-only 的。
    #[error("invite endpoint {0} is IPv4; hextet is IPv6-only")]
    Ipv4Endpoint(String),
    /// endpoint 无法解析。
    #[error("invite has invalid endpoint {0}")]
    BadEndpoint(String),
    /// 网络密钥或节点公钥编码非法。
    #[error("invite key: {0}")]
    BadKey(#[source] IdentityError),
}

/// 中继控制帧错误。
#[derive(Debug, thiserror::Error)]
pub enum RelayError {
    /// 数据报短于定长。
    #[error("relay frame too short")]
    TooShort,
    /// magic 不是 `HXTR`。
    #[error("relay frame has wrong magic")]
    BadMagic,
    /// 协议版本不认识。
    #[error("unsupported relay frame version {0}")]
    BadVersion(u8),
    /// 帧类型不认识。
    #[error("unknown relay frame kind {0}")]
    BadKind(u8),
    /// MAC 校验失败（密钥不对或报文被篡改）。
    #[error("relay frame MAC verification failed")]
    BadMac,
    /// 公钥不是合法的 ed25519 点。
    #[error("relay frame carries an invalid ed25519 public key")]
    BadPublicKey,
    /// 两端公钥相同（自己跟自己配对）。
    #[error("relay frame pairs a node with itself")]
    SelfPair,
}

/// LAN 组播公告报文错误。
#[derive(Debug, thiserror::Error)]
pub enum BeaconError {
    /// 数据报短于最小长度（头部 + MAC）。
    #[error("beacon too short")]
    TooShort,
    /// magic 不是 `HXTL`。
    #[error("beacon has wrong magic")]
    BadMagic,
    /// 协议版本不认识。
    #[error("unsupported beacon version {0}")]
    BadVersion(u8),
    /// 报文类型不认识。
    #[error("unknown beacon kind {0}")]
    BadKind(u8),
    /// 保留字节非零。
    #[error("beacon reserved byte must be zero")]
    BadReserved,
    /// 地址数量超过上限。
    #[error("beacon carries {0} addresses, more than allowed")]
    TooManyAddrs(usize),
    /// 报文长度与 `addr_count` 不自洽。
    #[error("beacon length mismatch: expected {expected}, got {got}")]
    LengthMismatch {
        /// 按 `addr_count` 算出的应有长度。
        expected: usize,
        /// 实际长度。
        got: usize,
    },
    /// MAC 校验失败（密钥不对或报文被篡改）。
    #[error("beacon MAC verification failed")]
    BadMac,
    /// 公钥不是合法的 ed25519 点。
    #[error("beacon carries an invalid ed25519 public key")]
    BadPublicKey,
}

/// gossip 条目错误。
#[derive(Debug, thiserror::Error)]
pub enum GossipError {
    /// 数据报短于最小长度。
    #[error("gossip entry too short")]
    TooShort,
    /// magic 不是 `HXTG`。
    #[error("gossip entry has wrong magic")]
    BadMagic,
    /// 协议版本不认识。
    #[error("unsupported gossip version {0}")]
    BadVersion(u8),
    /// 条目类型不认识。
    #[error("unknown gossip entry kind {0}")]
    BadKind(u8),
    /// endpoint 地址数量超过上限。
    #[error("gossip entry carries {0} endpoints, more than allowed")]
    TooManyAddrs(usize),
    /// 成员名超过长度上限。
    #[error("gossip member name is {0} bytes, longer than allowed")]
    NameTooLong(usize),
    /// 成员名不是合法 UTF-8。
    #[error("gossip member name is not valid UTF-8")]
    BadUtf8,
    /// 报文长度与字段不自洽。
    #[error("gossip entry length mismatch: expected {expected}, got {got}")]
    LengthMismatch {
        /// 按字段算出的应有长度。
        expected: usize,
        /// 实际长度。
        got: usize,
    },
    /// 签名校验失败（被篡改或签名者不是条目声明的 signer）。
    #[error("gossip entry signature verification failed")]
    BadSignature,
    /// 公钥不是合法的 ed25519 点。
    #[error("gossip entry carries an invalid ed25519 public key")]
    BadPublicKey,
    /// endpoint 条目必须由 node 自己签名（不能替别人宣告地址）。
    #[error("gossip endpoint entry must be self-signed")]
    EndpointNotSelfSigned,
    /// member/revocation 条目不能由被准入/被吊销的 node 自己签发。
    #[error("gossip member/revocation entry cannot be issued by its own subject")]
    SelfIssued,
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
