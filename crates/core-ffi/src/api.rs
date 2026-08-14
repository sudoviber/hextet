//! FFI 面：`hextet-core` 纯逻辑的同步导出（M7 第一片，见 ADR-0013）。
//!
//! 类型映射纪律（ADR-0013 决策 4）：
//! - 地址/endpoint（`Ipv6Addr` / `SocketAddrV6`）→ `String`（规范文本，边界内 `parse` / `to_string`）。
//! - 密钥/种子（`[u8; 32]`）→ base64 `String`（与 core 的线格式/人类格式一致）。
//! - 路径（`PathBuf`）→ `String`（Android 上由 Kotlin 传 app 私有目录）。
//! - 错误（`thiserror` 枚举）→ 扁平 [`FfiError`]（见 `error` 模块）。
//!
//! 全部函数同步、无 panic 跨越 FFI（UniFFI 的 `rust_call` 兜底 panic → 异常，但这里
//! 仍主动用 `Result` 表达可预期失败）。

use hextet_core::addr::derive_node_addr;
use hextet_core::config::Config;
use hextet_core::identity::{NodeIdentity, NodePublicKey};
use hextet_core::network::{NetworkKey, NetworkPrefix};

use crate::error::FfiError;

/// 一个新生成的身份：32 字节种子与公钥，均 base64。
///
/// Android 侧把 `seed_b64` 存进 Keystore / EncryptedSharedPreferences（**不要**落明文
/// 文件——core 的 `NodeIdentity::save` 是桌面 CLI 的 0600 文件路径，移动端由宿主接管）。
#[derive(uniffi::Record)]
pub struct GeneratedIdentity {
    /// 32 字节 ed25519 种子，base64。
    pub seed_b64: String,
    /// ed25519 公钥，base64。
    pub public_key_b64: String,
}

/// 一个节点在 overlay 里的派生地址簇（`hextet inspect` 的 `node` 字段等价）。
#[derive(uniffi::Record)]
pub struct NodeAddressInfo {
    /// 16-bit site 子网 id（网络内须唯一）。
    pub subnet_id: u16,
    /// 节点 site /64 网络地址。
    pub site: String,
    /// 节点自身 /128 地址。
    pub address: String,
}

/// 一个已校验 peer 的摘要（供 App 展示网络成员）。
#[derive(uniffi::Record)]
pub struct PeerSummary {
    /// peer 名。
    pub name: String,
    /// peer 的 ed25519 公钥（base64）。
    pub public_key_b64: String,
    /// peer 的 overlay /128 地址。
    pub address: String,
    /// peer 的 IPv6 endpoint（`[addr]:port` 文本，可为空——留给会合层发现）。
    pub endpoints: Vec<String>,
}

/// 已加载并校验的配置摘要（`hextet inspect` 的机器可读输出，去掉了 `PathBuf` 等 FFI 不友好字段）。
#[derive(uniffi::Record)]
pub struct ConfigSummary {
    /// 网络名。
    pub network_name: String,
    /// 网络 ULA /48 前缀。
    pub prefix: String,
    /// 本节点公钥（base64）。
    pub node_public_key_b64: String,
    /// 本节点 overlay /128 地址。
    pub node_address: String,
    /// 本节点 site /64。
    pub node_site: String,
    /// 本节点 WireGuard 监听端口。
    pub listen_port: u16,
    /// 已知 peer 列表。
    pub peers: Vec<PeerSummary>,
}

/// 生成一个新身份（`hextet keygen` 的 FFI 等价；不落盘，种子交给宿主保管）。
#[uniffi::export]
pub fn generate_identity() -> GeneratedIdentity {
    let id = NodeIdentity::generate();
    GeneratedIdentity {
        seed_b64: encode_seed(&id.seed()),
        public_key_b64: id.public().to_base64(),
    }
}

/// 从 base64 种子恢复身份并返回公钥（`hextet keygen` 反序列化等价）。
#[uniffi::export]
pub fn identity_public_key(seed_b64: String) -> Result<String, FfiError> {
    let seed = decode_seed(&seed_b64)?;
    Ok(NodeIdentity::from_seed(&seed).public().to_base64())
}

/// 由网络密钥派生网络 ULA /48 前缀（`hextet inspect` 的 `prefix` 字段等价）。
#[uniffi::export]
pub fn derive_network_prefix(network_key_b64: String) -> Result<String, FfiError> {
    let key = NetworkKey::from_base64(&network_key_b64).map_err(FfiError::from)?;
    Ok(NetworkPrefix::derive(&key).to_string())
}

/// 由网络密钥 + 节点公钥派生节点地址簇（`hextet inspect` 的 `node` 字段等价）。
#[uniffi::export]
pub fn derive_node_address(
    network_key_b64: String,
    public_key_b64: String,
) -> Result<NodeAddressInfo, FfiError> {
    let key = NetworkKey::from_base64(&network_key_b64).map_err(FfiError::from)?;
    let pk = NodePublicKey::from_base64(&public_key_b64).map_err(FfiError::from)?;
    let addr = derive_node_addr(NetworkPrefix::derive(&key), &pk).map_err(FfiError::from)?;
    Ok(NodeAddressInfo {
        subnet_id: addr.subnet_id,
        site: addr.site.to_string(),
        address: addr.address.to_string(),
    })
}

/// 渲染一份节点配置模板（`hextet init` 的 FFI 等价；返回 TOML 文本，由宿主决定是否落盘）。
#[uniffi::export]
pub fn render_config(
    name: String,
    network_key_b64: String,
    key_file: String,
    listen_port: u16,
    state_dir: Option<String>,
) -> Result<String, FfiError> {
    let key = NetworkKey::from_base64(&network_key_b64).map_err(FfiError::from)?;
    let state_dir = state_dir.as_deref().map(std::path::Path::new);
    Ok(Config::render_template(
        &name,
        &key,
        std::path::Path::new(&key_file),
        listen_port,
        state_dir,
    ))
}

/// 加载并校验一份配置，返回摘要（`hextet inspect` 的 FFI 等价；本节点公钥由调用方传入）。
#[uniffi::export]
pub fn load_config(path: String, own_public_key_b64: String) -> Result<ConfigSummary, FfiError> {
    let own_pk = NodePublicKey::from_base64(&own_public_key_b64).map_err(FfiError::from)?;
    let cfg = Config::load(std::path::Path::new(&path), Some(&own_pk)).map_err(FfiError::from)?;
    let own = derive_node_addr(cfg.prefix, &own_pk).map_err(FfiError::from)?;
    Ok(ConfigSummary {
        network_name: cfg.network_name,
        prefix: cfg.prefix.to_string(),
        node_public_key_b64: own_pk.to_base64(),
        node_address: own.address.to_string(),
        node_site: format!("{}/64", own.site),
        listen_port: cfg.node.listen_port,
        peers: cfg
            .peers
            .iter()
            .map(|p| PeerSummary {
                name: p.name.clone(),
                public_key_b64: p.public_key.to_base64(),
                address: p.addr.address.to_string(),
                endpoints: p.endpoints.iter().map(|e| e.to_string()).collect(),
            })
            .collect(),
    })
}

/// 32 字节种子 → 单行 base64（与 `NodeIdentity::save` 的线格式一致）。
fn encode_seed(seed: &[u8; 32]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(seed)
}

/// base64 → 32 字节种子；非 base64 或长度不对 → [`FfiError::InvalidInput`]。
fn decode_seed(s: &str) -> Result<[u8; 32], FfiError> {
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .map_err(|_| FfiError::InvalidInput("invalid base64 seed".into()))?;
    bytes
        .try_into()
        .map_err(|_| FfiError::InvalidInput("seed must be 32 bytes".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_generate_and_seed_roundtrip() {
        let id = generate_identity();
        assert_eq!(id.public_key_b64.len(), 44, "32 字节公钥 base64 = 44 字符");
        // 种子反序列化应得到同一公钥
        assert_eq!(
            identity_public_key(id.seed_b64.clone()).unwrap(),
            id.public_key_b64
        );
        // 不同种子 → 不同公钥
        let other = generate_identity();
        assert_ne!(other.public_key_b64, id.public_key_b64);
    }

    #[test]
    fn prefix_and_address_derive_consistently() {
        let nk = NetworkKey::generate();
        let nk_b64 = nk.to_base64();

        let prefix = derive_network_prefix(nk_b64.clone()).unwrap();
        assert!(prefix.ends_with("::/48"), "prefix = {prefix}");
        let prefix_addr: std::net::Ipv6Addr = prefix.trim_end_matches("/48").parse().unwrap();
        assert_eq!(prefix_addr.octets()[0], 0xfd, "ULA 前缀首字节必须是 0xfd");

        let id = generate_identity();
        let addr = derive_node_address(nk_b64, id.public_key_b64).unwrap();
        let node_addr: std::net::Ipv6Addr = addr.address.parse().unwrap();
        let site: std::net::Ipv6Addr = addr.site.parse().unwrap();
        // 节点地址落在派生的 /48 前缀内
        assert_eq!(node_addr.octets()[..6], prefix_addr.octets()[..6]);
        // site 是 /64 网络地址（后 64 位全零）
        assert_eq!(site.octets()[8..], [0u8; 8]);
        // 节点地址落在自己的 site /64 内
        assert_eq!(node_addr.octets()[..8], site.octets()[..8]);
    }

    #[test]
    fn render_config_roundtrips_through_load() {
        let nk = NetworkKey::generate();
        let id = generate_identity();
        let text = render_config(
            "home".into(),
            nk.to_base64(),
            "node.key".into(),
            hextet_core::defaults::DEFAULT_PORT,
            None,
        )
        .unwrap();

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hextet.toml");
        std::fs::write(&path, text).unwrap();

        let summary = load_config(path.display().to_string(), id.public_key_b64.clone()).unwrap();
        assert_eq!(summary.network_name, "home");
        assert_eq!(summary.node_public_key_b64, id.public_key_b64);
        assert_eq!(summary.listen_port, hextet_core::defaults::DEFAULT_PORT);
        assert!(summary.peers.is_empty());
        // 配置里的前缀与直接派生一致
        assert_eq!(
            summary.prefix,
            derive_network_prefix(nk.to_base64()).unwrap()
        );
    }

    #[test]
    fn invalid_inputs_are_rejected() {
        assert!(derive_network_prefix("!!!".into()).is_err());
        assert!(identity_public_key("short".into()).is_err());
        assert!(
            identity_public_key("QUJD".into()).is_err(),
            "3 字节种子长度非法"
        );
        assert!(derive_node_address(NetworkKey::generate().to_base64(), "bad!!".into()).is_err());
        assert!(render_config("home".into(), "bad!!".into(), "k".into(), 4193, None).is_err());
    }
}
