//! 节点配置：TOML 解析、默认值、派生与校验。

use std::net::{SocketAddr, SocketAddrV6};
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::addr::{NodeAddr, check_subnet_collisions, derive_node_addr};
use crate::defaults;
use crate::error::ConfigError;
use crate::identity::NodePublicKey;
use crate::network::{NetworkKey, NetworkPrefix};

#[derive(Deserialize)]
struct RawConfig {
    network: RawNetwork,
    node: RawNode,
    #[serde(default)]
    peers: Vec<RawPeer>,
}

#[derive(Deserialize)]
struct RawNetwork {
    name: String,
    key: String,
}

#[derive(Deserialize)]
struct RawNode {
    key_file: PathBuf,
    listen_port: Option<u16>,
    mtu: Option<u32>,
    interface: Option<String>,
}

#[derive(Deserialize)]
struct RawPeer {
    name: String,
    public_key: String,
    #[serde(default)]
    endpoints: Vec<String>,
}

/// 节点本地设置。
#[derive(Debug, Clone)]
pub struct NodeSettings {
    /// 节点密钥文件路径。
    pub key_file: PathBuf,
    /// WireGuard UDP 监听端口。
    pub listen_port: u16,
    /// 隧道 MTU。
    pub mtu: u32,
    /// 虚拟网络接口名。
    pub interface: String,
}

/// 一个已校验的 peer。
#[derive(Debug, Clone)]
pub struct Peer {
    /// peer 名。
    pub name: String,
    /// peer 的 ed25519 公钥。
    pub public_key: NodePublicKey,
    /// peer 的 IPv6 endpoint 列表。
    pub endpoints: Vec<SocketAddrV6>,
    /// peer 在网络中的派生地址。
    pub addr: NodeAddr,
}

/// 已加载并校验的配置。
#[derive(Debug)]
pub struct Config {
    /// 网络名。
    pub network_name: String,
    /// 网络共享密钥。
    pub network_key: NetworkKey,
    /// 网络 ULA /48 前缀。
    pub prefix: NetworkPrefix,
    /// 本节点设置。
    pub node: NodeSettings,
    /// 已知 peer 列表。
    pub peers: Vec<Peer>,
}

impl Config {
    /// 加载配置：解析 TOML → 派生前缀与 peer 地址 → 校验。
    pub fn load(path: &Path, own_pubkey: Option<&NodePublicKey>) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Io {
            path: path.to_owned(),
            source,
        })?;
        let raw: RawConfig = toml::from_str(&text)?;
        let network_key =
            NetworkKey::from_base64(&raw.network.key).map_err(|_| ConfigError::BadNetworkKey)?;
        let prefix = NetworkPrefix::derive(&network_key);

        let mut peers = Vec::with_capacity(raw.peers.len());
        for rp in &raw.peers {
            let public_key = NodePublicKey::from_base64(&rp.public_key).map_err(|source| {
                ConfigError::BadKey {
                    name: rp.name.clone(),
                    source,
                }
            })?;
            let mut endpoints = Vec::with_capacity(rp.endpoints.len());
            for e in &rp.endpoints {
                match e.parse::<SocketAddr>() {
                    Ok(SocketAddr::V6(v6)) => endpoints.push(v6),
                    Ok(SocketAddr::V4(_)) => {
                        return Err(ConfigError::Ipv4Endpoint {
                            name: rp.name.clone(),
                            endpoint: e.clone(),
                        });
                    }
                    Err(_) => {
                        return Err(ConfigError::BadEndpoint {
                            name: rp.name.clone(),
                            endpoint: e.clone(),
                        });
                    }
                }
            }
            let addr = derive_node_addr(prefix, &public_key)?;
            peers.push(Peer {
                name: rp.name.clone(),
                public_key,
                endpoints,
                addr,
            });
        }

        // 公钥去重
        for i in 0..peers.len() {
            for j in (i + 1)..peers.len() {
                if peers[i].public_key == peers[j].public_key {
                    return Err(ConfigError::DuplicatePeer {
                        a: peers[i].name.clone(),
                        b: peers[j].name.clone(),
                    });
                }
            }
        }

        // subnet 碰撞（含自身）
        let mut all: Vec<(String, NodeAddr)> = peers
            .iter()
            .map(|p| (p.name.clone(), p.addr.clone()))
            .collect();
        if let Some(own) = own_pubkey {
            all.push(("<self>".into(), derive_node_addr(prefix, own)?));
        }
        check_subnet_collisions(&all)?;

        Ok(Config {
            network_name: raw.network.name,
            network_key,
            prefix,
            node: NodeSettings {
                key_file: raw.node.key_file,
                listen_port: raw.node.listen_port.unwrap_or(defaults::DEFAULT_PORT),
                mtu: raw.node.mtu.unwrap_or(defaults::DEFAULT_MTU),
                interface: raw
                    .node
                    .interface
                    .unwrap_or_else(|| defaults::DEFAULT_INTERFACE.into()),
            },
            peers,
        })
    }

    /// 生成 `hextet init` 的配置模板。
    pub fn render_template(
        name: &str,
        network_key: &NetworkKey,
        key_file: &Path,
        listen_port: u16,
    ) -> String {
        format!(
            r#"# hextet 节点配置（v1，静态模式）
# 文档：docs/guides/quickstart.md

[network]
name = "{name}"
# 网络密钥：同一网络的所有节点必须一致。妥善保管。
key = "{key}"

[node]
key_file = "{key_file}"
listen_port = {listen_port}
# mtu = 1400
# interface = "hextet0"

# 每个对端一个 [[peers]] 块：
# [[peers]]
# name = "nas"
# public_key = "<对方 hextet keygen 输出的公钥>"
# endpoints = ["[对方公网IPv6]:4193"]
"#,
            name = name,
            key = network_key.to_base64(),
            key_file = key_file.display(),
            listen_port = listen_port,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
[network]
name = "home"
key = "{KEY}"

[node]
key_file = "node.key"

[[peers]]
name = "nas"
public_key = "{PK}"
endpoints = ["[2001:db8::1]:4193"]
"#;

    fn sample_toml() -> (String, crate::network::NetworkKey) {
        let nk = crate::network::NetworkKey::generate();
        let pk = crate::identity::NodeIdentity::generate().public();
        let s = SAMPLE
            .replace("{KEY}", &nk.to_base64())
            .replace("{PK}", &pk.to_base64());
        (s, nk)
    }

    #[test]
    fn parse_defaults_and_derivation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hextet.toml");
        let (toml_text, nk) = sample_toml();
        std::fs::write(&path, toml_text).unwrap();
        let cfg = Config::load(&path, None).unwrap();
        assert_eq!(cfg.network_name, "home");
        assert_eq!(cfg.node.listen_port, crate::defaults::DEFAULT_PORT);
        assert_eq!(cfg.node.mtu, crate::defaults::DEFAULT_MTU);
        assert_eq!(cfg.node.interface, crate::defaults::DEFAULT_INTERFACE);
        assert_eq!(cfg.prefix, crate::network::NetworkPrefix::derive(&nk));
        assert_eq!(cfg.peers.len(), 1);
        // peer 地址已派生且在网络前缀内
        assert_eq!(
            cfg.peers[0].addr.address.octets()[..6],
            *cfg.prefix.as_bytes()
        );
    }

    #[test]
    fn reject_ipv4_endpoint() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hextet.toml");
        let (toml_text, _) = sample_toml();
        let bad = toml_text.replace("[2001:db8::1]:4193", "1.2.3.4:4193");
        std::fs::write(&path, bad).unwrap();
        let err = Config::load(&path, None).unwrap_err();
        assert!(matches!(err, ConfigError::Ipv4Endpoint { .. }));
    }

    #[test]
    fn reject_duplicate_peer_pubkey() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hextet.toml");
        // 显式两个 [[peers]] 块，不同 name，相同 public_key
        let nk = crate::network::NetworkKey::generate();
        let pk = crate::identity::NodeIdentity::generate().public();
        let explicit_toml = format!(
            r#"
[network]
name = "home"
key = "{KEY}"

[node]
key_file = "node.key"

[[peers]]
name = "nas"
public_key = "{PK}"
endpoints = ["[2001:db8::1]:4193"]

[[peers]]
name = "nas2"
public_key = "{PK}"
endpoints = ["[2001:db8::2]:4193"]
"#,
            KEY = nk.to_base64(),
            PK = pk.to_base64(),
        );
        std::fs::write(&path, explicit_toml).unwrap();
        let err = Config::load(&path, None).unwrap_err();
        assert!(matches!(err, ConfigError::DuplicatePeer { .. }));
    }

    #[test]
    fn template_roundtrips() {
        let nk = crate::network::NetworkKey::generate();
        let text = Config::render_template("home", &nk, std::path::Path::new("node.key"), 4193);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hextet.toml");
        std::fs::write(&path, text).unwrap();
        let cfg = Config::load(&path, None).unwrap();
        assert_eq!(cfg.network_name, "home");
        assert!(cfg.peers.is_empty());
    }
}
