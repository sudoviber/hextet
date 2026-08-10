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
    probe_port: Option<u16>,
    state_dir: Option<PathBuf>,
    lan_discovery: Option<bool>,
    lan_port: Option<u16>,
    relay: Option<bool>,
    relay_port: Option<u16>,
    #[serde(default)]
    relay_allow: Vec<String>,
}

#[derive(Deserialize)]
struct RawPeer {
    name: String,
    public_key: String,
    #[serde(default)]
    endpoints: Vec<String>,
    relay: Option<bool>,
    relay_port: Option<u16>,
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
    /// doctor 探针 UDP 端口。
    pub probe_port: u16,
    /// daemon 的端点缓存与状态文件目录。
    pub state_dir: PathBuf,
    /// 是否启用 LAN 组播发现（默认开）。
    pub lan_discovery: bool,
    /// LAN 组播公告的 UDP 端口。
    pub lan_port: u16,
    /// 本节点是否**提供**中继服务（默认关；spec D5 要求显式启用）。
    pub relay: bool,
    /// 提供中继服务时的控制端口。
    pub relay_port: u16,
    /// 允许使用本节点中继的公钥白名单；空 = 任何网络成员都可以。
    pub relay_allow: Vec<NodePublicKey>,
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
    /// 这个 peer 可以**当中继用**（它得开着 `[node] relay = true`）。
    pub relay: bool,
    /// 这个 peer 的中继控制端口。
    pub relay_port: u16,
}

impl Peer {
    /// 这个 peer 作为中继时的控制地址（`relay = false` 时为空）。
    ///
    /// 中继控制端口与 WireGuard 端口不同，所以取 `endpoints` 里的**地址**、
    /// 换上 `relay_port`。多个 endpoint 时全部返回，由调用方依次尝试。
    pub fn relay_control_endpoints(&self) -> Vec<SocketAddrV6> {
        if !self.relay {
            return Vec::new();
        }
        self.endpoints
            .iter()
            .map(|e| SocketAddrV6::new(*e.ip(), self.relay_port, 0, 0))
            .collect()
    }
}

/// 已加载并校验的配置。
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

// 手写 Debug：`NetworkKey` 是秘密（实现 Drop 时会 zeroize），刻意不实现 Debug；
// 此处打码输出，避免测试/日志路径意外泄露网络密钥。
impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("network_name", &self.network_name)
            .field("network_key", &"<redacted>")
            .field("prefix", &self.prefix)
            .field("node", &self.node)
            .field("peers", &self.peers)
            .finish()
    }
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
            let relay = rp.relay.unwrap_or(false);
            if relay && endpoints.is_empty() {
                // 中继地址未知等于没配：与其在运行时静默不可用，不如加载时就报错
                return Err(ConfigError::RelayWithoutEndpoint {
                    name: rp.name.clone(),
                });
            }
            peers.push(Peer {
                name: rp.name.clone(),
                public_key,
                endpoints,
                addr,
                relay,
                relay_port: rp.relay_port.unwrap_or(defaults::DEFAULT_RELAY_PORT),
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

        let mut relay_allow = Vec::with_capacity(raw.node.relay_allow.len());
        for key in &raw.node.relay_allow {
            relay_allow.push(NodePublicKey::from_base64(key).map_err(|source| {
                ConfigError::BadKey {
                    name: format!("relay_allow[{key}]"),
                    source,
                }
            })?);
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
                probe_port: raw.node.probe_port.unwrap_or(defaults::DEFAULT_PROBE_PORT),
                state_dir: raw
                    .node
                    .state_dir
                    .unwrap_or_else(|| PathBuf::from(defaults::DEFAULT_STATE_DIR)),
                lan_discovery: raw.node.lan_discovery.unwrap_or(true),
                lan_port: raw.node.lan_port.unwrap_or(defaults::DEFAULT_LAN_PORT),
                relay: raw.node.relay.unwrap_or(false),
                relay_port: raw.node.relay_port.unwrap_or(defaults::DEFAULT_RELAY_PORT),
                relay_allow,
            },
            peers,
        })
    }

    /// 生成 `hextet init` 的配置模板。
    ///
    /// `state_dir` 为 `Some` 时写成生效的配置项，为 `None` 时只留一行注释示例
    /// （运行时走 `defaults::DEFAULT_STATE_DIR`）。
    pub fn render_template(
        name: &str,
        network_key: &NetworkKey,
        key_file: &Path,
        listen_port: u16,
        state_dir: Option<&Path>,
    ) -> String {
        let state_dir_line = match state_dir {
            Some(dir) => format!("state_dir = \"{}\"", dir.display()),
            None => format!("# state_dir = \"{}\"", defaults::DEFAULT_STATE_DIR),
        };
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
# probe_port = {probe_port}
# lan_discovery = true   # 同 LAN 内自动发现同网节点（组播 {lan_group}，端口 {lan_port}）
# lan_port = {lan_port}
# relay = false        # 让本节点为网络里其他节点提供中继（默认关，见 docs/guides/relay.md）
# relay_port = {relay_port}
# relay_allow = []     # 只允许这些公钥用本节点中继；空 = 任何网络成员
{state_dir_line}

# 每个对端一个 [[peers]] 块：
# [[peers]]
# name = "nas"
# public_key = "<对方 hextet keygen 输出的公钥>"
# endpoints = ["[对方公网IPv6]:4193"]
# relay = true       # 这个 peer 可以当中继用（需要它自己开了 [node] relay）
"#,
            name = name,
            key = network_key.to_base64(),
            key_file = key_file.display(),
            listen_port = listen_port,
            probe_port = defaults::DEFAULT_PROBE_PORT,
            lan_group = defaults::LAN_MULTICAST_GROUP,
            lan_port = defaults::DEFAULT_LAN_PORT,
            relay_port = defaults::DEFAULT_RELAY_PORT,
            state_dir_line = state_dir_line,
        )
    }
}

/// 渲染一个可直接追加到 `hextet.toml` 末尾的 `[[peers]]` 块。
///
/// `hextet join` 与 `hextet peer add` 共用它。刻意做成"追加"而不是"重写整个配置"：
/// 用户配置里的注释、字段顺序、自己加的说明全部原样保留——配置文件是用户的，
/// 不是程序的。
///
/// 输出以换行开头、以换行结尾，因此无论原文件末尾有没有换行，拼接结果都是合法 TOML。
/// `endpoints` 为空时**不输出** `endpoints` 这一行（而不是写个空数组），让配置读起来
/// 就是"这个 peer 的地址还不知道，交给会合层去发现"。
pub fn render_peer_block(
    name: &str,
    public_key: &NodePublicKey,
    endpoints: &[SocketAddrV6],
) -> String {
    let mut out = format!(
        "\n[[peers]]\nname = {}\npublic_key = \"{}\"\n",
        toml_basic_string(name),
        public_key.to_base64(),
    );
    if !endpoints.is_empty() {
        let list: Vec<String> = endpoints.iter().map(|e| format!("\"{e}\"")).collect();
        out.push_str(&format!("endpoints = [{}]\n", list.join(", ")));
    }
    out
}

/// 把字符串渲染成 TOML 基本字符串（含两侧引号）。
///
/// peer name 来自命令行，可能含引号或反斜杠；不转义会产出解析不了的配置文件。
fn toml_basic_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{:04X}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// 读配置 → 解析 `key_file` 相对路径 → 载身份 → 带 own_pubkey 重载配置。
///
/// 配置里的 subnet id 碰撞检测需要先知道本节点公钥，而公钥又要从 `key_file`
/// 指向的身份文件读出——因此第一次加载不带 `own_pubkey`，仅用来拿到 `key_file`
/// 路径，载入身份后再重新加载一次配置。
///
/// `key_file` 是相对路径时，基准目录是**配置文件所在目录**（不是进程 cwd），
/// 这样 `hextet -c /etc/hextet/home.toml` 能找到 `/etc/hextet/node.key`。
pub fn load_config_and_identity(
    config_path: &Path,
) -> Result<(Config, crate::identity::NodeIdentity), ConfigError> {
    let cfg = Config::load(config_path, None)?;
    let key_path = if cfg.node.key_file.is_relative() {
        config_path
            .parent()
            .unwrap_or(Path::new("."))
            .join(&cfg.node.key_file)
    } else {
        cfg.node.key_file.clone()
    };
    let id =
        crate::identity::NodeIdentity::load(&key_path).map_err(|source| ConfigError::Identity {
            path: key_path.clone(),
            source,
        })?;
    let cfg = Config::load(config_path, Some(&id.public()))?;
    Ok((cfg, id))
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
        let err = Config::load(&path, None).err().unwrap();
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
        let err = Config::load(&path, None).err().unwrap();
        assert!(matches!(err, ConfigError::DuplicatePeer { .. }));
    }

    #[test]
    fn template_roundtrips() {
        let nk = crate::network::NetworkKey::generate();
        let text =
            Config::render_template("home", &nk, std::path::Path::new("node.key"), 4193, None);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hextet.toml");
        std::fs::write(&path, text).unwrap();
        let cfg = Config::load(&path, None).unwrap();
        assert_eq!(cfg.network_name, "home");
        assert!(cfg.peers.is_empty());
    }

    #[test]
    fn own_pubkey_no_collision_with_peers() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hextet.toml");
        let (toml_text, _) = sample_toml();
        std::fs::write(&path, toml_text).unwrap();

        // 生成与 peer 不同的公钥作为自身
        let own_pubkey = crate::identity::NodeIdentity::generate().public();
        let cfg = Config::load(&path, Some(&own_pubkey)).unwrap();
        assert_eq!(cfg.network_name, "home");
        assert_eq!(cfg.peers.len(), 1);
    }

    #[test]
    fn own_pubkey_collision_with_peer() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hextet.toml");
        // 构造配置，peer 与 own 使用相同公钥（必然碰撞）
        let nk = crate::network::NetworkKey::generate();
        let pk = crate::identity::NodeIdentity::generate().public();
        let toml_text = format!(
            r#"
[network]
name = "home"
key = "{KEY}"

[node]
key_file = "node.key"

[[peers]]
name = "peer1"
public_key = "{PK}"
endpoints = ["[2001:db8::1]:4193"]
"#,
            KEY = nk.to_base64(),
            PK = pk.to_base64(),
        );
        std::fs::write(&path, toml_text).unwrap();

        // 用相同公钥作为自身 → subnet id 碰撞
        let err = Config::load(&path, Some(&pk)).err().unwrap();
        assert!(matches!(
            err,
            ConfigError::Addr(crate::error::AddrError::SubnetCollision { .. })
        ));
    }

    #[test]
    fn new_fields_default_and_parse() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hextet.toml");
        let (toml_text, _) = sample_toml();
        std::fs::write(&path, &toml_text).unwrap();
        let cfg = Config::load(&path, None).unwrap();
        // 缺省值
        assert_eq!(cfg.node.probe_port, crate::defaults::DEFAULT_PROBE_PORT);
        assert!(cfg.node.lan_discovery, "LAN 发现默认开");
        assert_eq!(cfg.node.lan_port, crate::defaults::DEFAULT_LAN_PORT);
        assert_eq!(
            cfg.node.state_dir,
            std::path::PathBuf::from(crate::defaults::DEFAULT_STATE_DIR)
        );

        // 显式值
        let explicit = toml_text.replace(
            "key_file = \"node.key\"",
            "key_file = \"node.key\"\nprobe_port = 5000\nstate_dir = \"/tmp/hxt-state\"\nlan_discovery = false\nlan_port = 5195",
        );
        std::fs::write(&path, explicit).unwrap();
        let cfg = Config::load(&path, None).unwrap();
        assert_eq!(cfg.node.probe_port, 5000);
        assert_eq!(
            cfg.node.state_dir,
            std::path::PathBuf::from("/tmp/hxt-state")
        );
        assert!(!cfg.node.lan_discovery);
        assert_eq!(cfg.node.lan_port, 5195);
    }

    #[test]
    fn template_with_state_dir_roundtrips() {
        let nk = crate::network::NetworkKey::generate();
        let text = Config::render_template(
            "home",
            &nk,
            std::path::Path::new("node.key"),
            4193,
            Some(std::path::Path::new("/var/lib/hextet-test")),
        );
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hextet.toml");
        std::fs::write(&path, text).unwrap();
        let cfg = Config::load(&path, None).unwrap();
        assert_eq!(
            cfg.node.state_dir,
            std::path::PathBuf::from("/var/lib/hextet-test")
        );
    }

    /// 渲染的 peer 块拼到模板后必须仍是合法配置，且字段解析回原值。
    #[test]
    fn peer_block_appends_to_template_and_parses() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hextet.toml");
        let nk = crate::network::NetworkKey::generate();
        let pk = crate::identity::NodeIdentity::generate().public();
        let mut text =
            Config::render_template("home", &nk, std::path::Path::new("node.key"), 4193, None);
        text.push_str(&render_peer_block(
            "nas",
            &pk,
            &[
                "[2001:db8::1]:4193".parse().unwrap(),
                "[2001:db8:2::9]:4193".parse().unwrap(),
            ],
        ));
        std::fs::write(&path, &text).unwrap();

        let cfg = Config::load(&path, None).unwrap();
        assert_eq!(cfg.peers.len(), 1);
        assert_eq!(cfg.peers[0].name, "nas");
        assert_eq!(cfg.peers[0].public_key, pk);
        assert_eq!(
            cfg.peers[0].endpoints,
            vec![
                "[2001:db8::1]:4193".parse::<SocketAddrV6>().unwrap(),
                "[2001:db8:2::9]:4193".parse().unwrap()
            ]
        );
    }

    #[test]
    fn peer_block_omits_endpoints_line_when_empty() {
        let pk = crate::identity::NodeIdentity::generate().public();
        let block = render_peer_block("nas", &pk, &[]);
        assert!(!block.contains("endpoints"), "got {block}");
        assert!(block.starts_with("\n[[peers]]\n"));
        assert!(block.ends_with('\n'));
    }

    /// 追加两个块后仍能解析出两个 peer（peer add 会反复追加）。
    #[test]
    fn multiple_peer_blocks_append_cleanly() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hextet.toml");
        let nk = crate::network::NetworkKey::generate();
        let mut text =
            Config::render_template("home", &nk, std::path::Path::new("node.key"), 4193, None);
        for name in ["a", "b"] {
            let pk = crate::identity::NodeIdentity::generate().public();
            text.push_str(&render_peer_block(name, &pk, &[]));
        }
        std::fs::write(&path, &text).unwrap();
        let cfg = Config::load(&path, None).unwrap();
        assert_eq!(cfg.peers.len(), 2);
        assert_eq!(cfg.peers[0].name, "a");
        assert_eq!(cfg.peers[1].name, "b");
    }

    /// name 里的引号与反斜杠必须被转义（否则产出解析不了的配置）。
    #[test]
    fn peer_block_escapes_special_chars_in_name() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hextet.toml");
        let nk = crate::network::NetworkKey::generate();
        let pk = crate::identity::NodeIdentity::generate().public();
        let weird = "na\"s\\path\tx";
        let mut text =
            Config::render_template("home", &nk, std::path::Path::new("node.key"), 4193, None);
        text.push_str(&render_peer_block(weird, &pk, &[]));
        std::fs::write(&path, &text).unwrap();
        let cfg = Config::load(&path, None).unwrap();
        assert_eq!(cfg.peers[0].name, weird);
    }

    #[test]
    fn relay_settings_default_and_parse() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hextet.toml");
        let (toml_text, _) = sample_toml();
        std::fs::write(&path, &toml_text).unwrap();
        let cfg = Config::load(&path, None).unwrap();
        assert!(!cfg.node.relay, "中继默认必须是关的（spec D5）");
        assert_eq!(cfg.node.relay_port, crate::defaults::DEFAULT_RELAY_PORT);
        assert!(cfg.node.relay_allow.is_empty());
        assert!(!cfg.peers[0].relay);
        assert!(cfg.peers[0].relay_control_endpoints().is_empty());

        let allow = crate::identity::NodeIdentity::generate().public();
        let explicit = toml_text
            .replace(
                "key_file = \"node.key\"",
                &format!(
                    "key_file = \"node.key\"\nrelay = true\nrelay_port = 5196\nrelay_allow = [\"{}\"]",
                    allow.to_base64()
                ),
            )
            .replace(
                "endpoints = [\"[2001:db8::1]:4193\"]",
                "endpoints = [\"[2001:db8::1]:4193\"]\nrelay = true",
            );
        std::fs::write(&path, explicit).unwrap();
        let cfg = Config::load(&path, None).unwrap();
        assert!(cfg.node.relay);
        assert_eq!(cfg.node.relay_port, 5196);
        assert_eq!(cfg.node.relay_allow, vec![allow]);
        assert!(cfg.peers[0].relay);
        // 中继控制地址 = endpoint 的地址 + relay_port（默认 4196，与 WG 端口不同）
        assert_eq!(
            cfg.peers[0].relay_control_endpoints(),
            vec!["[2001:db8::1]:4196".parse::<SocketAddrV6>().unwrap()]
        );
    }

    #[test]
    fn relay_peer_without_endpoints_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hextet.toml");
        let (toml_text, _) = sample_toml();
        let bad = toml_text.replace("endpoints = [\"[2001:db8::1]:4193\"]", "relay = true");
        std::fs::write(&path, bad).unwrap();
        let err = Config::load(&path, None).unwrap_err();
        assert!(
            matches!(err, ConfigError::RelayWithoutEndpoint { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn bad_relay_allow_key_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hextet.toml");
        let (toml_text, _) = sample_toml();
        let bad = toml_text.replace(
            "key_file = \"node.key\"",
            "key_file = \"node.key\"\nrelay_allow = [\"not-base64!!\"]",
        );
        std::fs::write(&path, bad).unwrap();
        assert!(matches!(
            Config::load(&path, None).unwrap_err(),
            ConfigError::BadKey { .. }
        ));
    }

    /// 原文件里的注释在追加后仍存在——这是"追加而非重写"的证据。
    #[test]
    fn peer_block_preserves_existing_comments() {
        let nk = crate::network::NetworkKey::generate();
        let pk = crate::identity::NodeIdentity::generate().public();
        let base =
            Config::render_template("home", &nk, std::path::Path::new("node.key"), 4193, None);
        let combined = format!("{base}{}", render_peer_block("nas", &pk, &[]));
        assert!(combined.contains("# mtu = 1400"));
    }

    #[test]
    fn load_config_and_identity_reads_relative_key_file() {
        let dir = tempfile::tempdir().unwrap();
        let id = crate::identity::NodeIdentity::generate();
        id.save(&dir.path().join("node.key")).unwrap();
        let nk = crate::network::NetworkKey::generate();
        let text =
            Config::render_template("home", &nk, std::path::Path::new("node.key"), 4193, None);
        let path = dir.path().join("hextet.toml");
        std::fs::write(&path, text).unwrap();

        let (cfg, loaded) = load_config_and_identity(&path).unwrap();
        assert_eq!(cfg.network_name, "home");
        assert_eq!(loaded.public(), id.public());
    }

    #[test]
    fn load_config_and_identity_reports_missing_key_file() {
        let dir = tempfile::tempdir().unwrap();
        let nk = crate::network::NetworkKey::generate();
        let text = Config::render_template(
            "home",
            &nk,
            std::path::Path::new("does-not-exist.key"),
            4193,
            None,
        );
        let path = dir.path().join("hextet.toml");
        std::fs::write(&path, text).unwrap();

        let err = load_config_and_identity(&path).unwrap_err();
        assert!(matches!(err, ConfigError::Identity { .. }), "got {err:?}");
    }
}
