//! 节点配置：TOML 解析、默认值、派生与校验。

use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::addr::{NodeAddr, check_subnet_collisions, derive_node_addr};
use crate::defaults;
use crate::error::ConfigError;
use crate::identity::NodePublicKey;
use crate::network::{NetworkKey, NetworkPrefix};
use crate::route::Ipv6Route;
use crate::secret::SecretString;

/// 自托管 DDNS 的更新提供方（会合兜底链第 ⑥ 层，见 ADR-0010）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DdnsProvider {
    /// 把 `{fqdn, value}` POST 到用户自己的 webhook URL（最自托管，零注册商锁定）。
    Webhook,
    /// 直接调 Cloudflare v4 API 更新 TXT 记录。
    Cloudflare,
}

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
    gossip_port: Option<u16>,
    #[serde(default)]
    gossip: Option<bool>,
    dht: Option<bool>,
    #[serde(default)]
    http_addr: Option<Ipv6Addr>,
    #[serde(default)]
    http_port: Option<u16>,
    #[serde(default)]
    web_dir: Option<PathBuf>,
    ddns: Option<bool>,
    #[serde(default)]
    ddns_fqdn: Option<String>,
    #[serde(default)]
    ddns_provider: Option<DdnsProvider>,
    #[serde(default)]
    ddns_webhook_url: Option<String>,
    #[serde(default)]
    ddns_secret: Option<SecretString>,
    #[serde(default)]
    ddns_zone: Option<String>,
    #[serde(default)]
    ddns_resolver: Option<SocketAddr>,
}

#[derive(Deserialize)]
struct RawPeer {
    name: String,
    public_key: String,
    #[serde(default)]
    endpoints: Vec<String>,
    relay: Option<bool>,
    relay_port: Option<u16>,
    #[serde(default)]
    routes: Vec<String>,
    #[serde(default)]
    ddns: Option<String>,
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
    /// 隧道内 gossip UDP 端口。
    pub gossip_port: u16,
    /// 是否启用隧道内 gossip（端点广播 + peer 转介 + 成员，默认开）。
    ///
    /// 关掉它可以隔离会合路径（netns E2E 用它把 DHT/DDNS 会合单独测出来，避免 gossip
    /// 一旦随隧道建立就立刻转介、污染 `endpoint_source` 断言）；生产按需关闭。
    pub gossip: bool,
    /// 是否启用 DHT 会合（默认开；会合兜底链第 ⑤ 层，控制面弱依赖 IPv4 出站 UDP）。
    pub dht: bool,
    /// HTTP 状态服务（`/healthz` + `/api/status`）监听地址（默认 `None` = 关闭）。
    ///
    /// 与 [`Self::http_port`] 成对出现：要么都设、要么都不设。hextet 是 IPv6-only 的，
    /// 因此这里直接是 [`Ipv6Addr`]，不存在 IPv4 泄漏路径。
    pub http_addr: Option<Ipv6Addr>,
    /// HTTP 状态服务监听端口（默认 `None` = 关闭）。
    pub http_port: Option<u16>,
    /// HTTP 状态服务要托管的静态前端目录（`web/` 的 React 构建产物，默认 `None` = 不托管）。
    ///
    /// 与 [`Self::http_addr`]/[`Self::http_port`] 不同，本项**不**要求成对出现：
    /// 只设 `web_dir` 而不设 http 地址/端口时，状态服务本身仍关着，故 `web_dir`
    /// 不生效；只有 http 服务启用时才被 `hextet_engine::http` 用作静态文件回退。
    pub web_dir: Option<PathBuf>,
    /// 是否启用自托管 DDNS 会合（默认关；会合兜底链第 ⑥ 层）。
    pub ddns: bool,
    /// 本节点要发布会合记录的 FQDN（`ddns = true` 时必填）。
    pub ddns_fqdn: Option<String>,
    /// DDNS 更新提供方（`webhook` / `cloudflare`）。
    pub ddns_provider: DdnsProvider,
    /// `webhook` 提供方的 URL（`ddns_provider = "webhook"` 时必填）。
    pub ddns_webhook_url: Option<String>,
    /// `webhook` 的 Bearer token 或 `cloudflare` 的 API token（秘密，Debug 打码）。
    pub ddns_secret: Option<SecretString>,
    /// `cloudflare` 提供方要更新的 zone 名（`ddns_provider = "cloudflare"` 时必填）。
    pub ddns_zone: Option<String>,
    /// 覆盖系统 DNS 配置、把 DDNS 查询指向的解析器（`ip:port`；可选）。
    ///
    /// 生产可用它固定解析器；netns E2E 用它把查询指向本地 DDNS mock（`hextet ddns node`）。
    pub ddns_resolver: Option<SocketAddr>,
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
    /// 这个 peer 通告的、在其背后可达的子网路由（site-to-site）。
    pub routes: Vec<Ipv6Route>,
    /// 这个 peer 的 DDNS 会合 FQDN（可选；对端靠它经 DNS 发现本 peer 的当前地址）。
    pub ddns: Option<String>,
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
        // HTTP 状态服务的地址/端口必须成对出现：只设一个等于半开配置，与其在运行时
        // 静默不可用，不如加载时就报错（both-or-neither）。
        if raw.node.http_addr.is_some() != raw.node.http_port.is_some() {
            return Err(ConfigError::HttpAddrPortMismatch);
        }
        // DDNS 会合（兜底链第 ⑥ 层）：ddns = true 时必须有 ddns_fqdn；webhook 提供方
        // 必须有 URL；cloudflare 提供方必须有 token + zone。与其运行时静默不可用，
        // 不如加载时就报错。
        let ddns = raw.node.ddns.unwrap_or(false);
        let ddns_provider = raw.node.ddns_provider.unwrap_or(DdnsProvider::Webhook);
        if ddns && raw.node.ddns_fqdn.as_deref().is_none_or(str::is_empty) {
            return Err(ConfigError::DdnsMissingFqdn);
        }
        if ddns
            && matches!(ddns_provider, DdnsProvider::Webhook)
            && raw
                .node
                .ddns_webhook_url
                .as_deref()
                .is_none_or(str::is_empty)
        {
            return Err(ConfigError::DdnsMissingWebhookUrl);
        }
        if ddns
            && matches!(ddns_provider, DdnsProvider::Cloudflare)
            && (raw.node.ddns_secret.is_none()
                || raw.node.ddns_zone.as_deref().is_none_or(str::is_empty))
        {
            return Err(ConfigError::DdnsMissingCloudflare);
        }
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
            let mut routes = Vec::with_capacity(rp.routes.len());
            for r in &rp.routes {
                let route = r
                    .parse::<Ipv6Route>()
                    .map_err(|source| ConfigError::BadRoute {
                        name: rp.name.clone(),
                        route: r.clone(),
                        source,
                    })?;
                if routes.contains(&route) {
                    return Err(ConfigError::DuplicateRoute {
                        name: rp.name.clone(),
                        route: r.clone(),
                    });
                }
                routes.push(route);
            }
            // peer 的 DDNS 会合域名：trim 后必须是非空、无空白、含 `.`、首尾非 `.` 的
            // 合法 FQDN。它是对端按名解析的入口，坏掉等于这一路会合静默失效。
            let ddns = match rp.ddns.as_deref().map(str::trim) {
                None | Some("") => None,
                Some(fqdn) => {
                    if fqdn.contains(char::is_whitespace)
                        || !fqdn.contains('.')
                        || fqdn.starts_with('.')
                        || fqdn.ends_with('.')
                    {
                        return Err(ConfigError::BadDdnsFqdn {
                            name: rp.name.clone(),
                        });
                    }
                    Some(fqdn.to_owned())
                }
            };
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
                routes,
                ddns,
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
        let own = match own_pubkey {
            Some(pk) => Some(derive_node_addr(prefix, pk)?),
            None => None,
        };
        let mut all: Vec<(String, NodeAddr)> = peers
            .iter()
            .map(|p| (p.name.clone(), p.addr.clone()))
            .collect();
        if let Some(o) = &own {
            all.push(("<self>".into(), o.clone()));
        }
        check_subnet_collisions(&all)?;

        // 通告路由校验：不与 overlay /48 或本节点 /64 site 冲突，peer 之间不重叠。
        // overlay /48 是 Ipv6Route 规范化后的网络地址，本节点 site 同理，两者都
        // 一定是合法路由，因此这里 unwrap 是安全的。
        let overlay = Ipv6Route::new(prefix.network(), NetworkPrefix::PREFIX_LEN)
            .expect("overlay /48 is a valid route");
        let own_site = own
            .as_ref()
            .map(|o| Ipv6Route::new(o.site, 64).expect("site /64 is a valid route"));
        for p in &peers {
            for r in &p.routes {
                if r.overlaps(&overlay) {
                    return Err(ConfigError::RouteConflict {
                        name: p.name.clone(),
                        route: r.to_string(),
                    });
                }
                if let Some(site) = &own_site
                    && r.overlaps(site)
                {
                    return Err(ConfigError::RouteConflict {
                        name: p.name.clone(),
                        route: r.to_string(),
                    });
                }
            }
        }
        for i in 0..peers.len() {
            for j in (i + 1)..peers.len() {
                for ra in &peers[i].routes {
                    for rb in &peers[j].routes {
                        if ra.overlaps(rb) {
                            return Err(ConfigError::RouteOverlap {
                                a: peers[i].name.clone(),
                                b: peers[j].name.clone(),
                                route_a: ra.to_string(),
                                route_b: rb.to_string(),
                            });
                        }
                    }
                }
            }
        }

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
                gossip_port: raw
                    .node
                    .gossip_port
                    .unwrap_or(defaults::DEFAULT_GOSSIP_PORT),
                gossip: raw.node.gossip.unwrap_or(true),
                dht: raw.node.dht.unwrap_or(true),
                http_addr: raw.node.http_addr,
                http_port: raw.node.http_port,
                web_dir: raw.node.web_dir,
                ddns,
                ddns_fqdn: raw.node.ddns_fqdn,
                ddns_provider,
                ddns_webhook_url: raw.node.ddns_webhook_url,
                ddns_secret: raw.node.ddns_secret,
                ddns_zone: raw.node.ddns_zone,
                ddns_resolver: raw.node.ddns_resolver,
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
# gossip_port = {gossip_port}   # 隧道内 gossip 端口（见 docs/protocol/gossip.md）
# gossip = true        # 隧道内 gossip（端点广播 + peer 转介 + 成员；默认开）
# dht = true           # DHT 会合（默认开；控制面弱依赖 IPv4 出站，见 docs/protocol/dht-record.md）
# http_addr = "::1"    # HTTP 状态服务监听地址（与 http_port 成对出现；默认关）
# http_port = 8080     # HTTP 状态服务端口（/healthz + /api/status）
# web_dir = "/var/lib/hextet/web"   # 状态服务托管的静态前端目录（web/ 的 React 构建产物）
# ddns = false        # 自托管 DDNS 会合（默认关；见 docs/guides/ddns.md）
# ddns_fqdn = "home.example.com"   # 本节点要发布会合记录的域名（ddns = true 时必填）
# ddns_provider = "webhook"        # "webhook" 或 "cloudflare"
# ddns_webhook_url = "https://ddns.example.com/update"  # webhook 提供方必填
# ddns_secret = "..." # webhook 的 Bearer token 或 cloudflare 的 API token（秘密，勿提交）
# ddns_zone = "example.com"        # cloudflare 提供方必填
# ddns_resolver = "1.1.1.1:53"     # 覆盖系统 DNS、把 DDNS 查询指向的解析器（可选）
{state_dir_line}

# 每个对端一个 [[peers]] 块：
# [[peers]]
# name = "nas"
# public_key = "<对方 hextet keygen 输出的公钥>"
# endpoints = ["[对方公网IPv6]:4193"]
# relay = true       # 这个 peer 可以当中继用（需要它自己开了 [node] relay）
# ddns = "nas.example.com"   # 按域名解析这个 peer（对端须开启 [node] ddns 发布）
"#,
            name = name,
            key = network_key.to_base64(),
            key_file = key_file.display(),
            listen_port = listen_port,
            probe_port = defaults::DEFAULT_PROBE_PORT,
            lan_group = defaults::LAN_MULTICAST_GROUP,
            lan_port = defaults::DEFAULT_LAN_PORT,
            relay_port = defaults::DEFAULT_RELAY_PORT,
            gossip_port = defaults::DEFAULT_GOSSIP_PORT,
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
/// 就是"这个 peer 的地址还不知道，交给会合层去发现"。`routes` 同理。
pub fn render_peer_block(
    name: &str,
    public_key: &NodePublicKey,
    endpoints: &[SocketAddrV6],
    routes: &[Ipv6Route],
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
    if !routes.is_empty() {
        let list: Vec<String> = routes.iter().map(|r| format!("\"{r}\"")).collect();
        out.push_str(&format!("routes = [{}]\n", list.join(", ")));
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
        assert_eq!(cfg.node.gossip_port, crate::defaults::DEFAULT_GOSSIP_PORT);
        assert!(cfg.node.dht, "DHT 会合默认开");

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
            &[],
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
        let block = render_peer_block("nas", &pk, &[], &[]);
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
            text.push_str(&render_peer_block(name, &pk, &[], &[]));
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
        text.push_str(&render_peer_block(weird, &pk, &[], &[]));
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
        let combined = format!("{base}{}", render_peer_block("nas", &pk, &[], &[]));
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

    #[test]
    fn http_addr_port_must_be_both_or_neither() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hextet.toml");
        let (toml_text, _) = sample_toml();

        // 都没设 → 都为 None（HTTP 状态服务默认关）
        std::fs::write(&path, &toml_text).unwrap();
        let cfg = Config::load(&path, None).unwrap();
        assert_eq!(cfg.node.http_addr, None);
        assert_eq!(cfg.node.http_port, None);

        // 成对设置 → 都解析出值
        let both = toml_text.replace(
            "key_file = \"node.key\"",
            "key_file = \"node.key\"\nhttp_addr = \"::1\"\nhttp_port = 8080",
        );
        std::fs::write(&path, both).unwrap();
        let cfg = Config::load(&path, None).unwrap();
        assert_eq!(cfg.node.http_addr, Some("::1".parse().unwrap()));
        assert_eq!(cfg.node.http_port, Some(8080));

        // 只设 http_port → 报错（both-or-neither）
        let port_only = toml_text.replace(
            "key_file = \"node.key\"",
            "key_file = \"node.key\"\nhttp_port = 8080",
        );
        std::fs::write(&path, port_only).unwrap();
        assert!(matches!(
            Config::load(&path, None).unwrap_err(),
            ConfigError::HttpAddrPortMismatch
        ));

        // 只设 http_addr → 报错（both-or-neither）
        let addr_only = toml_text.replace(
            "key_file = \"node.key\"",
            "key_file = \"node.key\"\nhttp_addr = \"::1\"",
        );
        std::fs::write(&path, addr_only).unwrap();
        assert!(matches!(
            Config::load(&path, None).unwrap_err(),
            ConfigError::HttpAddrPortMismatch
        ));
    }

    // ---- site-to-site 子网路由 ----

    fn with_route(toml_text: &str, route: &str) -> String {
        toml_text.replace(
            "endpoints = [\"[2001:db8::1]:4193\"]",
            &format!("endpoints = [\"[2001:db8::1]:4193\"]\nroutes = [\"{route}\"]"),
        )
    }

    #[test]
    fn routes_default_empty_and_parse() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hextet.toml");
        let (toml_text, _) = sample_toml();
        std::fs::write(&path, &toml_text).unwrap();
        let cfg = Config::load(&path, None).unwrap();
        assert!(cfg.peers[0].routes.is_empty(), "缺省应是空");

        let explicit = with_route(&toml_text, "2001:db8:dead::/64");
        std::fs::write(&path, explicit).unwrap();
        let cfg = Config::load(&path, None).unwrap();
        assert_eq!(cfg.peers[0].routes.len(), 1);
        assert_eq!(cfg.peers[0].routes[0].to_string(), "2001:db8:dead::/64");
    }

    #[test]
    fn render_peer_block_roundtrips_routes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hextet.toml");
        let nk = crate::network::NetworkKey::generate();
        let pk = crate::identity::NodeIdentity::generate().public();
        let mut text =
            Config::render_template("home", &nk, std::path::Path::new("node.key"), 4193, None);
        let routes: Vec<Ipv6Route> = ["2001:db8:dead::/64", "2001:db8:beef::/48"]
            .iter()
            .map(|s| s.parse().unwrap())
            .collect();
        text.push_str(&render_peer_block("nas", &pk, &[], &routes));
        std::fs::write(&path, &text).unwrap();
        let cfg = Config::load(&path, None).unwrap();
        assert_eq!(cfg.peers[0].routes, routes);
    }

    #[test]
    fn peer_block_omits_routes_line_when_empty() {
        let pk = crate::identity::NodeIdentity::generate().public();
        let block = render_peer_block("nas", &pk, &[], &[]);
        assert!(!block.contains("routes"), "got {block}");
    }

    #[test]
    fn reject_ipv4_route() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hextet.toml");
        let (toml_text, _) = sample_toml();
        let bad = with_route(&toml_text, "1.2.3.0/24");
        std::fs::write(&path, bad).unwrap();
        let err = Config::load(&path, None).unwrap_err();
        assert!(matches!(err, ConfigError::BadRoute { .. }), "got {err:?}");
    }

    #[test]
    fn reject_host_bits_set_route() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hextet.toml");
        let (toml_text, _) = sample_toml();
        let bad = with_route(&toml_text, "2001:db8:dead::1/64");
        std::fs::write(&path, bad).unwrap();
        let err = Config::load(&path, None).unwrap_err();
        assert!(matches!(err, ConfigError::BadRoute { .. }), "got {err:?}");
    }

    #[test]
    fn reject_duplicate_route_within_peer() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hextet.toml");
        let (toml_text, _) = sample_toml();
        let bad = toml_text.replace(
            "endpoints = [\"[2001:db8::1]:4193\"]",
            "endpoints = [\"[2001:db8::1]:4193\"]\nroutes = [\"2001:db8:dead::/64\", \"2001:db8:dead::/64\"]",
        );
        std::fs::write(&path, bad).unwrap();
        let err = Config::load(&path, None).unwrap_err();
        assert!(
            matches!(err, ConfigError::DuplicateRoute { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn reject_route_overlapping_overlay_48() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hextet.toml");
        let (toml_text, nk) = sample_toml();
        // 从 overlay /48 里摘一个 /64：等于把别人的 site 又当成自己背后的子网，冲突
        let prefix = crate::network::NetworkPrefix::derive(&nk);
        let mut octets = prefix.network().octets();
        octets[6] = 0x00;
        octets[7] = 0x01;
        let inside = format!("{}/64", std::net::Ipv6Addr::from(octets));
        let bad = with_route(&toml_text, &inside);
        std::fs::write(&path, bad).unwrap();
        let err = Config::load(&path, None).unwrap_err();
        assert!(
            matches!(err, ConfigError::RouteConflict { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn reject_route_overlapping_own_site() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hextet.toml");
        let nk = crate::network::NetworkKey::generate();
        let prefix = crate::network::NetworkPrefix::derive(&nk);
        let own = crate::identity::NodeIdentity::generate();
        let own_addr = derive_node_addr(prefix, &own.public()).unwrap();
        let peer = crate::identity::NodeIdentity::generate();
        let toml_text = format!(
            r#"
[network]
name = "home"
key = "{KEY}"

[node]
key_file = "node.key"

[[peers]]
name = "nas"
public_key = "{PK}"
routes = ["{SITE}/64"]
"#,
            KEY = nk.to_base64(),
            PK = peer.public().to_base64(),
            SITE = own_addr.site,
        );
        std::fs::write(&path, toml_text).unwrap();
        let err = Config::load(&path, Some(&own.public())).unwrap_err();
        assert!(
            matches!(err, ConfigError::RouteConflict { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn reject_route_overlap_between_peers() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hextet.toml");
        let nk = crate::network::NetworkKey::generate();
        let a = crate::identity::NodeIdentity::generate();
        let b = crate::identity::NodeIdentity::generate();
        let toml_text = format!(
            r#"
[network]
name = "home"
key = "{KEY}"

[node]
key_file = "node.key"

[[peers]]
name = "a"
public_key = "{PA}"
routes = ["2001:db8:dead::/48"]

[[peers]]
name = "b"
public_key = "{PB}"
routes = ["2001:db8:dead::/64"]
"#,
            KEY = nk.to_base64(),
            PA = a.public().to_base64(),
            PB = b.public().to_base64(),
        );
        std::fs::write(&path, toml_text).unwrap();
        let err = Config::load(&path, None).unwrap_err();
        assert!(
            matches!(err, ConfigError::RouteOverlap { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn ddns_defaults_off_and_peer_ddns_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hextet.toml");
        let (toml_text, _) = sample_toml();
        std::fs::write(&path, toml_text).unwrap();
        let cfg = Config::load(&path, None).unwrap();
        assert!(!cfg.node.ddns, "DDNS 默认必须关（与 DHT/中继同纪律）");
        assert!(cfg.node.ddns_fqdn.is_none());
        assert!(matches!(cfg.node.ddns_provider, DdnsProvider::Webhook));
        assert!(cfg.peers[0].ddns.is_none());
    }

    #[test]
    fn ddns_webhook_roundtrips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hextet.toml");
        let nk = crate::network::NetworkKey::generate();
        let pk = crate::identity::NodeIdentity::generate().public();
        let toml_text = format!(
            r#"
[network]
name = "home"
key = "{KEY}"

[node]
key_file = "node.key"
ddns = true
ddns_fqdn = "home.example.com"
ddns_provider = "webhook"
ddns_webhook_url = "https://ddns.example.com/update"
ddns_secret = "wh-tok"

[[peers]]
name = "nas"
public_key = "{PK}"
ddns = "nas.example.com"
"#,
            KEY = nk.to_base64(),
            PK = pk.to_base64(),
        );
        std::fs::write(&path, toml_text).unwrap();
        let cfg = Config::load(&path, None).unwrap();
        assert!(cfg.node.ddns);
        assert_eq!(cfg.node.ddns_fqdn.as_deref(), Some("home.example.com"));
        assert!(matches!(cfg.node.ddns_provider, DdnsProvider::Webhook));
        assert_eq!(
            cfg.node.ddns_webhook_url.as_deref(),
            Some("https://ddns.example.com/update")
        );
        assert_eq!(
            cfg.node.ddns_secret.as_ref().map(|s| s.expose()),
            Some("wh-tok")
        );
        assert_eq!(cfg.peers[0].ddns.as_deref(), Some("nas.example.com"));
        // 秘密绝不外泄进 Debug
        assert!(!format!("{cfg:?}").contains("wh-tok"));
    }

    #[test]
    fn ddns_cloudflare_requires_secret_and_zone() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hextet.toml");
        let nk = crate::network::NetworkKey::generate();
        let toml_text = format!(
            r#"
[network]
name = "home"
key = "{KEY}"

[node]
key_file = "node.key"
ddns = true
ddns_fqdn = "home.example.com"
ddns_provider = "cloudflare"
"#,
            KEY = nk.to_base64(),
        );
        std::fs::write(&path, toml_text).unwrap();
        let err = Config::load(&path, None).unwrap_err();
        assert!(
            matches!(err, ConfigError::DdnsMissingCloudflare),
            "got {err:?}"
        );
    }

    #[test]
    fn ddns_true_requires_fqdn() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hextet.toml");
        let (toml_text, _) = sample_toml();
        let bad = toml_text.replace(
            "key_file = \"node.key\"",
            "key_file = \"node.key\"\nddns = true",
        );
        std::fs::write(&path, bad).unwrap();
        let err = Config::load(&path, None).unwrap_err();
        assert!(matches!(err, ConfigError::DdnsMissingFqdn), "got {err:?}");
    }

    #[test]
    fn peer_ddns_rejects_bad_fqdn() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hextet.toml");
        let (toml_text, _) = sample_toml();
        let bad = toml_text.replace(
            "endpoints = [\"[2001:db8::1]:4193\"]",
            "endpoints = [\"[2001:db8::1]:4193\"]\nddns = \"not a fqdn\"",
        );
        std::fs::write(&path, bad).unwrap();
        let err = Config::load(&path, None).unwrap_err();
        assert!(
            matches!(err, ConfigError::BadDdnsFqdn { .. }),
            "got {err:?}"
        );
    }
}
