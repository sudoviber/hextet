//! 自托管 DDNS 会合（会合兜底链第 ⑥ 层）——daemon 侧的发布/查询接线。
//!
//! 纯逻辑的 URL 模板渲染 + AAAA 解析在 `hextet-discovery::ddns`；本模块只做**调度**：
//! 周期把本机地址经「更新 URL」发到用户自己的注册商、周期解析各 peer 的 DDNS 域名
//! （喂给 `discovered` 通道，`Source::Ddns`）。
//!
//! 与 LAN 组播、gossip、DHT 一样：DDNS 是**尽力而为**的一路会合，构建失败（例如
//! `update_url` 缺占位符）只降级为「这一路不可用」，绝不阻断 daemon 启动。
//!
//! 与 DHT 的一个刻意差异：**没有 `DdnsControl` 运行时更新通道**。DDNS 的查询目标
//! 来自 `[[peers]] ddns`（静态配置），而 gossip 准入的成员没有 DDNS 域名可查——
//! 配置不热加载，peer 的 DDNS 域名在进程生命周期内不变，因此不存在「运行时替换
//! 查询目标」的事件源。

use std::net::SocketAddrV6;
use std::time::Duration;

use hextet_core::config::Peer;
use hextet_discovery::ddns::{DdnsClient, HttpDdnsTransport, render_update_url};
use hextet_discovery::record::usable_endpoints;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::candidates::{DiscoveredEndpoints, Source};

/// 本机地址的发布周期（~10min：多数 DDNS 服务端的 TTL 在 5–60min 之间，10min 是
/// 「地址变化后足够快收敛」与「不刷爆注册商限流」的折中）。
pub const PUBLISH_INTERVAL: Duration = Duration::from_secs(10 * 60);
/// 解析各 peer DDNS 域名的周期（60s：比 DHT 的 30s 宽松，尊重 DNS TTL 与系统解析器
/// 的缓存，也避免对注册商的权威服务器形成高频轮询）。
pub const LOOKUP_INTERVAL: Duration = Duration::from_secs(60);

/// 一个经 DDNS 查询的 peer：`key_b64` 是 `discovered` 通道里用来定位 peer 的键，
/// `host` 是该 peer 的 DDNS 域名。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DdnsPeer {
    /// peer 的 ed25519 公钥 base64。
    pub key_b64: String,
    /// 该 peer 的自托管 DDNS 域名（`[[peers]] ddns`）。
    pub host: String,
}

/// DDNS 会合的运行参数。
#[derive(Debug)]
pub struct DdnsConfig {
    /// 更新 URL 模板（`{address}` 占位符）。
    pub update_url: String,
    /// 查询到的 AAAA 地址要配的固定端口（DDNS 只承载地址，见 ADR-0011）。
    pub port: u16,
    /// 枚举本机地址时要排除的接口（hextet0 自己）。
    pub exclude_interface: String,
    /// 要查询 DDNS 域名的 peer 列表。
    pub peers: Vec<DdnsPeer>,
}

/// DDNS 任务 → daemon 的派生事件。
#[derive(Debug, Clone)]
pub enum DdnsEvent {
    /// 某 peer 的 DDNS 解析结果更新（来源为 [`Source::Ddns`]）。
    Discovered(DiscoveredEndpoints),
}

/// 从配置的 peer 列表挑出配了 DDNS 域名的（供 daemon 构造 [`DdnsConfig`]）。
///
/// 纯逻辑，可直接单测；`ddns` 为 `None` 的 peer 不进入 DDNS 查询目标。
pub fn ddns_peers(peers: &[Peer]) -> Vec<DdnsPeer> {
    peers
        .iter()
        .filter_map(|p| {
            p.ddns.as_ref().map(|host| DdnsPeer {
                key_b64: p.public_key.to_base64(),
                host: host.clone(),
            })
        })
        .collect()
}

/// 常驻 DDNS 会合：周期发布 + 周期查询。
///
/// 构建失败（`update_url` 缺 `{address}` 占位符）时返回 `Err`，调用方据此 warn 并跳过
/// 这一路。正常返回只发生在 `tx` 的接收端被丢弃、或 `kick_rx` 关闭时。
pub async fn serve(
    cfg: DdnsConfig,
    tx: mpsc::Sender<DdnsEvent>,
    mut kick_rx: mpsc::Receiver<()>,
) -> std::io::Result<()> {
    // 启动前校验模板：缺占位符立即失败，不等到第一次发布才发现。
    render_update_url(&cfg.update_url, std::net::Ipv6Addr::LOCALHOST)
        .map_err(std::io::Error::other)?;
    let client = DdnsClient::new(cfg.update_url.clone(), Box::new(HttpDdnsTransport));
    info!(peers = cfg.peers.len(), "DDNS 会合已启动");

    let mut publish_tick = tokio::time::interval(PUBLISH_INTERVAL);
    let mut lookup_tick = tokio::time::interval(LOOKUP_INTERVAL);

    loop {
        tokio::select! {
            // 两个 interval 的第一次 tick 都立即触发：启动即发布、即查询
            _ = publish_tick.tick() => {
                publish_own(&client, &cfg).await;
            }
            _ = lookup_tick.tick() => {
                for peer in &cfg.peers {
                    let endpoints = client.lookup(&peer.host, cfg.port);
                    if endpoints.is_empty() {
                        debug!(peer = %peer.host, "DDNS 解析无可用地址");
                        continue;
                    }
                    debug!(peer = %peer.host, endpoints = endpoints.len(), "DDNS 解析到了会合地址");
                    if tx.send(DdnsEvent::Discovered(DiscoveredEndpoints {
                        source: Source::Ddns,
                        peer_key: peer.key_b64.clone(),
                        endpoints,
                    })).await.is_err() {
                        return Ok(());
                    }
                }
            }
            kicked = kick_rx.recv() => {
                if kicked.is_none() {
                    return Ok(());
                }
                debug!("本机地址变化：立刻重发 DDNS 更新");
                publish_own(&client, &cfg).await;
            }
        }
    }
}

/// 发布本机地址：枚举本机地址 → 过滤 → 逐地址发更新（AAAA 只承载地址）。
async fn publish_own(client: &DdnsClient, cfg: &DdnsConfig) {
    let addrs = match hextet_platform::list_global_ipv6(Some(&cfg.exclude_interface)).await {
        Ok(a) => a,
        Err(e) => {
            debug!(error = %e, "枚举本机地址失败，跳过 DDNS 发布");
            return;
        }
    };
    if addrs.is_empty() {
        debug!("本机没有可用作 endpoint 的地址，跳过 DDNS 发布");
        return;
    }
    let endpoints: Vec<SocketAddrV6> = usable_endpoints(&addrs, cfg.port);
    if endpoints.is_empty() {
        return;
    }
    match client.publish(&endpoints) {
        Ok(()) => debug!(endpoints = endpoints.len(), "DDNS 更新已发出"),
        Err(e) => warn!(error = %e, "DDNS 更新失败"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hextet_core::config::{Config, render_peer_block};
    use hextet_core::identity::NodeIdentity;

    /// 造一份含一个 peer 的配置，再手工补 `ddns` 字段来测 `ddns_peers`。
    fn peer_with(seed: u8, ddns: Option<&str>) -> Peer {
        let nk = hextet_core::network::NetworkKey::generate();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hextet.toml");
        let id = NodeIdentity::from_seed(&[seed; 32]);
        let mut text =
            Config::render_template("home", &nk, std::path::Path::new("node.key"), 4193, None);
        let mut block = render_peer_block("nas", &id.public(), &[], &[]);
        if let Some(host) = ddns {
            block.push_str(&format!("ddns = \"{host}\"\n"));
        }
        text.push_str(&block);
        std::fs::write(&path, text).unwrap();
        Config::load(&path, None).unwrap().peers.remove(0)
    }

    #[test]
    fn ddns_peers_filters_to_configured_hosts() {
        let with = peer_with(2, Some("nas.dynv6.net"));
        let without = peer_with(3, None);

        let all = vec![with.clone(), without];
        let got = ddns_peers(&all);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].host, "nas.dynv6.net");
        assert_eq!(got[0].key_b64, with.public_key.to_base64());
    }

    #[test]
    fn ddns_peers_empty_when_none_configured() {
        assert!(ddns_peers(&[peer_with(4, None)]).is_empty());
        assert!(ddns_peers(&[]).is_empty());
    }
}
