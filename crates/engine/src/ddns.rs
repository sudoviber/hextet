//! DDNS 会合（会合兜底链第 ⑥ 层）——daemon 侧的发布/查询接线。
//!
//! 纯逻辑的密钥派生 + AEAD 编解码在 `hextet-discovery::ddns`，DNS 查询在
//! `hextet-discovery::ddns::resolver`，HTTP 更新在 `hextet-discovery::ddns::updater`；
//! 本模块只做**调度**：周期发布本节点的 DDNS 会合记录（webhook/Cloudflare 更新 TXT）、
//! 周期查询各 peer 的 FQDN（喂给 `discovered` 通道，`Source::Ddns`）。
//!
//! 与 LAN/DHT/gossip 一样：DDNS 是**尽力而为**的一路会合，构建失败（例如解析器建不起
//! 来、webhook URL 非法）只降级为「这一路不可用」，绝不阻断 daemon 启动。

use std::net::{SocketAddr, SocketAddrV6};
use std::time::Duration;

use hextet_discovery::ddns::render_record;
use hextet_discovery::ddns::resolver::DdnsResolver;
use hextet_discovery::ddns::updater::DdnsUpdater;
use hextet_discovery::record::{RecordPayload, epoch_of, usable_endpoints};
use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::candidates::{DiscoveredEndpoints, Source};
use crate::state::unix_secs;

/// 自己会合记录的发布周期（15min：给 DNS TTL 传播留余量，见 docs/protocol/ddns.md）。
pub const PUBLISH_INTERVAL: Duration = Duration::from_secs(15 * 60);
/// 查询各 peer 会合记录的周期（受 TTL 缓存约束，但比 DHT 在中国可达）。
pub const LOOKUP_INTERVAL: Duration = Duration::from_secs(30);
/// 发布端封顶的 endpoint 数（TXT 单条 255 字节，见 ADR-0010 决策）。
pub const MAX_PUBLISHED_ENDPOINTS: usize = 2;

/// 一个要查询 DDNS 会合记录的 peer。
#[derive(Debug, Clone)]
pub struct DdnsPeer {
    /// peer 的 ed25519 公钥 base64（喂给 `DiscoveredEndpoints`）。
    pub key_b64: String,
    /// 这个 peer 的 DDNS FQDN；`None` = 不查询它。
    pub fqdn: Option<String>,
}

/// DDNS 会合的运行参数。
#[derive(Debug)]
pub struct DdnsConfig {
    /// 会合记录密钥（`hextet-discovery::ddns::derive_ddns_key`）。
    pub ddns_key: [u8; 32],
    /// 本节点 WireGuard 监听端口（会合记录里广播）。
    pub listen_port: u16,
    /// 枚举本机地址时要排除的接口（hextet0 自己）。
    pub exclude_interface: String,
    /// 本节点要发布会合记录的 FQDN；`None` = 不发布。
    pub fqdn: Option<String>,
    /// 更新器；`fqdn` 为 `Some` 时必为 `Some`。
    pub updater: Option<DdnsUpdater>,
    /// 覆盖系统 DNS、把查询指向的解析器（`ip:port`）；`None` = 系统配置。
    pub resolver_addr: Option<SocketAddr>,
    /// 初始要查询会合记录的 peer（运行时经 [`DdnsControl::UpdatePeers`] 更新）。
    pub peers: Vec<DdnsPeer>,
}

/// daemon → DDNS 任务的运行时控制。
#[derive(Debug, Clone)]
pub enum DdnsControl {
    /// 用新的 peer 列表替换查询目标（gossip 成员增删时推送）。
    UpdatePeers(Vec<DdnsPeer>),
}

/// DDNS 任务 → daemon 的派生事件。
#[derive(Debug, Clone)]
pub enum DdnsEvent {
    /// 某 peer 的会合记录更新（来源为 [`Source::Ddns`]）。
    Discovered(DiscoveredEndpoints),
}

/// 常驻 DDNS 会合：周期发布 + 周期查询。
///
/// 解析器构建失败时返回 `Err`，调用方据此 warn 并跳过这一路。正常返回只发生在
/// `tx` 的接收端被丢弃、或 `ctl_rx` 关闭时。
pub async fn serve(
    mut cfg: DdnsConfig,
    tx: mpsc::Sender<DdnsEvent>,
    mut ctl_rx: mpsc::Receiver<DdnsControl>,
    mut kick_rx: mpsc::Receiver<()>,
) -> std::io::Result<()> {
    let resolver = match cfg.resolver_addr {
        Some(addr) => DdnsResolver::with_nameserver(addr),
        None => DdnsResolver::new(),
    }
    .map_err(std::io::Error::other)?;
    debug!(resolver = ?cfg.resolver_addr, "DDNS 会合已启动（解析器就绪）");

    let mut peers: Vec<DdnsPeer> = std::mem::take(&mut cfg.peers);
    let mut publish_tick = tokio::time::interval(PUBLISH_INTERVAL);
    let mut lookup_tick = tokio::time::interval(LOOKUP_INTERVAL);

    loop {
        tokio::select! {
            // 两个 interval 的第一次 tick 都立即触发：启动即发布、即查询
            _ = publish_tick.tick() => {
                publish_own(&cfg).await;
            }
            _ = lookup_tick.tick() => {
                for peer in peers.iter().filter(|p| p.fqdn.is_some()) {
                    let fqdn = peer.fqdn.as_deref().expect("filtered on Some");
                    match resolver.lookup_peer(fqdn, &cfg.ddns_key).await {
                        Ok(endpoints) if !endpoints.is_empty() => {
                            debug!(peer = %peer.key_b64, fqdn, "DDNS 查到了会合记录");
                            if tx.send(DdnsEvent::Discovered(DiscoveredEndpoints {
                                source: Source::Ddns,
                                peer_key: peer.key_b64.clone(),
                                endpoints,
                            })).await.is_err() {
                                return Ok(());
                            }
                        }
                        Ok(_) => {}
                        Err(e) => debug!(peer = %peer.key_b64, fqdn, error = %e, "DDNS 查询失败"),
                    }
                }
            }
            kicked = kick_rx.recv() => {
                if kicked.is_none() {
                    return Ok(());
                }
                debug!("本机地址变化：立刻重发 DDNS 会合记录");
                publish_own(&cfg).await;
            }
            ctl = ctl_rx.recv() => {
                match ctl {
                    Some(DdnsControl::UpdatePeers(p)) => peers = p,
                    None => return Ok(()),
                }
            }
        }
    }
}

/// 发布本节点自己的会合记录：枚举本机地址 → 过滤 → 封顶 → 加密 → `set_txt`。
async fn publish_own(cfg: &DdnsConfig) {
    let (Some(fqdn), Some(updater)) = (&cfg.fqdn, &cfg.updater) else {
        return;
    };
    let addrs = match hextet_platform::list_global_ipv6(Some(&cfg.exclude_interface)).await {
        Ok(a) => a,
        Err(e) => {
            debug!(error = %e, "枚举本机地址失败，跳过 DDNS 发布");
            return;
        }
    };
    let usable = usable_endpoints(&addrs, cfg.listen_port);
    if usable.is_empty() {
        debug!("本机没有可用作 endpoint 的地址，跳过 DDNS 发布");
        return;
    }
    let dropped = usable.len().saturating_sub(MAX_PUBLISHED_ENDPOINTS);
    if dropped > 0 {
        warn!(dropped, "DDNS 记录 endpoint 超上限，丢弃多余的");
    }
    let endpoints: Vec<SocketAddrV6> = usable.into_iter().take(MAX_PUBLISHED_ENDPOINTS).collect();
    let epoch = epoch_of(unix_secs(std::time::SystemTime::now()));
    let value = match render_record(&cfg.ddns_key, &RecordPayload { endpoints, epoch }) {
        Ok(v) => v,
        Err(e) => {
            warn!(error = %e, "渲染 DDNS 会合记录失败");
            return;
        }
    };
    match updater.set_txt(fqdn, &value).await {
        Ok(()) => debug!(fqdn, "DDNS 会合记录已发布"),
        Err(e) => warn!(fqdn, error = %e, "DDNS 会合记录发布失败"),
    }
}
