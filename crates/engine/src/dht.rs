//! DHT 会合（会合兜底链第 ⑤ 层）——daemon 侧的发布/查询接线。
//!
//! 纯逻辑的密钥派生 + AEAD 在 `hextet-discovery::record`，传输在
//! `hextet-discovery::client`，节点表持久化在 `hextet-discovery::nodes`；本模块只做
//! **调度**：周期发布自己的会合记录、周期查询各 peer 的会合记录（喂给
//! `discovered` 通道，`Source::Dht`）、周期持久化 bootstrap 节点表。
//!
//! 与 LAN 组播、gossip 一样：DHT 是**尽力而为**的一路会合，构建失败（例如没有
//! IPv4、`mainline` 无法绑定）只降级为「这一路不可用」，绝不阻断 daemon 启动。
//! 真正的数据面仍是纯 IPv6，DHT 只是控制面弱依赖 IPv4（spec §5）。

use std::net::{Ipv4Addr, SocketAddrV6};
use std::path::PathBuf;
use std::time::Duration;

use hextet_core::identity::NodePublicKey;
use hextet_discovery::client::DhtClient;
use hextet_discovery::nodes::DhtNodesFile;
use hextet_discovery::record::{epoch_of, usable_endpoints};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::candidates::{DiscoveredEndpoints, Source};
use crate::state::unix_secs;

/// 自己会合记录的发布周期（~55min：BEP44 的 2h 过期前重发，spec §5）。
pub const PUBLISH_INTERVAL: Duration = Duration::from_secs(55 * 60);
/// 查询各 peer 会合记录的周期。
pub const LOOKUP_INTERVAL: Duration = Duration::from_secs(30);
/// 一轮查询的总时长预算：串行查完全部 peer 最多花这么久，超时放弃剩余 peer。
///
/// 串行 `lookup` 每个最坏要几秒（mainline 内部 2s 超时），peer 一多就会把
/// `publish_tick`/`save_tick`/`kick_rx` 饿死；20s 预算在 30s 的 `LOOKUP_INTERVAL`
/// 内给它们留足余量，被跳过的 peer 下一轮（30s 后）会再查。
const LOOKUP_BUDGET: Duration = Duration::from_secs(20);
/// 会合记录里最多发布几个 endpoint（= `MAX_CANDIDATES`：候选列表上限 8，多发布无意义，
/// 且把记录值稳在 BEP44 的 1000 字节上限以内）。
const MAX_PUBLISHED_ENDPOINTS: usize = 8;
/// 持久化 bootstrap 节点表的周期。
pub const NODES_SAVE_INTERVAL: Duration = Duration::from_secs(10 * 60);

/// DHT 会合的运行参数。
#[derive(Debug)]
pub struct DhtConfig {
    /// 会合记录密钥（`hextet-discovery::record::derive_dht_key`）。
    pub dht_key: [u8; 32],
    /// 本节点公钥（自己的会合记录用）。
    pub own_public: NodePublicKey,
    /// 本节点 WireGuard 监听端口（会合记录里广播）。
    pub listen_port: u16,
    /// 枚举本机地址时要排除的接口（hextet0 自己）。
    pub exclude_interface: String,
    /// bootstrap 节点表持久化路径。
    pub nodes_path: PathBuf,
    /// 初始要查询会合记录的 peer 公钥 base64（运行时经 [`DhtControl::UpdatePeers`] 更新）。
    pub peers: Vec<String>,
}

/// daemon → DHT 任务的运行时控制。
#[derive(Debug, Clone)]
pub enum DhtControl {
    /// 用新的 peer 公钥 base64 列表替换查询目标（gossip 成员增删时推送）。
    UpdatePeers(Vec<String>),
}

/// DHT 任务 → daemon 的派生事件。
#[derive(Debug, Clone)]
pub enum DhtEvent {
    /// 某 peer 的会合记录更新（来源为 [`Source::Dht`]）。
    Discovered(DiscoveredEndpoints),
}

/// 常驻 DHT 会合：周期发布 + 周期查询 + 周期落盘。
///
/// 构建失败（无 IPv4 / mainline 不可用）时返回 `Err`，调用方据此 warn 并跳过这一路。
/// 正常返回只发生在 `tx` 的接收端被丢弃、或 `ctl_rx` 关闭时。
pub async fn serve(
    mut cfg: DhtConfig,
    tx: mpsc::Sender<DhtEvent>,
    mut ctl_rx: mpsc::Receiver<DhtControl>,
    mut kick_rx: mpsc::Receiver<()>,
) -> std::io::Result<()> {
    // 先读持久化的 bootstrap 节点表（软状态，读失败 = 空表）
    let mut nodes = DhtNodesFile::load(&cfg.nodes_path);
    let client = DhtClient::new(cfg.dht_key, nodes.nodes.clone(), Ipv4Addr::UNSPECIFIED)
        .map_err(std::io::Error::other)?;
    info!(bootstrap = nodes.nodes.len(), "DHT 会合已启动");

    let mut peers: Vec<NodePublicKey> = std::mem::take(&mut cfg.peers)
        .into_iter()
        .filter_map(|b64| NodePublicKey::from_base64(&b64).ok())
        .collect();
    let mut publish_tick = tokio::time::interval(PUBLISH_INTERVAL);
    let mut lookup_tick = tokio::time::interval(LOOKUP_INTERVAL);
    let mut save_tick = tokio::time::interval(NODES_SAVE_INTERVAL);

    loop {
        tokio::select! {
            // 三个 interval 的第一次 tick 都立即触发：启动即发布、即查询、即落盘
            _ = publish_tick.tick() => {
                publish_own(&client, &cfg).await;
            }
            _ = lookup_tick.tick() => {
                // 整轮查询限时（见 LOOKUP_BUDGET）：超时即放弃剩余 peer，避免串行
                // lookup 把 publish/save/kick 分支饿死。被跳过的 peer 下轮补查。
                let done = tokio::time::timeout(LOOKUP_BUDGET, async {
                    for peer in &peers {
                        match client.lookup(peer).await {
                            Ok(endpoints) if !endpoints.is_empty() => {
                                debug!(peer = %peer.to_base64(), "DHT 查到了会合记录");
                                if tx.send(DhtEvent::Discovered(DiscoveredEndpoints {
                                    source: Source::Dht,
                                    peer_key: peer.to_base64(),
                                    endpoints,
                                })).await.is_err() {
                                    return true;
                                }
                            }
                            Ok(_) => {}
                            Err(e) => debug!(peer = %peer.to_base64(), error = %e, "DHT 查询失败"),
                        }
                    }
                    false
                }).await;
                // 通道关闭 → 退出任务；超时（Err）→ 只放弃本轮剩余 peer，不退出
                if done.unwrap_or(false) {
                    return Ok(());
                }
            }
            _ = save_tick.tick() => {
                nodes.refresh(client.bootstrap_nodes().await);
                if let Err(e) = nodes.save(&cfg.nodes_path) {
                    warn!(path = %cfg.nodes_path.display(), error = %e, "写 DHT 节点表失败");
                }
            }
            kicked = kick_rx.recv() => {
                if kicked.is_none() {
                    return Ok(());
                }
                debug!("本机地址变化：立刻重发会合记录");
                publish_own(&client, &cfg).await;
            }
            ctl = ctl_rx.recv() => {
                match ctl {
                    Some(DhtControl::UpdatePeers(p)) => {
                        peers = p.into_iter().filter_map(|b64| NodePublicKey::from_base64(&b64).ok()).collect();
                    }
                    None => return Ok(()),
                }
            }
        }
    }
}

/// 发布本节点自己的会合记录：枚举本机地址 → 过滤 → 加密 → `put_mutable`。
async fn publish_own(client: &DhtClient, cfg: &DhtConfig) {
    let addrs = match hextet_platform::list_global_ipv6(Some(&cfg.exclude_interface)).await {
        Ok(a) => a,
        Err(e) => {
            debug!(error = %e, "枚举本机地址失败，跳过 DHT 发布");
            return;
        }
    };
    if addrs.is_empty() {
        debug!("本机没有可用作 endpoint 的地址，跳过 DHT 发布");
        return;
    }
    let endpoints: Vec<SocketAddrV6> = usable_endpoints(&addrs, cfg.listen_port)
        .into_iter()
        .take(MAX_PUBLISHED_ENDPOINTS)
        .collect();
    if endpoints.is_empty() {
        return;
    }
    let epoch = epoch_of(unix_secs(std::time::SystemTime::now()));
    match client.publish(&cfg.own_public, &endpoints, epoch).await {
        Ok(()) => debug!(endpoints = endpoints.len(), "DHT 会合记录已发布"),
        Err(e) => warn!(error = %e, "DHT 会合记录发布失败"),
    }
}
