//! 隧道内 gossip（协议规范：docs/protocol/gossip.md）。
//!
//! 纯逻辑部分（[`handle_datagram`]、[`is_within_prefix`]）不碰 socket，可完整单测；
//! 真正的收发在 [`serve`] 里，由 `scripts/netns-e2e-gossip.sh` 端到端覆盖。
//!
//! 与 LAN 组播的差异：gossip **只跑在 WG 隧道内**——socket 绑定在 overlay 地址上，
//! 收到的包还额外校验源地址在网络 /48 内（隧道外拿不到这个地址）。条目本身靠
//! ed25519 签名认证（见 `hextet_core::gossip`），不需要网络密钥派生的对称 MAC。

use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use std::time::Duration;

use hextet_core::gossip::{Entry, GossipStore};
use hextet_core::identity::NodeIdentity;
use hextet_core::network::NetworkPrefix;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::candidates::{DiscoveredEndpoints, Source};
use crate::state::unix_secs;

/// gossip 周期全量广播的间隔。
pub const BROADCAST_INTERVAL: Duration = Duration::from_secs(30);
/// 收包缓冲区（条目最大 ~500 字节，留足余量）。
const BUF_LEN: usize = 1500;

/// gossip 从隧道里推给 daemon 的派生决策。
#[derive(Debug, Clone)]
pub enum GossipEvent {
    /// 某 peer 的 endpoint 条目更新（转介）。
    Discovered(DiscoveredEndpoints),
    /// 某 node 被准入为成员。
    MemberAdmitted {
        /// 被准入的 node 公钥。
        node: hextet_core::identity::NodePublicKey,
        /// 成员名。
        name: String,
        /// 该 node 的 overlay 地址（由公钥派生）。
        address: Ipv6Addr,
    },
    /// 某 node 被吊销。
    Revoked {
        /// 被吊销的 node 公钥。
        node: hextet_core::identity::NodePublicKey,
    },
}

/// 源地址是否在网络 /48 前缀内（隧道内 gossip 的第二道防线）。
///
/// 第一道防线是 socket 只绑 overlay 地址；这里兜底：即使有人从隧道外向我们的
/// overlay 地址发 UDP（几乎不可能），源地址也不该落在网络前缀之外。
pub fn is_within_prefix(addr: &Ipv6Addr, prefix: &NetworkPrefix) -> bool {
    &addr.octets()[..6] == prefix.as_bytes()
}

/// 处理一个收到的数据报：校验源 → 解码 → 合并 → 派生事件。
///
/// 以下情形一律**静默**丢弃：源地址不在网络内、解码失败、条目非法（store 拒绝）、
/// 自己的 endpoint 条目（会通过转介回环）、无可用 endpoint 的 endpoint 条目。
pub fn handle_datagram(
    buf: &[u8],
    src: Ipv6Addr,
    prefix: &NetworkPrefix,
    own_key_b64: &str,
    store: &mut GossipStore,
) -> Option<GossipEvent> {
    if !is_within_prefix(&src, prefix) {
        return None;
    }
    let entry = Entry::decode(buf).ok()?;
    match entry {
        Entry::Endpoint { .. } => {
            let node = entry.node().to_base64();
            if node == own_key_b64 {
                return None;
            }
            let endpoints = entry.endpoint_addrs();
            if endpoints.is_empty() {
                return None;
            }
            let outcome = store.merge(entry);
            if outcome != hextet_core::gossip::MergeOutcome::Applied {
                return None;
            }
            Some(GossipEvent::Discovered(DiscoveredEndpoints {
                source: Source::Gossip,
                peer_key: node,
                endpoints,
            }))
        }
        Entry::Member { .. } => {
            let node = entry.node().clone();
            let name = match &entry {
                Entry::Member { name, .. } => name.clone(),
                _ => unreachable!(),
            };
            let outcome = store.merge(entry);
            if outcome != hextet_core::gossip::MergeOutcome::Applied {
                return None;
            }
            // 已吊销的 node 不再准入：member 与 revocation 是不同 key，LWW 不会跨类型比较，
            // 所以这里显式查一次，避免"吊销后又收到它的 member 条目"把它重新拉回来。
            if store.is_revoked(&node) {
                return None;
            }
            // 地址由公钥派生（与 site 字段自洽），成员名仅用于展示
            let address = match hextet_core::addr::derive_node_addr(*prefix, &node) {
                Ok(a) => a.address,
                Err(e) => {
                    debug!(error = %e, "成员地址派生失败，忽略该 member 条目");
                    return None;
                }
            };
            Some(GossipEvent::MemberAdmitted {
                node,
                name,
                address,
            })
        }
        Entry::Revocation { .. } => {
            let node = entry.node().clone();
            let outcome = store.merge(entry);
            if outcome != hextet_core::gossip::MergeOutcome::Applied {
                return None;
            }
            Some(GossipEvent::Revoked { node })
        }
    }
}

/// gossip 运行参数。
#[derive(Debug)]
pub struct GossipConfig {
    /// gossip UDP 端口（默认 4197）。
    pub port: u16,
    /// 本节点 overlay 地址（socket 绑定到它 → 隧道内才可达）。
    pub own_address: Ipv6Addr,
    /// 网络 /48 前缀（校验源地址）。
    pub prefix: NetworkPrefix,
    /// 本节点身份（给 endpoint 条目签名）。
    pub own_identity: NodeIdentity,
    /// 本节点 WireGuard 监听端口（endpoint 条目里要广播的端口）。
    pub listen_port: u16,
    /// 枚举本机地址时要排除的接口（hextet0 自己）。
    pub exclude_interface: String,
    /// 初始广播目标：已配置 peer 的 overlay 地址。
    pub targets: Vec<Ipv6Addr>,
}

/// 广播目标更新（daemon 在 peer 增删时推送）。
#[derive(Debug, Clone)]
pub enum GossipControl {
    /// 用新的 overlay 地址列表替换广播目标。
    UpdateTargets(Vec<Ipv6Addr>),
}

/// 常驻 gossip：周期广播 + 收包。
///
/// 只在 socket 出错、`tx` 的接收端被丢弃、或 `ctl_rx` 关闭时返回。
/// `kick_rx` 收到信号时立刻补发一次（本机地址变化 → 广播新的 endpoint 条目）。
pub async fn serve(
    mut cfg: GossipConfig,
    tx: mpsc::Sender<GossipEvent>,
    mut ctl_rx: mpsc::Receiver<GossipControl>,
    mut kick_rx: mpsc::Receiver<()>,
) -> std::io::Result<()> {
    let bind = SocketAddrV6::new(cfg.own_address, cfg.port, 0, 0);
    let socket = UdpSocket::bind(bind).await?;
    info!(
        address = %cfg.own_address,
        port = cfg.port,
        "隧道内 gossip 已启动（只监听 overlay 地址）"
    );

    let own_key_b64 = cfg.own_identity.public().to_base64();
    let mut store = GossipStore::new();
    let mut targets = std::mem::take(&mut cfg.targets);
    let mut seq = unix_secs(std::time::SystemTime::now());
    let mut buf = vec![0u8; BUF_LEN];
    let mut ticker = tokio::time::interval(BROADCAST_INTERVAL);

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                broadcast(&socket, &cfg, &store, &targets, &mut seq, true).await;
            }
            kicked = kick_rx.recv() => {
                if kicked.is_none() {
                    return Ok(());
                }
                debug!("本机地址变化：立刻广播新的 endpoint 条目");
                broadcast(&socket, &cfg, &store, &targets, &mut seq, true).await;
            }
            ctl = ctl_rx.recv() => {
                match ctl {
                    Some(GossipControl::UpdateTargets(t)) => targets = t,
                    None => return Ok(()),
                }
            }
            received = socket.recv_from(&mut buf) => {
                let (n, src) = received?;
                let SocketAddr::V6(src6) = src else { continue };
                if let Some(event) = handle_datagram(&buf[..n], *src6.ip(), &cfg.prefix, &own_key_b64, &mut store) {
                    // 变化即发：收到新条目后立刻把它转播出去（gossip 传播），
                    // 不必等 30s 周期——对端换前缀后的恢复延迟取决于这条路径。
                    // 这里 announce_self=false：只转播学到的条目，绝不重签自己的
                    // endpoint（否则双方各自把 seq 推进一格、把对方的新条目反复
                    // Applied，形成永不收敛的 ping-pong 放大）。
                    broadcast(&socket, &cfg, &store, &targets, &mut seq, false).await;
                    if tx.send(event).await.is_err() {
                        return Ok(());
                    }
                }
            }
        }
    }
}

/// 向所有目标广播：自己的 endpoint 条目 + 表里的全部条目（gossip 传播）。
///
/// `announce_self` 决定是否重签自己的 endpoint 条目并推进 seq：
/// - 周期 tick / 本机地址变化（kick）→ true：自己的状态变了/心跳，要推进 seq。
/// - 收到新条目后的转播 → false：只把学到的条目转发出去，自己的状态没变，
///   绝不能推进 seq——否则双方会把对方带新 seq 的条目反复 Applied → 再转播 →
///   再推进 seq，形成永不收敛的 ping-pong 放大。
async fn broadcast(
    socket: &UdpSocket,
    cfg: &GossipConfig,
    store: &GossipStore,
    targets: &[Ipv6Addr],
    seq: &mut u64,
    announce_self: bool,
) {
    let mut packets: Vec<Vec<u8>> = Vec::new();
    if announce_self {
        // 本机当前地址由 platform 枚举（排除 hextet0 自己），并截断到上限
        let addrs = match hextet_platform::list_global_ipv6(Some(&cfg.exclude_interface)).await {
            Ok(a) => a,
            Err(e) => {
                debug!(error = %e, "枚举本机地址失败，跳过 gossip 广播");
                return;
            }
        };
        if addrs.is_empty() {
            debug!("本机没有可用作 endpoint 的地址，跳过 gossip 广播");
            return;
        }
        let addrs: Vec<Ipv6Addr> = addrs
            .into_iter()
            .take(hextet_core::gossip::GOSSIP_MAX_ADDRS)
            .collect();
        // 严格单调：每次广播 seq 至少 +1。否则"同一秒内换地址"时，收方的 LWW 会因
        // seq 相同而按字节序选一个，可能在旧地址与新地址之间挑到旧的（旧地址字节序
        // 更小）。gossip 不做绝对时间校验（不同于 LAN 公告的 ±300s），单调即可。
        *seq = (*seq + 1).max(unix_secs(std::time::SystemTime::now()));
        match Entry::sign_endpoint(&cfg.own_identity, addrs, cfg.listen_port, *seq) {
            Ok(e) => {
                if let Ok(b) = e.encode() {
                    packets.push(b);
                }
            }
            Err(e) => {
                warn!(error = %e, "编码本机 endpoint 条目失败");
                return;
            }
        }
    }

    for entry in store.entries() {
        if let Ok(b) = entry.encode() {
            packets.push(b);
        }
    }

    for &target in targets {
        let dst = SocketAddr::V6(SocketAddrV6::new(target, cfg.port, 0, 0));
        for pkt in &packets {
            if let Err(e) = socket.send_to(pkt, dst).await {
                debug!(target = %target, error = %e, "gossip 广播失败");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hextet_core::gossip::Entry;
    use hextet_core::identity::NodeIdentity;
    use hextet_core::network::NetworkKey;

    fn prefix() -> NetworkPrefix {
        NetworkPrefix::derive(
            &NetworkKey::from_base64("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap(),
        )
    }

    fn id(seed: u8) -> NodeIdentity {
        NodeIdentity::from_seed(&[seed; 32])
    }

    fn own() -> String {
        id(1).public().to_base64()
    }

    #[test]
    fn within_prefix_detection() {
        let p = prefix();
        // 用网络前缀构造一个地址
        let mut octets = [0u8; 16];
        octets[..6].copy_from_slice(p.as_bytes());
        octets[8] = 1;
        let inside = Ipv6Addr::from(octets);
        assert!(is_within_prefix(&inside, &p));
        assert!(!is_within_prefix(&"2001:db8::1".parse().unwrap(), &p));
        assert!(!is_within_prefix(&"fd00::1".parse().unwrap(), &p));
    }

    #[test]
    fn endpoint_entry_is_forwarded_as_discovered() {
        let p = prefix();
        let mut store = GossipStore::new();
        let src = {
            let mut octets = [0u8; 16];
            octets[..6].copy_from_slice(p.as_bytes());
            octets[8] = 9;
            Ipv6Addr::from(octets)
        };
        let entry =
            Entry::sign_endpoint(&id(2), vec!["2001:db8::2".parse().unwrap()], 4193, 100).unwrap();
        let bytes = entry.encode().unwrap();
        let ev = handle_datagram(&bytes, src, &p, &own(), &mut store).expect("应有转介");
        match ev {
            GossipEvent::Discovered(d) => {
                assert_eq!(d.source, Source::Gossip);
                assert_eq!(d.peer_key, id(2).public().to_base64());
                assert_eq!(d.endpoints.len(), 1);
            }
            other => panic!("expected Discovered, got {other:?}"),
        }
    }

    #[test]
    fn own_endpoint_is_ignored() {
        let p = prefix();
        let mut store = GossipStore::new();
        let src = {
            let mut octets = [0u8; 16];
            octets[..6].copy_from_slice(p.as_bytes());
            octets[8] = 9;
            Ipv6Addr::from(octets)
        };
        let entry =
            Entry::sign_endpoint(&id(1), vec!["2001:db8::1".parse().unwrap()], 4193, 100).unwrap();
        let bytes = entry.encode().unwrap();
        assert!(handle_datagram(&bytes, src, &p, &own(), &mut store).is_none());
        assert!(store.is_empty());
    }

    #[test]
    fn out_of_prefix_source_is_dropped() {
        let p = prefix();
        let mut store = GossipStore::new();
        let entry =
            Entry::sign_endpoint(&id(2), vec!["2001:db8::2".parse().unwrap()], 4193, 100).unwrap();
        let bytes = entry.encode().unwrap();
        // 源地址不在网络内：即使条目合法也直接丢
        assert!(
            handle_datagram(
                &bytes,
                "2001:db8::ff".parse().unwrap(),
                &p,
                &own(),
                &mut store
            )
            .is_none()
        );
    }

    #[test]
    fn member_entry_derives_address() {
        let p = prefix();
        let mut store = GossipStore::new();
        let src = {
            let mut octets = [0u8; 16];
            octets[..6].copy_from_slice(p.as_bytes());
            octets[8] = 9;
            Ipv6Addr::from(octets)
        };
        let member =
            Entry::sign_member(&id(1), id(2).public(), "nas".into(), 7, 100, [0xaa; 16]).unwrap();
        let bytes = member.encode().unwrap();
        let ev = handle_datagram(&bytes, src, &p, &own(), &mut store).expect("应有成员准入");
        match ev {
            GossipEvent::MemberAdmitted {
                node,
                name,
                address,
            } => {
                assert_eq!(node, id(2).public());
                assert_eq!(name, "nas");
                // 地址在 /48 内
                assert_eq!(&address.octets()[..6], p.as_bytes());
            }
            other => panic!("expected MemberAdmitted, got {other:?}"),
        }
    }

    #[test]
    fn revocation_is_forwarded() {
        let p = prefix();
        let mut store = GossipStore::new();
        let src = {
            let mut octets = [0u8; 16];
            octets[..6].copy_from_slice(p.as_bytes());
            octets[8] = 9;
            Ipv6Addr::from(octets)
        };
        let rev = Entry::sign_revocation(&id(1), id(2).public(), 100).unwrap();
        let bytes = rev.encode().unwrap();
        let ev = handle_datagram(&bytes, src, &p, &own(), &mut store).expect("应有吊销");
        assert!(matches!(ev, GossipEvent::Revoked { .. }));
    }

    #[test]
    fn stale_entries_are_dropped() {
        let p = prefix();
        let mut store = GossipStore::new();
        let src = {
            let mut octets = [0u8; 16];
            octets[..6].copy_from_slice(p.as_bytes());
            octets[8] = 9;
            Ipv6Addr::from(octets)
        };
        let entry =
            Entry::sign_endpoint(&id(2), vec!["2001:db8::2".parse().unwrap()], 4193, 100).unwrap();
        let bytes = entry.encode().unwrap();
        assert!(handle_datagram(&bytes, src, &p, &own(), &mut store).is_some());
        // 同样的 seq 再来一次：Stale，不再发事件
        assert!(handle_datagram(&bytes, src, &p, &own(), &mut store).is_none());
    }
}
