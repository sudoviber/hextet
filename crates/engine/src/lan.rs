//! LAN 组播发现（协议规范：docs/protocol/lan-discovery.md）。
//!
//! 本文件的纯逻辑部分（[`LanTable`] 与 [`handle_datagram`]）不碰 socket，可完整单测；
//! 真正的组播收发在 [`serve`] 里，由 `scripts/netns-e2e-lan.sh` 端到端覆盖。

use std::collections::HashMap;
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use std::time::{Duration, SystemTime};

use hextet_core::beacon::{BEACON_MAX_ADDRS, Beacon};
use hextet_core::identity::NodePublicKey;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::candidates::{DiscoveredEndpoints, Source};
use crate::state::unix_secs;

/// 两次公告之间的间隔。
///
/// 5s 是"同 LAN 双端同时换前缀后多久恢复"的上界；一条公告 ≤130 字节，
/// 5s 一发折合 26 B/s，噪声可忽略。
pub const ANNOUNCE_INTERVAL: Duration = Duration::from_secs(5);
/// 一条 LAN 记录多久没被刷新就丢弃。
///
/// 12 个公告周期。给得比周期宽松得多，是因为丢几个组播包很常见（交换机的组播
/// snooping、无线漫游），而错误地丢掉一条有效记录的代价是"要多等一个周期"。
pub const ENTRY_TTL: Duration = Duration::from_secs(60);
/// 表里最多跟踪多少个节点。
pub const MAX_TRACKED: usize = 64;
/// 公告的 `seq`（发送时刻）与本地时钟允许的最大偏差（秒）。
pub const SEQ_SKEW_TOLERANCE_SECS: u64 = 300;

/// 通知 daemon：某个 peer 的 LAN endpoint 集合有更新。
///
/// 这是会合层「discovered」通道的通用载体（[`crate::candidates::DiscoveredEndpoints`]）
/// 的特例：来源固定为 [`Source::Lan`]。
pub type LanUpdate = DiscoveredEndpoints;

#[derive(Debug)]
struct Entry {
    endpoints: Vec<SocketAddrV6>,
    seq: u64,
    last_seen_unix: u64,
}

/// "LAN 上现在有谁、在哪"的软状态表。
///
/// 纯内存、不持久化：LAN 上的信息 5s 就会重新广告一次，落盘没有意义。
#[derive(Debug, Default)]
pub struct LanTable {
    entries: HashMap<String, Entry>,
}

impl LanTable {
    /// 新建空表。
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// 当前跟踪的节点数。
    pub fn tracked(&self) -> usize {
        self.entries.len()
    }

    /// 记录一次公告。返回 `true` 表示 endpoint 集合**发生了变化**（新节点或集合不同）。
    ///
    /// 抗重放：`seq` 比已记录的更旧时整条丢弃（连 TTL 都不刷新）。
    /// 表满时先 [`prune`](Self::prune)，仍满则**拒绝新条目**而不是驱逐已知节点——
    /// 已知节点的价值高于一个可能是伪造的新条目，而正常网络的成员数远小于
    /// [`MAX_TRACKED`]。
    pub fn record(
        &mut self,
        peer_key: String,
        endpoints: Vec<SocketAddrV6>,
        seq: u64,
        now_unix: u64,
    ) -> bool {
        if let Some(entry) = self.entries.get_mut(&peer_key) {
            if seq < entry.seq {
                return false;
            }
            entry.seq = seq;
            entry.last_seen_unix = now_unix;
            if entry.endpoints == endpoints {
                return false;
            }
            entry.endpoints = endpoints;
            return true;
        }

        if self.entries.len() >= MAX_TRACKED {
            self.prune(now_unix);
            if self.entries.len() >= MAX_TRACKED {
                debug!(
                    tracked = self.entries.len(),
                    "LAN 发现表已满，忽略新节点的公告"
                );
                return false;
            }
        }
        self.entries.insert(
            peer_key,
            Entry {
                endpoints,
                seq,
                last_seen_unix: now_unix,
            },
        );
        true
    }

    /// 某节点当前公告的 endpoint（未知节点返回空）。
    pub fn endpoints_for(&self, peer_key: &str) -> &[SocketAddrV6] {
        self.entries
            .get(peer_key)
            .map(|e| e.endpoints.as_slice())
            .unwrap_or(&[])
    }

    /// 丢弃超过 [`ENTRY_TTL`] 未刷新的记录。
    pub fn prune(&mut self, now_unix: u64) {
        let ttl = ENTRY_TTL.as_secs();
        self.entries
            .retain(|_, e| now_unix.saturating_sub(e.last_seen_unix) <= ttl);
    }
}

/// 处理一个收到的数据报：校验 → 记表 → 决定要不要通知 daemon。
///
/// 以下情形一律**静默**丢弃（不回任何东西、不记日志到 info 级别——LAN 上的观察者
/// 不该从我们的行为里读出任何信息）：
/// 解码失败、公钥是自己（组播回环）、没有可用 endpoint、`seq` 与本地时钟差得太远、
/// `seq` 比已记录的更旧（重放）。
pub fn handle_datagram(
    buf: &[u8],
    own_key_b64: &str,
    lan_key: &[u8; 32],
    table: &mut LanTable,
    now_unix: u64,
) -> Option<LanUpdate> {
    let beacon = Beacon::decode(buf, lan_key).ok()?;
    let peer_key = beacon.node_public_key.to_base64();
    if peer_key == own_key_b64 {
        return None;
    }
    if beacon.seq.abs_diff(now_unix) > SEQ_SKEW_TOLERANCE_SECS {
        debug!(seq = beacon.seq, now = now_unix, "LAN 公告的时间戳偏差过大");
        return None;
    }
    let endpoints = beacon.endpoints();
    if endpoints.is_empty() {
        return None;
    }
    if !table.record(peer_key.clone(), endpoints.clone(), beacon.seq, now_unix) {
        return None;
    }
    Some(DiscoveredEndpoints {
        source: Source::Lan,
        peer_key,
        endpoints,
    })
}

/// LAN 发现的运行参数。
#[derive(Debug, Clone)]
pub struct LanConfig {
    /// 公告 UDP 端口。
    pub port: u16,
    /// 链路本地组播组（默认 `ff02::4193`）。
    pub group: Ipv6Addr,
    /// 要在其上收发公告的接口 netlink index。
    pub interfaces: Vec<u32>,
    /// 本节点公钥（用来忽略自己的公告）。
    pub own_public_key: NodePublicKey,
    /// 公告认证密钥（`derive_lan_key`）。
    pub lan_key: [u8; 32],
    /// 公告里带的 WireGuard 监听端口。
    pub listen_port: u16,
    /// 枚举本机地址时要排除的接口（hextet 自己的 WG 接口）。
    pub exclude_interface: String,
}

/// 常驻 LAN 发现：周期公告 + 收公告。
///
/// 只在 socket 出错或 `tx` 的接收端被丢弃时返回。`kick_rx` 收到信号时立刻补发一次
/// 公告——daemon 在本机地址变化后踢它，于是"换前缀"到"对端知道我的新地址"的延迟
/// 不再受公告周期约束。
pub async fn serve(
    cfg: LanConfig,
    tx: mpsc::Sender<LanUpdate>,
    mut kick_rx: mpsc::Receiver<()>,
) -> std::io::Result<()> {
    if cfg.interfaces.is_empty() {
        return Err(std::io::Error::other("没有可用于组播的接口"));
    }
    let bind = SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, cfg.port, 0, 0);
    let socket = UdpSocket::bind(bind).await?;
    // 自己的公告会被公钥检查挡掉，关掉回环只是省一次收发
    if let Err(e) = socket.set_multicast_loop_v6(false) {
        debug!(error = %e, "关闭组播回环失败（无害，继续）");
    }

    let mut joined = 0usize;
    for &index in &cfg.interfaces {
        match socket.join_multicast_v6(&cfg.group, index) {
            Ok(()) => joined += 1,
            // 容器/虚拟环境里常有些接口 join 不了；只要还有一个成功就继续
            Err(e) => warn!(if_index = index, error = %e, "加入组播组失败，跳过该接口"),
        }
    }
    if joined == 0 {
        return Err(std::io::Error::other(
            "所有接口都无法加入 LAN 组播组，LAN 发现不可用",
        ));
    }
    info!(
        group = %cfg.group,
        port = cfg.port,
        interfaces = joined,
        "LAN 发现已启动"
    );

    let own_key_b64 = cfg.own_public_key.to_base64();
    let mut table = LanTable::new();
    let mut buf = [0u8; 256];
    let mut ticker = tokio::time::interval(ANNOUNCE_INTERVAL);

    loop {
        tokio::select! {
            // interval 的第一次 tick 立即触发：启动即公告，不用等一个周期
            _ = ticker.tick() => {
                announce(&socket, &cfg, &mut table).await;
            }
            kicked = kick_rx.recv() => {
                if kicked.is_none() {
                    return Ok(());
                }
                debug!("本机地址变化：立刻补发一次 LAN 公告");
                announce(&socket, &cfg, &mut table).await;
            }
            received = socket.recv_from(&mut buf) => {
                let (n, _src) = received?;
                let now_unix = unix_secs(SystemTime::now());
                if let Some(update) =
                    handle_datagram(&buf[..n], &own_key_b64, &cfg.lan_key, &mut table, now_unix)
                {
                    debug!(
                        peer = %update.peer_key,
                        endpoints = ?update.endpoints,
                        "LAN 上发现同网节点"
                    );
                    if tx.send(update).await.is_err() {
                        // daemon 走了：正常收尾
                        return Ok(());
                    }
                }
            }
        }
    }
}

/// 向每个接口发一条公告。地址枚举失败或本机没有可用地址时**跳过本次**。
async fn announce(socket: &UdpSocket, cfg: &LanConfig, table: &mut LanTable) {
    let now_unix = unix_secs(SystemTime::now());
    table.prune(now_unix);

    let addrs = match hextet_platform::list_global_ipv6(Some(&cfg.exclude_interface)).await {
        Ok(a) => a,
        Err(e) => {
            debug!(error = %e, "枚举本机地址失败，跳过本次 LAN 公告");
            return;
        }
    };
    if addrs.is_empty() {
        debug!("本机没有可用作 endpoint 的地址，跳过本次 LAN 公告");
        return;
    }
    // 截断在这里显式做：core 的 encode 拒绝超量，不做静默截断
    let addresses: Vec<Ipv6Addr> = addrs.into_iter().take(BEACON_MAX_ADDRS).collect();
    let beacon = Beacon {
        node_public_key: cfg.own_public_key.clone(),
        listen_port: cfg.listen_port,
        seq: now_unix,
        addresses,
    };
    let bytes = match beacon.encode(&cfg.lan_key) {
        Ok(b) => b,
        Err(e) => {
            warn!(error = %e, "编码 LAN 公告失败");
            return;
        }
    };
    for &index in &cfg.interfaces {
        let target = SocketAddrV6::new(cfg.group, cfg.port, 0, index);
        if let Err(e) = socket.send_to(&bytes, SocketAddr::V6(target)).await {
            debug!(if_index = index, error = %e, "发送 LAN 公告失败");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hextet_core::beacon::Beacon;
    use hextet_core::identity::NodeIdentity;

    const KEY: [u8; 32] = [3u8; 32];
    const NOW: u64 = 1_770_000_000;

    fn ep(s: &str) -> SocketAddrV6 {
        s.parse().unwrap()
    }

    fn beacon_bytes(seed: u8, port: u16, seq: u64, addrs: &[&str]) -> (String, Vec<u8>) {
        let id = NodeIdentity::from_seed(&[seed; 32]);
        let b = Beacon {
            node_public_key: id.public(),
            listen_port: port,
            seq,
            addresses: addrs
                .iter()
                .map(|a| a.parse::<Ipv6Addr>().unwrap())
                .collect(),
        };
        (id.public().to_base64(), b.encode(&KEY).unwrap())
    }

    fn own_key() -> String {
        NodeIdentity::from_seed(&[1u8; 32]).public().to_base64()
    }

    #[test]
    fn first_announcement_is_an_update() {
        let mut table = LanTable::new();
        let (peer, bytes) = beacon_bytes(2, 4193, NOW, &["2001:db8::2"]);
        let update = handle_datagram(&bytes, &own_key(), &KEY, &mut table, NOW).expect("有更新");
        assert_eq!(update.peer_key, peer);
        assert_eq!(update.endpoints, vec![ep("[2001:db8::2]:4193")]);
        assert_eq!(table.endpoints_for(&peer), &[ep("[2001:db8::2]:4193")]);
        assert_eq!(table.tracked(), 1);
    }

    /// 组播会把自己的公告回环给自己：必须按公钥忽略，否则会把自己当成 peer。
    #[test]
    fn own_announcement_is_ignored() {
        let mut table = LanTable::new();
        let (_, bytes) = beacon_bytes(1, 4193, NOW, &["2001:db8::1"]);
        assert!(handle_datagram(&bytes, &own_key(), &KEY, &mut table, NOW).is_none());
        assert_eq!(table.tracked(), 0);
    }

    #[test]
    fn bad_mac_is_ignored() {
        let mut table = LanTable::new();
        let (_, mut bytes) = beacon_bytes(2, 4193, NOW, &["2001:db8::2"]);
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        assert!(handle_datagram(&bytes, &own_key(), &KEY, &mut table, NOW).is_none());
        assert_eq!(table.tracked(), 0);
    }

    #[test]
    fn garbage_is_ignored() {
        let mut table = LanTable::new();
        assert!(handle_datagram(b"hello", &own_key(), &KEY, &mut table, NOW).is_none());
        assert!(handle_datagram(&[], &own_key(), &KEY, &mut table, NOW).is_none());
    }

    /// 只有 ULA/链路本地地址的公告没有可用 endpoint，等于没说什么：忽略。
    #[test]
    fn announcement_without_usable_endpoints_is_ignored() {
        let mut table = LanTable::new();
        let (_, bytes) = beacon_bytes(2, 4193, NOW, &["fd00::2", "fe80::2"]);
        assert!(handle_datagram(&bytes, &own_key(), &KEY, &mut table, NOW).is_none());
        assert_eq!(table.tracked(), 0);
    }

    #[test]
    fn stale_and_future_seq_are_ignored() {
        let mut table = LanTable::new();
        for seq in [
            NOW - SEQ_SKEW_TOLERANCE_SECS - 1,
            NOW + SEQ_SKEW_TOLERANCE_SECS + 1,
        ] {
            let (_, bytes) = beacon_bytes(2, 4193, seq, &["2001:db8::2"]);
            assert!(
                handle_datagram(&bytes, &own_key(), &KEY, &mut table, NOW).is_none(),
                "seq={seq} 应被忽略"
            );
        }
        assert_eq!(table.tracked(), 0);
    }

    /// 重放一条**更旧**的公告不能把已知地址改回去。
    #[test]
    fn replayed_older_announcement_does_not_change_anything() {
        let mut table = LanTable::new();
        let (peer, new_bytes) = beacon_bytes(2, 4193, NOW, &["2001:db8::9"]);
        handle_datagram(&new_bytes, &own_key(), &KEY, &mut table, NOW).expect("首条");

        let (_, old_bytes) = beacon_bytes(2, 4193, NOW - 30, &["2001:db8::1"]);
        assert!(handle_datagram(&old_bytes, &own_key(), &KEY, &mut table, NOW).is_none());
        assert_eq!(table.endpoints_for(&peer), &[ep("[2001:db8::9]:4193")]);
    }

    /// 同 seq 同内容（周期公告在同一秒内重发）：刷新 TTL，但不制造更新事件。
    #[test]
    fn identical_announcement_refreshes_ttl_without_an_update() {
        let mut table = LanTable::new();
        let (peer, bytes) = beacon_bytes(2, 4193, NOW, &["2001:db8::2"]);
        handle_datagram(&bytes, &own_key(), &KEY, &mut table, NOW).expect("首条");
        assert!(handle_datagram(&bytes, &own_key(), &KEY, &mut table, NOW + 30).is_none());
        // TTL 已被刷新：从 NOW+30 起再过 ENTRY_TTL-1 秒仍在
        table.prune(NOW + 30 + ENTRY_TTL.as_secs() - 1);
        assert_eq!(table.endpoints_for(&peer).len(), 1);
    }

    #[test]
    fn changed_endpoint_set_is_an_update() {
        let mut table = LanTable::new();
        let (peer, first) = beacon_bytes(2, 4193, NOW, &["2001:db8::2"]);
        handle_datagram(&first, &own_key(), &KEY, &mut table, NOW).expect("首条");
        // 换了前缀
        let (_, second) = beacon_bytes(2, 4193, NOW + 5, &["2001:db8:2::2"]);
        let update =
            handle_datagram(&second, &own_key(), &KEY, &mut table, NOW + 5).expect("应有更新");
        assert_eq!(update.endpoints, vec![ep("[2001:db8:2::2]:4193")]);
        assert_eq!(table.endpoints_for(&peer), &[ep("[2001:db8:2::2]:4193")]);
    }

    #[test]
    fn entries_expire_after_ttl() {
        let mut table = LanTable::new();
        let (peer, bytes) = beacon_bytes(2, 4193, NOW, &["2001:db8::2"]);
        handle_datagram(&bytes, &own_key(), &KEY, &mut table, NOW).expect("首条");
        table.prune(NOW + ENTRY_TTL.as_secs());
        assert_eq!(table.tracked(), 1, "刚好到 TTL 还不该被清掉");
        table.prune(NOW + ENTRY_TTL.as_secs() + 1);
        assert_eq!(table.tracked(), 0);
        assert!(table.endpoints_for(&peer).is_empty());
    }

    #[test]
    fn unknown_peer_has_no_endpoints() {
        let table = LanTable::new();
        assert!(table.endpoints_for("nobody").is_empty());
    }

    /// 表满时不驱逐已知节点：一个可能是伪造的新条目不该顶掉真实的 peer。
    #[test]
    fn table_stays_bounded_without_evicting_known_peers() {
        let mut table = LanTable::new();
        for i in 0..(MAX_TRACKED + 10) {
            let seed = u8::try_from(i % 200).unwrap() + 20;
            let (_, bytes) = beacon_bytes(seed, 4193, NOW, &[&format!("2001:db8::{:x}", i + 1)]);
            handle_datagram(&bytes, &own_key(), &KEY, &mut table, NOW);
        }
        assert_eq!(table.tracked(), MAX_TRACKED);

        // 第一个进来的仍在表里（没被后来者顶掉）
        let (first_peer, bytes) = beacon_bytes(20, 4193, NOW + 1, &["2001:db8::1"]);
        assert!(!table.endpoints_for(&first_peer).is_empty());
        // 已知节点的更新在表满时依然生效
        let _ = bytes;
    }

    /// 表满时已知节点的地址更新必须照常生效（只拒绝**新增**条目）。
    #[test]
    fn full_table_still_updates_known_peers() {
        let mut table = LanTable::new();
        let (peer, first) = beacon_bytes(20, 4193, NOW, &["2001:db8::1"]);
        handle_datagram(&first, &own_key(), &KEY, &mut table, NOW).expect("首条");
        for i in 1..(MAX_TRACKED + 10) {
            let seed = u8::try_from(i % 200).unwrap() + 21;
            let (_, bytes) = beacon_bytes(seed, 4193, NOW, &[&format!("2001:db8::{:x}", i + 1)]);
            handle_datagram(&bytes, &own_key(), &KEY, &mut table, NOW);
        }
        assert_eq!(table.tracked(), MAX_TRACKED);
        let (_, moved) = beacon_bytes(20, 4193, NOW + 5, &["2001:db8:2::1"]);
        let update =
            handle_datagram(&moved, &own_key(), &KEY, &mut table, NOW + 5).expect("应有更新");
        assert_eq!(update.peer_key, peer);
        assert_eq!(update.endpoints, vec![ep("[2001:db8:2::1]:4193")]);
    }

    #[test]
    fn endpoints_are_capped_per_peer() {
        let mut table = LanTable::new();
        // 一条公告最多 4 个地址（core 侧限制），这里确认表也如实存下它们
        let (peer, bytes) = beacon_bytes(
            2,
            4193,
            NOW,
            &["2001:db8::1", "2001:db8::2", "2001:db8::3", "2001:db8::4"],
        );
        handle_datagram(&bytes, &own_key(), &KEY, &mut table, NOW).expect("首条");
        assert_eq!(table.endpoints_for(&peer).len(), 4);
    }
}
