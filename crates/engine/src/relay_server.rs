//! 中继转发器（服务端；协议规范：docs/protocol/relay.md）。
//!
//! 只有在 `[node] relay = true` 时才会被启用（spec D5：默认关闭、显式启用）。
//! 它做的事很少：认证控制帧、给每一对会话分配一个 UDP 端口、在那个端口上把裸
//! WireGuard 包按源地址转给另一侧。**不解密、不解析载荷、不记录载荷。**
//!
//! 会话表与包速限制是纯逻辑（可单测）；转发本身用 loopback 端到端测。

use std::collections::HashMap;
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use std::time::{Duration, Instant, SystemTime};

use hextet_core::relay::{RelayFrame, RelayKind, SessionKey, is_relay_frame};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::candidates::normalize;
use crate::state::unix_secs;

/// 会话多久没被 `Register` 续期就关掉。
pub const SESSION_TTL: Duration = Duration::from_secs(180);
/// 客户端续期节奏（服务端不强制，只用来解释 TTL 的取值）。
pub const REGISTER_INTERVAL: Duration = Duration::from_secs(30);
/// 清理过期会话的周期。
pub const PRUNE_INTERVAL: Duration = Duration::from_secs(30);
/// 同时最多多少对会话。
///
/// 每对会话占一个 UDP socket 与一个 tokio 任务，256 对足够任何家庭/小团队网络，
/// 又让"别人的机器"上的资源占用有明确上界。
pub const MAX_SESSIONS: usize = 256;
/// 控制帧 `seq` 与本地时钟允许的最大偏差（秒）。
pub const SEQ_SKEW_TOLERANCE_SECS: u64 = 300;
/// 每对会话每秒最多转发多少个包。
///
/// 2000 pps × 1400 字节 ≈ 22 Mbps。中继跑在**别人的**机器上，必须有上限；
/// 需要更高就显式调大（配置项在 Task 13）。
pub const MAX_PACKETS_PER_SEC: u32 = 2_000;

/// 转发缓冲区大小。
///
/// WireGuard 报文 = 隧道 MTU + 32 字节开销，正常远小于 2048。收到恰好填满缓冲区的
/// 数据报时按"可能被截断"处理直接丢弃——转发一个截断的包只会让对端解密失败，
/// 还掩盖了真实原因。
const FORWARD_BUF: usize = 2048;

/// 谁可以用本节点做中继。
#[derive(Debug, Clone)]
pub enum RelayPolicy {
    /// 任何持有本网络 network key 的成员（默认）。
    AnyMember,
    /// 只有白名单里的公钥。
    Allowlist(Vec<[u8; 32]>),
}

impl RelayPolicy {
    /// 该公钥能不能在本节点上建会话。
    ///
    /// 会话两侧各自注册，因此白名单会**分别**校验两端——只放行一端时会话保持半开，
    /// 不会转发任何东西。
    pub fn allows(&self, key: &[u8; 32]) -> bool {
        match self {
            Self::AnyMember => true,
            Self::Allowlist(list) => list.contains(key),
        }
    }
}

/// 会话两侧的数据面地址；下标与 [`SessionKey`] 的排序一致。
pub type SessionAddrs = [Option<SocketAddrV6>; 2];

#[derive(Debug)]
struct Session {
    port: u16,
    addrs: SessionAddrs,
    last_seen_unix: u64,
}

/// 会话表（纯逻辑）。
#[derive(Debug, Default)]
pub struct RelayTable {
    sessions: HashMap<SessionKey, Session>,
}

impl RelayTable {
    /// 新建空表。
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
        }
    }

    /// 当前会话数。
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    /// 表是否为空。
    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    /// 是否已有这对会话。
    pub fn contains(&self, key: &SessionKey) -> bool {
        self.sessions.contains_key(key)
    }

    /// 新建会话。表满时返回 `false`（调用方应先 [`prune`](Self::prune)）。
    pub fn insert(&mut self, key: SessionKey, port: u16, now_unix: u64) -> bool {
        if self.sessions.len() >= MAX_SESSIONS {
            return false;
        }
        self.sessions.insert(
            key,
            Session {
                port,
                addrs: [None, None],
                last_seen_unix: now_unix,
            },
        );
        true
    }

    /// 记录/更新某一侧的数据面地址并续期。返回该侧地址是否**变化**了。
    ///
    /// 地址变化是正常的：某一侧换了前缀，它的下一次 `Register` 会带来新地址，
    /// 转发随即跟上。
    pub fn touch_addr(
        &mut self,
        key: &SessionKey,
        side: usize,
        addr: SocketAddrV6,
        now_unix: u64,
    ) -> bool {
        let Some(session) = self.sessions.get_mut(key) else {
            return false;
        };
        session.last_seen_unix = now_unix;
        let slot = &mut session.addrs[side.min(1)];
        if *slot == Some(addr) {
            return false;
        }
        *slot = Some(addr);
        true
    }

    /// 这对会话两侧当前的数据面地址。
    pub fn addrs(&self, key: &SessionKey) -> SessionAddrs {
        self.sessions.get(key).map_or([None, None], |s| s.addrs)
    }

    /// 这对会话占用的 UDP 端口。
    pub fn port(&self, key: &SessionKey) -> Option<u16> {
        self.sessions.get(key).map(|s| s.port)
    }

    /// 删除会话。
    pub fn remove(&mut self, key: &SessionKey) {
        self.sessions.remove(key);
    }

    /// 清理超过 [`SESSION_TTL`] 未续期的会话，返回被清掉的键。
    pub fn prune(&mut self, now_unix: u64) -> Vec<SessionKey> {
        let ttl = SESSION_TTL.as_secs();
        let stale: Vec<SessionKey> = self
            .sessions
            .iter()
            .filter(|(_, s)| now_unix.saturating_sub(s.last_seen_unix) > ttl)
            .map(|(k, _)| *k)
            .collect();
        for key in &stale {
            self.sessions.remove(key);
        }
        stale
    }
}

/// 每会话的包速限制（固定窗口）。
#[derive(Debug)]
pub struct PacketLimiter {
    window_start: Instant,
    count: u32,
    dropped: u32,
}

impl PacketLimiter {
    /// 新建限速器。
    pub fn new(now: Instant) -> Self {
        Self {
            window_start: now,
            count: 0,
            dropped: 0,
        }
    }

    /// 放行这个包吗？
    ///
    /// 窗口滚动时若上一窗口有丢包，记一条 warn——**每窗口最多一条**，
    /// 绝不每包一条（那本身就是一种放大攻击）。
    pub fn allow(&mut self, now: Instant) -> bool {
        if now.duration_since(self.window_start) >= Duration::from_secs(1) {
            if self.dropped > 0 {
                warn!(
                    dropped = self.dropped,
                    limit = MAX_PACKETS_PER_SEC,
                    "中继会话超过包速上限，已丢包"
                );
            }
            self.window_start = now;
            self.count = 0;
            self.dropped = 0;
        }
        if self.count >= MAX_PACKETS_PER_SEC {
            self.dropped = self.dropped.saturating_add(1);
            return false;
        }
        self.count += 1;
        true
    }
}

/// 在控制 socket 上提供中继服务，直到读取出错。
///
/// 认证失败、时钟偏差过大、策略不允许、类型不对的帧一律**静默丢弃**。
pub async fn serve(
    control: UdpSocket,
    relay_key: [u8; 32],
    policy: RelayPolicy,
) -> std::io::Result<()> {
    let mut table = RelayTable::new();
    let mut senders: HashMap<SessionKey, mpsc::Sender<SessionAddrs>> = HashMap::new();
    let mut buf = [0u8; 256];
    let mut pruner = tokio::time::interval(PRUNE_INTERVAL);

    loop {
        tokio::select! {
            _ = pruner.tick() => {
                for key in table.prune(unix_secs(SystemTime::now())) {
                    // drop 掉发送端 → 对应的转发任务读到 None 后自行退出
                    senders.remove(&key);
                    debug!("中继会话超时已关闭");
                }
            }
            received = control.recv_from(&mut buf) => {
                let (n, src) = received?;
                let SocketAddr::V6(src6) = src else {
                    continue; // hextet 是 IPv6-only 的
                };
                let Ok(frame) = RelayFrame::decode(&buf[..n], &relay_key) else {
                    continue;
                };
                let now_unix = unix_secs(SystemTime::now());
                if frame.seq.abs_diff(now_unix) > SEQ_SKEW_TOLERANCE_SECS {
                    debug!(seq = frame.seq, now = now_unix, "中继控制帧时间戳偏差过大");
                    continue;
                }
                if !policy.allows(frame.self_key.as_bytes()) {
                    debug!(peer = %frame.self_key.to_base64(), "中继策略不允许该节点");
                    continue;
                }
                let key = frame.session_key();
                let side = usize::from(frame.self_key.as_bytes() != &key[0]);

                match frame.kind {
                    RelayKind::Register => {
                        if frame.port == 0 {
                            // 没有 WG 端口就无法组装数据面地址（见 docs/protocol/relay.md C-0）
                            debug!("Register 没带 WG 监听端口，忽略");
                            continue;
                        }
                        if !table.contains(&key) {
                            for stale in table.prune(now_unix) {
                                senders.remove(&stale);
                            }
                            if table.len() >= MAX_SESSIONS {
                                warn!(
                                    sessions = table.len(),
                                    "中继会话数已达上限，拒绝新会话"
                                );
                                continue;
                            }
                            let bind = SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0);
                            let session_socket = match UdpSocket::bind(bind).await {
                                Ok(s) => s,
                                Err(e) => {
                                    warn!(error = %e, "为中继会话绑定 socket 失败");
                                    continue;
                                }
                            };
                            let port = match session_socket.local_addr() {
                                Ok(a) => a.port(),
                                Err(e) => {
                                    warn!(error = %e, "读取会话 socket 端口失败");
                                    continue;
                                }
                            };
                            if !table.insert(key, port, now_unix) {
                                continue;
                            }
                            let (tx, rx) = mpsc::channel::<SessionAddrs>(4);
                            senders.insert(key, tx);
                            info!(port, "中继会话已建立");
                            tokio::spawn(forward(session_socket, rx));
                        }
                        let data_addr = normalize(SocketAddrV6::new(*src6.ip(), frame.port, 0, 0));
                        if table.touch_addr(&key, side, data_addr, now_unix) {
                            info!(side, endpoint = %data_addr, "中继会话一侧地址就位/更新");
                        }
                        if let Some(tx) = senders.get(&key) {
                            // 通道满说明转发任务正忙，下一次续期会补上
                            let _ = tx.try_send(table.addrs(&key));
                        }
                        let ack = RelayFrame {
                            kind: RelayKind::RegisterAck,
                            port: table.port(&key).unwrap_or(0),
                            seq: now_unix,
                            self_key: frame.self_key.clone(),
                            peer_key: frame.peer_key.clone(),
                        };
                        if let Err(e) = control.send_to(&ack.encode(&relay_key), src).await {
                            debug!(error = %e, "回 RegisterAck 失败");
                        }
                    }
                    RelayKind::Unregister => {
                        if table.contains(&key) {
                            table.remove(&key);
                            senders.remove(&key);
                            info!("中继会话已按请求注销");
                        }
                    }
                    // 服务端不该收到 ack；静默丢弃
                    RelayKind::RegisterAck => continue,
                }
            }
        }
    }
}

/// 一对会话的转发循环：按源地址二选一，原样透传。
async fn forward(socket: UdpSocket, mut rx: mpsc::Receiver<SessionAddrs>) {
    let mut addrs: SessionAddrs = [None, None];
    let mut buf = vec![0u8; FORWARD_BUF];
    let mut limiter = PacketLimiter::new(Instant::now());

    loop {
        tokio::select! {
            update = rx.recv() => {
                match update {
                    Some(next) => addrs = next,
                    // 控制循环删掉了这个会话
                    None => {
                        debug!("中继会话结束，转发任务退出");
                        return;
                    }
                }
            }
            received = socket.recv_from(&mut buf) => {
                let (n, src) = match received {
                    Ok(v) => v,
                    Err(e) => {
                        debug!(error = %e, "中继会话 socket 读失败，结束会话");
                        return;
                    }
                };
                let SocketAddr::V6(src6) = src else { continue };
                // 控制帧不该出现在会话 socket 上；更重要的是绝不能把它当数据转发出去
                if is_relay_frame(&buf[..n]) {
                    continue;
                }
                if n == FORWARD_BUF {
                    debug!("数据报可能被截断（≥{FORWARD_BUF} 字节），丢弃");
                    continue;
                }
                let from = normalize(src6);
                let dst = if Some(from) == addrs[0] {
                    addrs[1]
                } else if Some(from) == addrs[1] {
                    addrs[0]
                } else {
                    // 会话还半开（只有一侧注册过），或者来自完全无关的地址
                    None
                };
                let Some(dst) = dst else { continue };
                if !limiter.allow(Instant::now()) {
                    continue;
                }
                if let Err(e) = socket.send_to(&buf[..n], SocketAddr::V6(dst)).await {
                    debug!(error = %e, "中继转发失败");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hextet_core::identity::{NodeIdentity, NodePublicKey};
    use hextet_core::relay::session_key_of;

    const KEY: [u8; 32] = [4u8; 32];

    fn id(seed: u8) -> NodeIdentity {
        NodeIdentity::from_seed(&[seed; 32])
    }

    fn ep(s: &str) -> SocketAddrV6 {
        s.parse().unwrap()
    }

    fn pair(x: u8, y: u8) -> SessionKey {
        session_key_of(id(x).public().as_bytes(), id(y).public().as_bytes())
    }

    #[test]
    fn table_tracks_two_sides_and_expires() {
        let mut table = RelayTable::new();
        let key = pair(2, 3);
        assert!(!table.contains(&key));
        assert!(table.is_empty());

        assert!(table.insert(key, 40000, 1000));
        assert_eq!(table.port(&key), Some(40000));
        assert_eq!(table.addrs(&key), [None, None]);
        assert_eq!(table.len(), 1);

        assert!(table.touch_addr(&key, 0, ep("[2001:db8::1]:4193"), 1000));
        assert!(table.touch_addr(&key, 1, ep("[2001:db8::2]:4193"), 1000));
        assert_eq!(
            table.addrs(&key),
            [
                Some(ep("[2001:db8::1]:4193")),
                Some(ep("[2001:db8::2]:4193"))
            ]
        );
        // 同一地址再来一次不算变化
        assert!(!table.touch_addr(&key, 0, ep("[2001:db8::1]:4193"), 1001));
        // 换了地址（换前缀）算变化
        assert!(table.touch_addr(&key, 0, ep("[2001:db8:9::1]:4193"), 1002));

        // 刚好到 TTL 不清，超过才清
        assert!(table.prune(1002 + SESSION_TTL.as_secs()).is_empty());
        assert_eq!(table.prune(1002 + SESSION_TTL.as_secs() + 1), vec![key]);
        assert!(table.is_empty());
        assert_eq!(table.port(&key), None);
        assert_eq!(table.addrs(&key), [None, None]);
        assert!(!table.touch_addr(&key, 0, ep("[2001:db8::1]:4193"), 2000));
    }

    #[test]
    fn table_is_bounded() {
        let mut table = RelayTable::new();
        for i in 0..MAX_SESSIONS {
            let key = [
                [u8::try_from(i % 251).unwrap(); 32],
                [(i / 251) as u8 + 1; 32],
            ];
            assert!(table.insert(key, 1234, 0), "第 {i} 个会话应能建立");
        }
        assert_eq!(table.len(), MAX_SESSIONS);
        assert!(
            !table.insert(pair(9, 10), 1234, 0),
            "表满时必须拒绝新会话，而不是驱逐旧会话"
        );
        assert_eq!(table.len(), MAX_SESSIONS);
    }

    #[test]
    fn table_remove_is_idempotent() {
        let mut table = RelayTable::new();
        let key = pair(2, 3);
        table.insert(key, 1, 0);
        table.remove(&key);
        table.remove(&key);
        assert!(table.is_empty());
    }

    #[test]
    fn packet_limiter_caps_per_window_and_resets() {
        let t0 = Instant::now();
        let mut limiter = PacketLimiter::new(t0);
        for i in 0..MAX_PACKETS_PER_SEC {
            assert!(limiter.allow(t0), "第 {i} 个包应放行");
        }
        assert!(!limiter.allow(t0), "超过上限必须丢弃");
        assert!(!limiter.allow(t0 + Duration::from_millis(999)));
        // 新窗口重置
        assert!(limiter.allow(t0 + Duration::from_millis(1_001)));
    }

    #[test]
    fn policy_allowlist_only_admits_listed_keys() {
        let a = *id(2).public().as_bytes();
        let b = *id(3).public().as_bytes();
        assert!(RelayPolicy::AnyMember.allows(&a));
        let policy = RelayPolicy::Allowlist(vec![a]);
        assert!(policy.allows(&a));
        assert!(!policy.allows(&b));
    }

    // ---- loopback 端到端 ----

    /// 启动一个中继，返回它的控制地址。
    async fn spawn_relay(policy: RelayPolicy) -> SocketAddr {
        let control = UdpSocket::bind("[::1]:0").await.unwrap();
        let addr = control.local_addr().unwrap();
        tokio::spawn(async move { serve(control, KEY, policy).await });
        addr
    }

    /// 模拟一个节点：控制 socket（临时端口）+ "WG" socket（它的监听端口）。
    struct Node {
        identity: NodeIdentity,
        ctrl: UdpSocket,
        wg: UdpSocket,
        wg_port: u16,
    }

    async fn node(seed: u8) -> Node {
        let ctrl = UdpSocket::bind("[::1]:0").await.unwrap();
        let wg = UdpSocket::bind("[::1]:0").await.unwrap();
        let wg_port = wg.local_addr().unwrap().port();
        Node {
            identity: id(seed),
            ctrl,
            wg,
            wg_port,
        }
    }

    /// 发一帧控制帧。
    async fn send_frame(node: &Node, relay: SocketAddr, kind: RelayKind, peer: &NodePublicKey) {
        let frame = RelayFrame {
            kind,
            port: node.wg_port,
            seq: unix_secs(SystemTime::now()),
            self_key: node.identity.public(),
            peer_key: peer.clone(),
        };
        node.ctrl.send_to(&frame.encode(&KEY), relay).await.unwrap();
    }

    /// 注册并等 ack，返回中继分配的会话端口。
    async fn register(node: &Node, relay: SocketAddr, peer: &NodePublicKey) -> u16 {
        send_frame(node, relay, RelayKind::Register, peer).await;
        let mut buf = [0u8; 256];
        let (n, _) = tokio::time::timeout(Duration::from_secs(2), node.ctrl.recv_from(&mut buf))
            .await
            .expect("2s 内应收到 RegisterAck")
            .unwrap();
        let ack = RelayFrame::decode(&buf[..n], &KEY).unwrap();
        assert_eq!(ack.kind, RelayKind::RegisterAck);
        // ack 原样回带请求里的两个公钥，客户端据此把 ack 与自己的请求配对
        assert_eq!(ack.self_key, node.identity.public());
        assert_eq!(&ack.peer_key, peer);
        assert_ne!(ack.port, 0);
        ack.port
    }

    /// 从 WG socket 发一个"数据包"，返回对端收到的内容。
    async fn expect_relayed(from: &Node, to: &Node, session: u16, payload: &[u8]) {
        let target: SocketAddr = format!("[::1]:{session}").parse().unwrap();
        from.wg.send_to(payload, target).await.unwrap();
        let mut buf = [0u8; 2048];
        let (n, src) = tokio::time::timeout(Duration::from_secs(2), to.wg.recv_from(&mut buf))
            .await
            .expect("2s 内应收到转发的数据")
            .unwrap();
        assert_eq!(&buf[..n], payload);
        // 转发后源地址是中继的会话端口——对端的 WireGuard 正是据此把 endpoint
        // 设成中继（roaming），这一条不成立整个中继就没意义
        assert_eq!(src.port(), session);
    }

    #[tokio::test]
    async fn relays_payload_in_both_directions() {
        let relay = spawn_relay(RelayPolicy::AnyMember).await;
        let a = node(2).await;
        let b = node(3).await;

        let port_a = register(&a, relay, &b.identity.public()).await;
        let port_b = register(&b, relay, &a.identity.public()).await;
        assert_eq!(port_a, port_b, "同一对会话必须拿到同一个端口");

        expect_relayed(&a, &b, port_a, b"a-to-b").await;
        expect_relayed(&b, &a, port_a, b"b-to-a").await;
    }

    #[tokio::test]
    async fn half_open_session_forwards_nothing() {
        let relay = spawn_relay(RelayPolicy::AnyMember).await;
        let a = node(2).await;
        let b = node(3).await;

        // 只有 a 注册：b 从未注册过，中继不知道它在哪
        let port = register(&a, relay, &b.identity.public()).await;
        let target: SocketAddr = format!("[::1]:{port}").parse().unwrap();
        a.wg.send_to(b"nobody-home", target).await.unwrap();

        let mut buf = [0u8; 256];
        let got = tokio::time::timeout(Duration::from_millis(400), b.wg.recv_from(&mut buf)).await;
        assert!(got.is_err(), "半开会话不该转发任何东西，却收到了 {got:?}");
    }

    #[tokio::test]
    async fn bad_mac_gets_no_ack() {
        let relay = spawn_relay(RelayPolicy::AnyMember).await;
        let a = node(2).await;
        let b = node(3).await;

        let frame = RelayFrame {
            kind: RelayKind::Register,
            port: a.wg_port,
            seq: unix_secs(SystemTime::now()),
            self_key: a.identity.public(),
            peer_key: b.identity.public(),
        };
        // 用错的密钥签
        a.ctrl
            .send_to(&frame.encode(&[9u8; 32]), relay)
            .await
            .unwrap();
        // 完全不是控制帧
        a.ctrl.send_to(b"hello", relay).await.unwrap();

        let mut buf = [0u8; 256];
        let got =
            tokio::time::timeout(Duration::from_millis(400), a.ctrl.recv_from(&mut buf)).await;
        assert!(got.is_err(), "中继不该回任何东西，却收到了 {got:?}");
    }

    #[tokio::test]
    async fn stale_seq_is_rejected() {
        let relay = spawn_relay(RelayPolicy::AnyMember).await;
        let a = node(2).await;
        let b = node(3).await;

        let frame = RelayFrame {
            kind: RelayKind::Register,
            port: a.wg_port,
            // 一小时前的帧：重放窗口之外
            seq: unix_secs(SystemTime::now()) - 3600,
            self_key: a.identity.public(),
            peer_key: b.identity.public(),
        };
        a.ctrl.send_to(&frame.encode(&KEY), relay).await.unwrap();
        let mut buf = [0u8; 256];
        let got =
            tokio::time::timeout(Duration::from_millis(400), a.ctrl.recv_from(&mut buf)).await;
        assert!(got.is_err(), "陈旧的帧不该被接受，却拿到了 {got:?}");
    }

    #[tokio::test]
    async fn unregister_stops_forwarding() {
        let relay = spawn_relay(RelayPolicy::AnyMember).await;
        let a = node(2).await;
        let b = node(3).await;
        let port = register(&a, relay, &b.identity.public()).await;
        register(&b, relay, &a.identity.public()).await;
        expect_relayed(&a, &b, port, b"still-here").await;

        send_frame(&a, relay, RelayKind::Unregister, &b.identity.public()).await;
        // 给控制循环一点时间处理注销
        tokio::time::sleep(Duration::from_millis(200)).await;

        let target: SocketAddr = format!("[::1]:{port}").parse().unwrap();
        a.wg.send_to(b"after-unregister", target).await.unwrap();
        let mut buf = [0u8; 256];
        let got = tokio::time::timeout(Duration::from_millis(400), b.wg.recv_from(&mut buf)).await;
        assert!(got.is_err(), "注销后不该再转发，却收到了 {got:?}");
    }

    #[tokio::test]
    async fn control_frames_are_not_forwarded_as_data() {
        let relay = spawn_relay(RelayPolicy::AnyMember).await;
        let a = node(2).await;
        let b = node(3).await;
        let port = register(&a, relay, &b.identity.public()).await;
        register(&b, relay, &a.identity.public()).await;

        // 往会话端口上打一个合法的控制帧：绝不能被当数据转发给对端
        let frame = RelayFrame {
            kind: RelayKind::Register,
            port: a.wg_port,
            seq: unix_secs(SystemTime::now()),
            self_key: a.identity.public(),
            peer_key: b.identity.public(),
        };
        let target: SocketAddr = format!("[::1]:{port}").parse().unwrap();
        a.wg.send_to(&frame.encode(&KEY), target).await.unwrap();

        let mut buf = [0u8; 256];
        let got = tokio::time::timeout(Duration::from_millis(400), b.wg.recv_from(&mut buf)).await;
        assert!(got.is_err(), "控制帧不该被当数据转发，对端却收到了 {got:?}");

        // 而正常数据仍然通（会话没被这条帧破坏）
        expect_relayed(&a, &b, port, b"still-works").await;
    }

    #[tokio::test]
    async fn allowlist_blocks_unlisted_nodes() {
        let a = node(2).await;
        let b = node(3).await;
        let relay = spawn_relay(RelayPolicy::Allowlist(vec![
            *a.identity.public().as_bytes(),
        ]))
        .await;

        // a 在白名单里：能拿到 ack
        let port = register(&a, relay, &b.identity.public()).await;
        // b 不在：注册被忽略，会话保持半开
        send_frame(&b, relay, RelayKind::Register, &a.identity.public()).await;
        let mut buf = [0u8; 256];
        assert!(
            tokio::time::timeout(Duration::from_millis(400), b.ctrl.recv_from(&mut buf))
                .await
                .is_err(),
            "白名单外的节点不该拿到 ack"
        );
        let target: SocketAddr = format!("[::1]:{port}").parse().unwrap();
        a.wg.send_to(b"nope", target).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(400), b.wg.recv_from(&mut buf))
                .await
                .is_err(),
            "半开会话不该转发"
        );
    }
}
