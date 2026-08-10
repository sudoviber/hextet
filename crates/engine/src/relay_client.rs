//! 中继客户端：注册一对会话、续期、注销（协议规范：docs/protocol/relay.md）。
//!
//! 注册是一次请求-应答：我们把「我是谁、要跟谁通、我的 WireGuard 监听端口是几」告诉
//! 中继，中继回带它为这对会话分配的端口。拿到端口才知道该把对端的 WG endpoint 设成
//! 什么——所以这一步必须等到应答，不能乐观假设。

use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use std::time::{Duration, Instant, SystemTime};

use hextet_core::identity::NodePublicKey;
use hextet_core::relay::{RelayFrame, RelayKind};
use tokio::net::UdpSocket;
use tracing::debug;

use crate::candidates::normalize;
use crate::state::unix_secs;

/// 没收到应答时的重发间隔。
pub const RETRY_INTERVAL: Duration = Duration::from_millis(700);
/// 放弃注册前的总等待时间。
pub const REGISTER_TIMEOUT: Duration = Duration::from_secs(5);
/// 续期节奏（服务端会话 TTL 是 180s，30s 一次留足 6 次重试余量）。
pub const REGISTER_INTERVAL: Duration = crate::relay_server::REGISTER_INTERVAL;

/// 一条已建立的中继会话。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelaySession {
    /// 中继为这对会话分配的 endpoint——把对端的 WireGuard endpoint 设成它。
    pub endpoint: SocketAddrV6,
    /// 实际应答的中继控制地址（续期与注销都发给它）。
    pub control: SocketAddrV6,
}

/// 向中继注册一对会话（默认超时）。
pub async fn register(
    control_addrs: &[SocketAddrV6],
    self_key: &NodePublicKey,
    peer_key: &NodePublicKey,
    wg_listen_port: u16,
    relay_key: &[u8; 32],
) -> Option<RelaySession> {
    register_with_timeout(
        control_addrs,
        self_key,
        peer_key,
        wg_listen_port,
        relay_key,
        REGISTER_TIMEOUT,
    )
    .await
}

/// 同 [`register`]，但可指定总超时（测试用）。
///
/// 每轮向**所有**候选控制地址各发一帧，然后等一个 [`RETRY_INTERVAL`]；
/// 收到与本次请求匹配的 `RegisterAck` 即返回。全部超时返回 `None`——
/// 调用方据此如实报告"中继不可用"，绝不假装已经在中继。
pub async fn register_with_timeout(
    control_addrs: &[SocketAddrV6],
    self_key: &NodePublicKey,
    peer_key: &NodePublicKey,
    wg_listen_port: u16,
    relay_key: &[u8; 32],
    timeout: Duration,
) -> Option<RelaySession> {
    if control_addrs.is_empty() || wg_listen_port == 0 {
        return None;
    }
    let socket = UdpSocket::bind(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0))
        .await
        .inspect_err(|e| debug!(error = %e, "绑定中继注册 socket 失败"))
        .ok()?;

    let deadline = Instant::now() + timeout;
    let mut buf = [0u8; 256];
    while Instant::now() < deadline {
        let frame = RelayFrame {
            kind: RelayKind::Register,
            port: wg_listen_port,
            seq: unix_secs(SystemTime::now()),
            self_key: self_key.clone(),
            peer_key: peer_key.clone(),
        };
        let bytes = frame.encode(relay_key);
        for control in control_addrs {
            if let Err(e) = socket.send_to(&bytes, SocketAddr::V6(*control)).await {
                debug!(control = %control, error = %e, "发送中继注册失败");
            }
        }

        let Ok(Ok((n, src))) =
            tokio::time::timeout(RETRY_INTERVAL, socket.recv_from(&mut buf)).await
        else {
            continue; // 超时或读错：下一轮重发
        };
        let SocketAddr::V6(src6) = src else { continue };
        let Ok(ack) = RelayFrame::decode(&buf[..n], relay_key) else {
            continue;
        };
        // 必须与本次请求配对：类型、两个公钥、端口非零
        if ack.kind != RelayKind::RegisterAck
            || &ack.self_key != self_key
            || &ack.peer_key != peer_key
            || ack.port == 0
        {
            continue;
        }
        return Some(RelaySession {
            endpoint: SocketAddrV6::new(*src6.ip(), ack.port, 0, 0),
            control: normalize(src6),
        });
    }
    None
}

/// 注销一对会话（尽力而为，不等应答）。
///
/// 直连升级成功后调用它，让中继立刻释放那个会话的 socket 与任务，
/// 而不是等 180s TTL。发不出去也无所谓——TTL 兜底。
pub async fn unregister(
    control: SocketAddrV6,
    self_key: &NodePublicKey,
    peer_key: &NodePublicKey,
    wg_listen_port: u16,
    relay_key: &[u8; 32],
) {
    let Ok(socket) = UdpSocket::bind(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0)).await
    else {
        return;
    };
    let frame = RelayFrame {
        kind: RelayKind::Unregister,
        port: wg_listen_port,
        seq: unix_secs(SystemTime::now()),
        self_key: self_key.clone(),
        peer_key: peer_key.clone(),
    };
    if let Err(e) = socket
        .send_to(&frame.encode(relay_key), SocketAddr::V6(control))
        .await
    {
        debug!(control = %control, error = %e, "发送中继注销失败（TTL 会兜底）");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay_server::{self, RelayPolicy};
    use hextet_core::identity::NodeIdentity;

    const KEY: [u8; 32] = [4u8; 32];

    fn id(seed: u8) -> NodeIdentity {
        NodeIdentity::from_seed(&[seed; 32])
    }

    async fn spawn_relay() -> SocketAddrV6 {
        let control = UdpSocket::bind("[::1]:0").await.unwrap();
        let SocketAddr::V6(addr) = control.local_addr().unwrap() else {
            unreachable!("bound to an IPv6 address")
        };
        tokio::spawn(
            async move { relay_server::serve(control, KEY, RelayPolicy::AnyMember).await },
        );
        addr
    }

    /// 一个节点的 "WireGuard socket"：它的端口就是要告诉中继的监听端口。
    async fn wg_socket() -> (UdpSocket, u16) {
        let sock = UdpSocket::bind("[::1]:0").await.unwrap();
        let port = sock.local_addr().unwrap().port();
        (sock, port)
    }

    #[tokio::test]
    async fn register_yields_a_working_session_endpoint() {
        let relay = spawn_relay().await;
        let (a, b) = (id(2), id(3));
        let (wg_a, port_a) = wg_socket().await;
        let (wg_b, port_b) = wg_socket().await;

        let sess_a = register(&[relay], &a.public(), &b.public(), port_a, &KEY)
            .await
            .expect("a 应注册成功");
        let sess_b = register(&[relay], &b.public(), &a.public(), port_b, &KEY)
            .await
            .expect("b 应注册成功");
        // 同一对会话：两侧拿到同一个 endpoint
        assert_eq!(sess_a.endpoint, sess_b.endpoint);
        assert_eq!(sess_a.control, relay);
        // 会话端口不是控制端口
        assert_ne!(sess_a.endpoint.port(), relay.port());

        // 拿这个 endpoint 当 WG endpoint 用：包真的能到对端
        wg_a.send_to(b"through-the-relay", SocketAddr::V6(sess_a.endpoint))
            .await
            .unwrap();
        let mut buf = [0u8; 256];
        let (n, src) = tokio::time::timeout(Duration::from_secs(2), wg_b.recv_from(&mut buf))
            .await
            .expect("2s 内应收到中继过来的数据")
            .unwrap();
        assert_eq!(&buf[..n], b"through-the-relay");
        assert_eq!(src.port(), sess_a.endpoint.port());
    }

    #[tokio::test]
    async fn register_gives_up_when_nobody_answers() {
        // 绑一个 socket 拿到端口后立刻丢掉：这个端口上没人应答
        let dead = {
            let s = UdpSocket::bind("[::1]:0").await.unwrap();
            let SocketAddr::V6(a) = s.local_addr().unwrap() else {
                unreachable!()
            };
            a
        };
        let got = register_with_timeout(
            &[dead],
            &id(2).public(),
            &id(3).public(),
            4193,
            &KEY,
            Duration::from_millis(300),
        )
        .await;
        assert!(got.is_none(), "没人应答时必须如实返回 None");
    }

    #[tokio::test]
    async fn wrong_relay_key_yields_none() {
        let relay = spawn_relay().await;
        let got = register_with_timeout(
            &[relay],
            &id(2).public(),
            &id(3).public(),
            4193,
            &[9u8; 32],
            Duration::from_millis(300),
        )
        .await;
        assert!(got.is_none(), "密钥不对时中继不该应答");
    }

    #[tokio::test]
    async fn empty_inputs_are_rejected_without_touching_the_network() {
        assert!(
            register(&[], &id(2).public(), &id(3).public(), 4193, &KEY)
                .await
                .is_none()
        );
        let relay = spawn_relay().await;
        // WG 端口为 0 时中继无法组装数据面地址，客户端提前拒绝
        assert!(
            register_with_timeout(
                &[relay],
                &id(2).public(),
                &id(3).public(),
                0,
                &KEY,
                Duration::from_millis(300)
            )
            .await
            .is_none()
        );
    }

    #[tokio::test]
    async fn unregister_releases_the_session() {
        let relay = spawn_relay().await;
        let (a, b) = (id(2), id(3));
        let (wg_a, port_a) = wg_socket().await;
        let (wg_b, port_b) = wg_socket().await;
        let sess = register(&[relay], &a.public(), &b.public(), port_a, &KEY)
            .await
            .unwrap();
        register(&[relay], &b.public(), &a.public(), port_b, &KEY)
            .await
            .unwrap();

        unregister(sess.control, &a.public(), &b.public(), port_a, &KEY).await;
        tokio::time::sleep(Duration::from_millis(200)).await;

        wg_a.send_to(b"after-unregister", SocketAddr::V6(sess.endpoint))
            .await
            .unwrap();
        let mut buf = [0u8; 256];
        assert!(
            tokio::time::timeout(Duration::from_millis(400), wg_b.recv_from(&mut buf))
                .await
                .is_err(),
            "注销后中继不该再转发"
        );
    }
}
