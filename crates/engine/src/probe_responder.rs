//! doctor 探针响应器（协议规范：docs/protocol/doctor-probe.md）。
//!
//! daemon 常开这个 socket，让网络内其他节点能请它"回探"，从而判定对方的入站
//! 策略。它只是一个 UDP socket：不改任何防火墙规则，不放行任何入站流量。

use std::collections::HashMap;
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use std::time::{Duration, Instant};

use hextet_core::probe::{ProbeKind, ProbePacket};
use tokio::net::UdpSocket;
use tracing::debug;

/// 收到 Request 后延迟多久发 Unsolicited。
///
/// 给客户端留出把"专门收 Unsolicited 的 socket"准备好的时间；同时让两个回包
/// 在时间上明显分开，便于抓包排查。
pub const UNSOLICITED_DELAY: Duration = Duration::from_millis(300);

/// 同一源 IP 两次请求之间的最小间隔。
pub const MIN_REQUEST_INTERVAL: Duration = Duration::from_secs(1);

/// 限速表条目上限（防止被大量伪造源 IP 撑爆内存）。
const RATE_TABLE_MAX: usize = 64;

/// 清理限速表时丢弃多久之前的条目。
const RATE_ENTRY_TTL: Duration = Duration::from_secs(60);

/// 按源 IP 限速的简易计数器。
#[derive(Debug, Default)]
pub struct RateLimiter {
    seen: HashMap<Ipv6Addr, Instant>,
}

impl RateLimiter {
    /// 新建空限速器。
    pub fn new() -> Self {
        Self {
            seen: HashMap::new(),
        }
    }

    /// 当前跟踪的源 IP 数量（可观测性/测试用）。
    pub fn tracked(&self) -> usize {
        self.seen.len()
    }

    /// 是否放行来自 `ip` 的这次请求。
    pub fn allow(&mut self, ip: Ipv6Addr, now: Instant) -> bool {
        if let Some(prev) = self.seen.get(&ip)
            && now.duration_since(*prev) < MIN_REQUEST_INTERVAL
        {
            return false;
        }
        if self.seen.len() >= RATE_TABLE_MAX {
            self.seen
                .retain(|_, t| now.duration_since(*t) < RATE_ENTRY_TTL);
            // 清理后仍然满：整表清空。宁可让限速短暂放宽，也不让表无界增长——
            // 报文本身只有 32 字节且需要有效 MAC，放宽的风险远小于内存耗尽。
            if self.seen.len() >= RATE_TABLE_MAX {
                self.seen.clear();
            }
        }
        self.seen.insert(ip, now);
        true
    }
}

/// 在给定 socket 上提供探针服务，直到读取出错。
///
/// 校验失败、类型不对、限速命中的包一律静默丢弃——不给探测者任何
/// "这个地址上有 hextet 节点"的信号。
pub async fn serve(socket: UdpSocket, probe_key: [u8; 32]) -> std::io::Result<()> {
    let mut limiter = RateLimiter::new();
    let mut buf = [0u8; 128];
    loop {
        let (n, src) = socket.recv_from(&mut buf).await?;
        let SocketAddr::V6(src6) = src else {
            // hextet 是 IPv6-only 的
            continue;
        };
        let Ok(packet) = ProbePacket::decode(&buf[..n], &probe_key) else {
            continue;
        };
        if packet.kind != ProbeKind::Request {
            continue;
        }
        if !limiter.allow(*src6.ip(), Instant::now()) {
            debug!(peer = %src6.ip(), "探针请求被限速");
            continue;
        }

        // ① 已请求路径：从本 socket 直接回，命中对方的出站 state
        let response = ProbePacket {
            kind: ProbeKind::Response,
            nonce: packet.nonce,
            reply_port: 0,
        }
        .encode(&probe_key);
        if let Err(e) = socket.send_to(&response, src).await {
            debug!(peer = %src6.ip(), error = %e, "回 Response 失败");
        }

        // ② 未经请求路径：延迟后用新的临时 socket（另一个源端口）发向 reply_port
        if packet.reply_port != 0 {
            let target = SocketAddrV6::new(*src6.ip(), packet.reply_port, 0, src6.scope_id());
            let nonce = packet.nonce;
            tokio::spawn(async move {
                tokio::time::sleep(UNSOLICITED_DELAY).await;
                match UdpSocket::bind("[::]:0").await {
                    Ok(sock) => {
                        let unsolicited = ProbePacket {
                            kind: ProbeKind::Unsolicited,
                            nonce,
                            reply_port: 0,
                        }
                        .encode(&probe_key);
                        if let Err(e) = sock.send_to(&unsolicited, SocketAddr::V6(target)).await {
                            debug!(target = %target, error = %e, "发 Unsolicited 失败");
                        }
                    }
                    Err(e) => debug!(error = %e, "绑定临时 socket 失败"),
                }
            });
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> [u8; 32] {
        [7u8; 32]
    }

    #[test]
    fn rate_limiter_allows_then_denies_then_allows() {
        let mut limiter = RateLimiter::new();
        let ip: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let t0 = Instant::now();
        assert!(limiter.allow(ip, t0));
        assert!(!limiter.allow(ip, t0 + Duration::from_millis(500)));
        assert!(!limiter.allow(ip, t0 + Duration::from_millis(999)));
        assert!(limiter.allow(ip, t0 + Duration::from_millis(1_001)));
    }

    #[test]
    fn rate_limiter_tracks_ips_independently() {
        let mut limiter = RateLimiter::new();
        let t0 = Instant::now();
        assert!(limiter.allow("2001:db8::1".parse().unwrap(), t0));
        assert!(limiter.allow("2001:db8::2".parse().unwrap(), t0));
        assert!(!limiter.allow("2001:db8::1".parse().unwrap(), t0));
    }

    #[test]
    fn rate_limiter_table_stays_bounded() {
        let mut limiter = RateLimiter::new();
        let t0 = Instant::now();
        for i in 0..500u32 {
            let ip: Ipv6Addr = format!("2001:db8::{i:x}").parse().unwrap();
            limiter.allow(ip, t0 + Duration::from_millis(u64::from(i)));
        }
        assert!(
            limiter.tracked() <= RATE_TABLE_MAX,
            "table grew to {}",
            limiter.tracked()
        );
    }

    /// 端到端（loopback，无需 root）：Request → Response + Unsolicited。
    #[tokio::test]
    async fn responder_answers_and_sends_unsolicited() {
        let responder = UdpSocket::bind("[::1]:0").await.unwrap();
        let responder_addr = responder.local_addr().unwrap();
        tokio::spawn(async move { serve(responder, key()).await });

        let s1 = UdpSocket::bind("[::1]:0").await.unwrap();
        let s2 = UdpSocket::bind("[::1]:0").await.unwrap();
        let reply_port = s2.local_addr().unwrap().port();

        let request = ProbePacket {
            kind: ProbeKind::Request,
            nonce: 0xabcd,
            reply_port,
        }
        .encode(&key());
        s1.send_to(&request, responder_addr).await.unwrap();

        // ① 已请求路径：Response 回到 s1
        let mut buf = [0u8; 128];
        let (n, _) = tokio::time::timeout(Duration::from_secs(2), s1.recv_from(&mut buf))
            .await
            .expect("2s 内应收到 Response")
            .unwrap();
        let resp = ProbePacket::decode(&buf[..n], &key()).unwrap();
        assert_eq!(resp.kind, ProbeKind::Response);
        assert_eq!(resp.nonce, 0xabcd);

        // ② 未经请求路径：Unsolicited 到达 s2（loopback 无防火墙，必达）
        let (n, src) = tokio::time::timeout(Duration::from_secs(2), s2.recv_from(&mut buf))
            .await
            .expect("2s 内应收到 Unsolicited")
            .unwrap();
        let unsol = ProbePacket::decode(&buf[..n], &key()).unwrap();
        assert_eq!(unsol.kind, ProbeKind::Unsolicited);
        assert_eq!(unsol.nonce, 0xabcd);
        // 必须来自另一个源端口，否则它会命中客户端的出站 state，测不出"未经请求"
        assert_ne!(src.port(), responder_addr.port());
    }

    #[tokio::test]
    async fn responder_ignores_bad_mac_and_non_request() {
        let responder = UdpSocket::bind("[::1]:0").await.unwrap();
        let responder_addr = responder.local_addr().unwrap();
        tokio::spawn(async move { serve(responder, key()).await });

        let s1 = UdpSocket::bind("[::1]:0").await.unwrap();

        // 密钥不对
        let bad = ProbePacket {
            kind: ProbeKind::Request,
            nonce: 1,
            reply_port: 0,
        }
        .encode(&[9u8; 32]);
        s1.send_to(&bad, responder_addr).await.unwrap();

        // 类型不是 Request
        let wrong_kind = ProbePacket {
            kind: ProbeKind::Response,
            nonce: 2,
            reply_port: 0,
        }
        .encode(&key());
        s1.send_to(&wrong_kind, responder_addr).await.unwrap();

        // 完全不是探针
        s1.send_to(b"hello", responder_addr).await.unwrap();

        let mut buf = [0u8; 128];
        let got = tokio::time::timeout(Duration::from_millis(500), s1.recv_from(&mut buf)).await;
        assert!(got.is_err(), "响应器不该回任何东西，却收到了 {got:?}");
    }

    #[tokio::test]
    async fn responder_skips_unsolicited_when_reply_port_is_zero() {
        let responder = UdpSocket::bind("[::1]:0").await.unwrap();
        let responder_addr = responder.local_addr().unwrap();
        tokio::spawn(async move { serve(responder, key()).await });

        let s1 = UdpSocket::bind("[::1]:0").await.unwrap();
        let request = ProbePacket {
            kind: ProbeKind::Request,
            nonce: 5,
            reply_port: 0,
        }
        .encode(&key());
        s1.send_to(&request, responder_addr).await.unwrap();

        let mut buf = [0u8; 128];
        // 只应收到一个 Response，之后没有第二个包
        let (n, _) = tokio::time::timeout(Duration::from_secs(2), s1.recv_from(&mut buf))
            .await
            .expect("应收到 Response")
            .unwrap();
        assert_eq!(
            ProbePacket::decode(&buf[..n], &key()).unwrap().kind,
            ProbeKind::Response
        );
        let extra = tokio::time::timeout(Duration::from_millis(600), s1.recv_from(&mut buf)).await;
        assert!(extra.is_err(), "reply_port=0 时不该有 Unsolicited");
    }
}
