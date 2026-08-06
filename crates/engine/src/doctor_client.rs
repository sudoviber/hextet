//! doctor 探针客户端：请对端回探，收集证据，得出本机入站可达性。

use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use std::time::Duration;

use hextet_core::doctor::{ProbeEvidence, Reachability, classify};
use hextet_core::probe::{ProbeKind, ProbePacket};
use rand_core::RngCore as _;
use tokio::net::UdpSocket;
use tracing::debug;

/// Request 的重发间隔（容忍单个包丢失）。
pub const REQUEST_RETRY_INTERVAL: Duration = Duration::from_millis(700);

/// 一次探测的完整结果。
#[derive(Debug, Clone)]
pub struct ProbeOutcome {
    /// 结论。
    pub reachability: Reachability,
    /// 得出结论所依据的证据。
    pub evidence: ProbeEvidence,
    /// 被探测的对端探针地址。
    pub target: SocketAddrV6,
    /// 本机的公网 IPv6 地址列表。
    pub global_addresses: Vec<Ipv6Addr>,
}

/// 请 `target` 上的对端响应器回探本机。
///
/// 绑两个 socket：`s1` 发 Request 并收 Response（走本机已建立的出站 state），
/// `s2` **只收不发**，其端口写进 Request 的 `reply_port`——对端会从另一个源端口
/// 向它发一个未经请求的包，只有本机放行未经请求的入站时才能收到。
///
/// `global_addresses` 由调用方提供（`hextet_platform::list_global_ipv6`），
/// 这样本函数保持平台无关、可在任何机器上用 loopback 测试。
pub async fn probe_peer(
    target: SocketAddrV6,
    probe_key: &[u8; 32],
    timeout: Duration,
    global_addresses: Vec<Ipv6Addr>,
) -> std::io::Result<ProbeOutcome> {
    let s1 = UdpSocket::bind("[::]:0").await?;
    let s2 = UdpSocket::bind("[::]:0").await?;
    let reply_port = s2.local_addr()?.port();
    let nonce = rand_core::OsRng.next_u64();
    let request = ProbePacket {
        kind: ProbeKind::Request,
        nonce,
        reply_port,
    }
    .encode(probe_key);

    let mut solicited_ok = false;
    let mut unsolicited_ok = false;
    let mut buf1 = [0u8; 128];
    let mut buf2 = [0u8; 128];

    // interval 的第一次 tick 立即触发，因此第一个 Request 由循环发出
    let mut retry = tokio::time::interval(REQUEST_RETRY_INTERVAL);
    let deadline = tokio::time::sleep(timeout);
    tokio::pin!(deadline);

    while !(solicited_ok && unsolicited_ok) {
        tokio::select! {
            _ = &mut deadline => break,
            _ = retry.tick() => {
                if !solicited_ok
                    && let Err(e) = s1.send_to(&request, SocketAddr::V6(target)).await
                {
                    debug!(target = %target, error = %e, "发 Request 失败");
                }
            }
            received = s1.recv_from(&mut buf1) => match received {
                Ok((n, _)) => {
                    if let Ok(p) = ProbePacket::decode(&buf1[..n], probe_key)
                        && p.kind == ProbeKind::Response
                        && p.nonce == nonce
                    {
                        solicited_ok = true;
                    }
                }
                // 目标端口无人监听时内核会把 ICMP port-unreachable 转成一次
                // recv 错误：这正是"没人应答"的证据，继续等超时而不是提前返回
                Err(e) => debug!(error = %e, "s1 收包出错（继续等待）"),
            },
            received = s2.recv_from(&mut buf2) => match received {
                Ok((n, _)) => {
                    if let Ok(p) = ProbePacket::decode(&buf2[..n], probe_key)
                        && p.kind == ProbeKind::Unsolicited
                        && p.nonce == nonce
                    {
                        unsolicited_ok = true;
                    }
                }
                Err(e) => debug!(error = %e, "s2 收包出错（继续等待）"),
            },
        }
    }

    let evidence = ProbeEvidence {
        has_global_ipv6: !global_addresses.is_empty(),
        solicited_ok,
        unsolicited_ok,
    };
    Ok(ProbeOutcome {
        reachability: classify(&evidence),
        evidence,
        target,
        global_addresses,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> [u8; 32] {
        [11u8; 32]
    }

    fn localhost() -> Vec<Ipv6Addr> {
        // classify 只看"有没有全局地址"，loopback 测试里塞一个假的文档地址即可
        vec!["2001:db8::1".parse().unwrap()]
    }

    /// loopback 上没有任何防火墙：两条路径都应通 → open。
    #[tokio::test]
    async fn probe_against_real_responder_reports_open() {
        let responder = tokio::net::UdpSocket::bind("[::1]:0").await.unwrap();
        let port = responder.local_addr().unwrap().port();
        tokio::spawn(async move { crate::probe_responder::serve(responder, key()).await });

        let target = SocketAddrV6::new("::1".parse().unwrap(), port, 0, 0);
        let outcome = probe_peer(target, &key(), Duration::from_secs(3), localhost())
            .await
            .unwrap();
        assert!(outcome.evidence.solicited_ok, "{outcome:?}");
        assert!(outcome.evidence.unsolicited_ok, "{outcome:?}");
        assert_eq!(outcome.reachability, Reachability::Open);
        assert_eq!(outcome.target, target);
    }

    /// 没人应答（对端没跑 daemon / 不可达 / 本机出站被拦）→ blocked。
    #[tokio::test]
    async fn probe_against_nobody_reports_blocked() {
        // 先绑再释放，拿一个几乎确定没人监听的端口
        let port = {
            let s = tokio::net::UdpSocket::bind("[::1]:0").await.unwrap();
            s.local_addr().unwrap().port()
        };
        let target = SocketAddrV6::new("::1".parse().unwrap(), port, 0, 0);
        let outcome = probe_peer(target, &key(), Duration::from_millis(800), localhost())
            .await
            .unwrap();
        assert!(!outcome.evidence.solicited_ok);
        assert!(!outcome.evidence.unsolicited_ok);
        assert_eq!(outcome.reachability, Reachability::Blocked);
    }

    /// 密钥不一致时对端静默丢弃 → 客户端什么都收不到 → blocked。
    #[tokio::test]
    async fn mismatched_network_key_reports_blocked() {
        let responder = tokio::net::UdpSocket::bind("[::1]:0").await.unwrap();
        let port = responder.local_addr().unwrap().port();
        tokio::spawn(async move { crate::probe_responder::serve(responder, [99u8; 32]).await });

        let target = SocketAddrV6::new("::1".parse().unwrap(), port, 0, 0);
        let outcome = probe_peer(target, &key(), Duration::from_millis(800), localhost())
            .await
            .unwrap();
        assert_eq!(outcome.reachability, Reachability::Blocked);
    }

    /// 本机没有全局 IPv6 时，无论探测结果如何都先报 no-ipv6。
    #[tokio::test]
    async fn no_global_address_reports_no_ipv6() {
        let responder = tokio::net::UdpSocket::bind("[::1]:0").await.unwrap();
        let port = responder.local_addr().unwrap().port();
        tokio::spawn(async move { crate::probe_responder::serve(responder, key()).await });

        let target = SocketAddrV6::new("::1".parse().unwrap(), port, 0, 0);
        let outcome = probe_peer(target, &key(), Duration::from_secs(3), vec![])
            .await
            .unwrap();
        assert_eq!(outcome.reachability, Reachability::NoIpv6);
        // 证据仍然如实记录（便于诊断"有 daemon 但本机没地址"）
        assert!(outcome.evidence.solicited_ok);
    }
}
