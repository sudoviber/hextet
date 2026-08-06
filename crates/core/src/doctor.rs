//! 入站可达性分类（协议规范：docs/protocol/doctor-probe.md）。

use serde::Serialize;

/// 本机 IPv6 入站可达性。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Reachability {
    /// 本机没有可用的公网 IPv6（GUA）——先解决这个，其他都是后话。
    #[serde(rename = "no-ipv6")]
    NoIpv6,
    /// 未经请求的入站包也能进来：可被动可达。
    #[serde(rename = "open")]
    Open,
    /// 只有"已请求"的回包能进来（住宅 CPE / 光猫 IPv6 SPI 的常态）。
    /// 打洞成立，裸监听不成立。
    #[serde(rename = "stateful")]
    Stateful,
    /// 连自己发出去的请求的回包都收不到，或对端没应答。
    #[serde(rename = "blocked")]
    Blocked,
}

impl Reachability {
    /// 稳定的短字符串形式（与 `--json` 里的取值一致）。
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NoIpv6 => "no-ipv6",
            Self::Open => "open",
            Self::Stateful => "stateful",
            Self::Blocked => "blocked",
        }
    }
}

/// 一次探测收集到的证据。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ProbeEvidence {
    /// 本机是否有可用的公网 IPv6 地址。
    pub has_global_ipv6: bool,
    /// 对端对我们的 Request 的直接回复是否到达（证明"出站+回包"这条路通）。
    pub solicited_ok: bool,
    /// 对端从另一个源端口发来的未经请求的包是否到达。
    pub unsolicited_ok: bool,
}

/// 由证据得出结论。
pub fn classify(evidence: &ProbeEvidence) -> Reachability {
    if !evidence.has_global_ipv6 {
        return Reachability::NoIpv6;
    }
    if evidence.unsolicited_ok {
        return Reachability::Open;
    }
    if evidence.solicited_ok {
        return Reachability::Stateful;
    }
    Reachability::Blocked
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evidence(global: bool, solicited: bool, unsolicited: bool) -> ProbeEvidence {
        ProbeEvidence {
            has_global_ipv6: global,
            solicited_ok: solicited,
            unsolicited_ok: unsolicited,
        }
    }

    #[test]
    fn no_global_ipv6_dominates() {
        // 没有公网 IPv6 时其他证据无意义：先解决"根本没地址"这件事
        assert_eq!(classify(&evidence(false, true, true)), Reachability::NoIpv6);
        assert_eq!(
            classify(&evidence(false, false, false)),
            Reachability::NoIpv6
        );
    }

    #[test]
    fn unsolicited_means_open() {
        assert_eq!(classify(&evidence(true, true, true)), Reachability::Open);
        // 未经请求的包能进来，就算 Response 丢了也说明入站是开放的
        assert_eq!(classify(&evidence(true, false, true)), Reachability::Open);
    }

    #[test]
    fn solicited_only_means_stateful() {
        assert_eq!(
            classify(&evidence(true, true, false)),
            Reachability::Stateful
        );
    }

    #[test]
    fn nothing_arrives_means_blocked() {
        assert_eq!(
            classify(&evidence(true, false, false)),
            Reachability::Blocked
        );
    }

    #[test]
    fn as_str_matches_serde() {
        for (r, s) in [
            (Reachability::NoIpv6, "no-ipv6"),
            (Reachability::Open, "open"),
            (Reachability::Stateful, "stateful"),
            (Reachability::Blocked, "blocked"),
        ] {
            assert_eq!(r.as_str(), s);
            assert_eq!(serde_json::to_string(&r).unwrap(), format!("\"{s}\""));
        }
    }
}
