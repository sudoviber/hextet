//! 候选 endpoint 组装。
//!
//! IPv6 下端口永远由自己决定，会合记录里只有**地址**在变（设计 spec §5），
//! 所以"打洞"在实现上就是"在若干个候选 `[addr]:port` 之间轮换，看哪个能握手"。

use std::net::SocketAddrV6;

use crate::cache::CachedEndpoint;

/// 候选 endpoint 数量上限。
///
/// 轮换间隔 2.5s，8 个候选跑完一轮 20s；再多会让"一轮都试不完"变成常态，
/// 超出部分丢弃（调用方负责 log 丢了多少）。
pub const MAX_CANDIDATES: usize = 8;

/// 归一化 endpoint：把 `flowinfo` 与 `scope_id` 清零。
///
/// `SocketAddrV6` 的 `PartialEq` 会比较 flowinfo 与 scope_id，而内核报告的
/// endpoint 与配置/缓存里解析出来的值在这两个字段上未必一致。不归一化就会让
/// "内核 endpoint != 当前候选"恒真，于是每个 tick 都被误判成一次 roaming，
/// 不停重写端点缓存。所有跨来源比较与存储都必须先过这个函数。
pub fn normalize(ep: SocketAddrV6) -> SocketAddrV6 {
    SocketAddrV6::new(*ep.ip(), ep.port(), 0, 0)
}

fn push_unique(out: &mut Vec<SocketAddrV6>, ep: SocketAddrV6) {
    let ep = normalize(ep);
    if out.len() < MAX_CANDIDATES && !out.contains(&ep) {
        out.push(ep);
    }
}

/// 候选 endpoint 的各路来源。
///
/// 会合层（设计 spec §3 D3 的兜底链）每加一层就多一个来源，因此用具名字段的结构体
/// 而不是位置参数——加一层不必改所有调用点的参数顺序。
#[derive(Debug, Default, Clone, Copy)]
pub struct CandidateSources<'a> {
    /// 上次被证实可用的 endpoint（端点缓存的 `last_good`）。
    pub last_good: Option<SocketAddrV6>,
    /// 会合层**当下**发现的 endpoint（阶段 B：LAN 公告；阶段 D：gossip 转介；
    /// 阶段 E：DHT）。调用方按新鲜度排好序。
    pub discovered: &'a [SocketAddrV6],
    /// 配置文件里手填的 endpoint（保持配置顺序）。
    pub configured: &'a [SocketAddrV6],
    /// 端点缓存里的历史条目。
    pub cached: &'a [CachedEndpoint],
}

/// 组装候选 endpoint 列表。
///
/// 顺序：`last_good` → `discovered` → `configured`（保持配置顺序）→ `cached`
/// （`last_seen_unix` 由新到旧）。
///
/// - `last_good` 最前：让"重启后立刻重连"成为最快路径。
/// - `discovered` 先于 `configured`：discovered 是**活证据**（几十秒内亲耳听到对端
///   在这个地址上），configured 是**静态声明**（可能是几个月前写下的）。活证据优先，
///   才能让"同 LAN 双端同时换前缀"在一个公告周期内恢复。
/// - `configured` 仍在 `cached` 之前：用户手填的地址是终极兜底（spec §3 D3 ⑦），
///   写了就得生效。
pub fn build_candidates(sources: &CandidateSources<'_>) -> Vec<SocketAddrV6> {
    let mut out: Vec<SocketAddrV6> = Vec::new();
    if let Some(ep) = sources.last_good {
        push_unique(&mut out, ep);
    }
    for ep in sources.discovered {
        push_unique(&mut out, *ep);
    }
    for ep in sources.configured {
        push_unique(&mut out, *ep);
    }
    let mut cached_sorted: Vec<&CachedEndpoint> = sources.cached.iter().collect();
    cached_sorted.sort_by_key(|c| std::cmp::Reverse(c.last_seen_unix));
    for c in cached_sorted {
        push_unique(&mut out, c.endpoint);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ep(s: &str) -> SocketAddrV6 {
        s.parse().unwrap()
    }

    /// 只给 configured 的来源（多数测试只关心一两路来源）。
    fn from_configured<'a>(configured: &'a [SocketAddrV6]) -> CandidateSources<'a> {
        CandidateSources {
            configured,
            ..Default::default()
        }
    }

    #[test]
    fn empty_inputs_give_empty_output() {
        assert!(build_candidates(&CandidateSources::default()).is_empty());
    }

    #[test]
    fn last_good_comes_first() {
        let configured = vec![ep("[2001:db8::1]:4193"), ep("[2001:db8::2]:4193")];
        let out = build_candidates(&CandidateSources {
            last_good: Some(ep("[2001:db8::2]:4193")),
            configured: &configured,
            ..Default::default()
        });
        assert_eq!(out[0], ep("[2001:db8::2]:4193"));
        assert_eq!(out[1], ep("[2001:db8::1]:4193"));
        // last_good 与配置项重复时不出现两次
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn configured_order_is_preserved() {
        let configured = vec![
            ep("[2001:db8::1]:4193"),
            ep("[2001:db8::2]:4193"),
            ep("[2001:db8::3]:4193"),
        ];
        let out = build_candidates(&from_configured(&configured));
        assert_eq!(out, configured);
    }

    /// 活证据（LAN/gossip/DHT 当下发现的）优先于静态配置。
    #[test]
    fn discovered_outranks_configured() {
        let configured = vec![ep("[2001:db8::1]:4193")];
        let discovered = vec![ep("[2001:db8:9::9]:4193")];
        let out = build_candidates(&CandidateSources {
            discovered: &discovered,
            configured: &configured,
            ..Default::default()
        });
        assert_eq!(
            out,
            vec![ep("[2001:db8:9::9]:4193"), ep("[2001:db8::1]:4193")]
        );
    }

    #[test]
    fn last_good_still_outranks_discovered() {
        let discovered = vec![ep("[2001:db8:9::9]:4193")];
        let out = build_candidates(&CandidateSources {
            last_good: Some(ep("[2001:db8::1]:4193")),
            discovered: &discovered,
            ..Default::default()
        });
        assert_eq!(out[0], ep("[2001:db8::1]:4193"));
    }

    #[test]
    fn cached_follow_configured_newest_first() {
        let configured = vec![ep("[2001:db8::1]:4193")];
        let cached = vec![
            CachedEndpoint {
                endpoint: ep("[2001:db8::7]:4193"),
                last_seen_unix: 100,
            },
            CachedEndpoint {
                endpoint: ep("[2001:db8::9]:4193"),
                last_seen_unix: 900,
            },
        ];
        let out = build_candidates(&CandidateSources {
            configured: &configured,
            cached: &cached,
            ..Default::default()
        });
        assert_eq!(
            out,
            vec![
                ep("[2001:db8::1]:4193"),
                ep("[2001:db8::9]:4193"),
                ep("[2001:db8::7]:4193"),
            ]
        );
    }

    #[test]
    fn duplicates_across_sources_are_deduped() {
        let one = ep("[2001:db8::1]:4193");
        let configured = vec![one];
        let discovered = vec![one];
        let cached = vec![CachedEndpoint {
            endpoint: one,
            last_seen_unix: 5,
        }];
        let out = build_candidates(&CandidateSources {
            last_good: Some(one),
            discovered: &discovered,
            configured: &configured,
            cached: &cached,
        });
        assert_eq!(out, vec![one]);
    }

    #[test]
    fn output_is_capped() {
        let configured: Vec<SocketAddrV6> = (1..=20)
            .map(|i| ep(&format!("[2001:db8::{i:x}]:4193")))
            .collect();
        let out = build_candidates(&from_configured(&configured));
        assert_eq!(out.len(), MAX_CANDIDATES);
        assert_eq!(out[0], configured[0]);
    }

    /// 截断发生在拼接过程中：靠前的来源先占位，所以 discovered 不会被 configured 挤掉。
    #[test]
    fn cap_favours_higher_ranked_sources() {
        let configured: Vec<SocketAddrV6> = (1..=20)
            .map(|i| ep(&format!("[2001:db8::{i:x}]:4193")))
            .collect();
        let discovered = vec![ep("[2001:db8:9::9]:4193")];
        let out = build_candidates(&CandidateSources {
            discovered: &discovered,
            configured: &configured,
            ..Default::default()
        });
        assert_eq!(out.len(), MAX_CANDIDATES);
        assert_eq!(out[0], ep("[2001:db8:9::9]:4193"));
    }

    #[test]
    fn normalize_clears_flowinfo_and_scope() {
        let raw = SocketAddrV6::new("2001:db8::1".parse().unwrap(), 4193, 7, 3);
        let n = normalize(raw);
        assert_eq!(n.flowinfo(), 0);
        assert_eq!(n.scope_id(), 0);
        assert_eq!(n.port(), 4193);
        assert_eq!(
            *n.ip(),
            "2001:db8::1".parse::<std::net::Ipv6Addr>().unwrap()
        );
        // 归一化后两个只差 scope_id 的地址相等（这正是去重与 roaming 判定要的语义）
        assert_eq!(n, normalize(SocketAddrV6::new(*raw.ip(), 4193, 0, 9)));
    }
}
