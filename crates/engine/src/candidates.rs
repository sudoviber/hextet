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

/// 组装候选 endpoint 列表。
///
/// 顺序：`last_good` → `configured`（保持配置顺序）→ `cached`（`last_seen_unix`
/// 由新到旧）。上次成功的放最前面，让"重启后立刻重连"成为最快路径；配置项优先于
/// 缓存，让用户手填的地址（终极兜底，设计 spec §3 D3 ⑦）总能生效。
pub fn build_candidates(
    configured: &[SocketAddrV6],
    cached: &[CachedEndpoint],
    last_good: Option<SocketAddrV6>,
) -> Vec<SocketAddrV6> {
    let mut out: Vec<SocketAddrV6> = Vec::new();
    if let Some(ep) = last_good {
        push_unique(&mut out, ep);
    }
    for ep in configured {
        push_unique(&mut out, *ep);
    }
    let mut cached_sorted: Vec<&CachedEndpoint> = cached.iter().collect();
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

    #[test]
    fn empty_inputs_give_empty_output() {
        assert!(build_candidates(&[], &[], None).is_empty());
    }

    #[test]
    fn last_good_comes_first() {
        let configured = vec![ep("[2001:db8::1]:4193"), ep("[2001:db8::2]:4193")];
        let out = build_candidates(&configured, &[], Some(ep("[2001:db8::2]:4193")));
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
        let out = build_candidates(&configured, &[], None);
        assert_eq!(out, configured);
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
        let out = build_candidates(&configured, &cached, None);
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
        let configured = vec![ep("[2001:db8::1]:4193")];
        let cached = vec![CachedEndpoint {
            endpoint: ep("[2001:db8::1]:4193"),
            last_seen_unix: 5,
        }];
        let out = build_candidates(&configured, &cached, Some(ep("[2001:db8::1]:4193")));
        assert_eq!(out, vec![ep("[2001:db8::1]:4193")]);
    }

    #[test]
    fn output_is_capped() {
        let configured: Vec<SocketAddrV6> = (1..=20)
            .map(|i| ep(&format!("[2001:db8::{i:x}]:4193")))
            .collect();
        let out = build_candidates(&configured, &[], None);
        assert_eq!(out.len(), MAX_CANDIDATES);
        assert_eq!(out[0], configured[0]);
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
