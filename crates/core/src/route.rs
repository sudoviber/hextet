//! 通告子网路由（site-to-site）的模型与派生。
//!
//! 一个节点可以把若干 IPv6 子网通告为「在我背后可达」（例如家里的 LAN），
//! 其它节点连上它之后会把发往这些前缀的流量送进隧道。这里的 [`Ipv6Route`] 是
//! 该子网的规范化表示：**只存网络地址**（host 位必须为零，解析时就拒绝），
//! 并提供 `contains`/`overlaps` 供配置校验与 AllowedIPs 派生使用。

use std::fmt;
use std::net::Ipv6Addr;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::RouteError;

/// 一条已规范化的 IPv6 子网路由（`prefix/prefix_len`）。
///
/// 不变量：`prefix` 一定是该前缀长度的**网络地址**（host 位全零）。这个不变量
/// 由 [`Ipv6Route::new`] 与 [`FromStr`] 强制，因此 `Display` 打印出来的一定能
/// 原样 `parse` 回去。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ipv6Route {
    prefix: Ipv6Addr,
    prefix_len: u8,
}

/// 构造一个 `len` 位的全 1 掩码（高位在前）。
fn mask(len: u8) -> [u8; 16] {
    let mut m = [0u8; 16];
    let whole = (len / 8) as usize;
    let rem = len % 8;
    m[..whole].fill(0xff);
    if rem > 0 {
        m[whole] = 0xff << (8 - rem);
    }
    m
}

impl Ipv6Route {
    /// 由前缀地址与长度构造；`prefix` 的 host 位必须为零，长度必须在 `1..=128`。
    pub fn new(prefix: Ipv6Addr, prefix_len: u8) -> Result<Self, RouteError> {
        if prefix_len == 0 || prefix_len > 128 {
            return Err(RouteError::BadPrefixLen(prefix_len));
        }
        let masked = apply_mask(prefix, prefix_len);
        if masked != prefix {
            return Err(RouteError::HostBitsSet(format!("{prefix}/{prefix_len}")));
        }
        Ok(Self { prefix, prefix_len })
    }

    /// 网络地址（即规范化后的 `prefix`，host 位全零）。
    pub fn prefix(&self) -> Ipv6Addr {
        self.prefix
    }

    /// 前缀长度。
    pub fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    /// 这个路由是否包含给定地址。
    pub fn contains(&self, addr: &Ipv6Addr) -> bool {
        apply_mask(*addr, self.prefix_len) == self.prefix
    }

    /// 两个路由是否重叠（一个包含另一个的网络地址）。
    ///
    /// 因为两个路由的前缀都是对齐的网络地址，「重叠」等价于「其中一个的网络地址
    /// 落在另一个的范围内」。两个路由完全相同（相等）也算重叠。
    pub fn overlaps(&self, other: &Self) -> bool {
        self.contains(&other.prefix) || other.contains(&self.prefix)
    }
}

/// 把地址低 `128 - len` 位清零，得到它所属的 /`len` 网络地址。
fn apply_mask(addr: Ipv6Addr, len: u8) -> Ipv6Addr {
    let m = mask(len);
    let mut o = addr.octets();
    for (b, mm) in o.iter_mut().zip(m) {
        *b &= mm;
    }
    Ipv6Addr::from(o)
}

impl fmt::Display for Ipv6Route {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.prefix, self.prefix_len)
    }
}

impl FromStr for Ipv6Route {
    type Err = RouteError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (addr_str, len_str) = s
            .split_once('/')
            .ok_or_else(|| RouteError::Invalid(s.to_owned()))?;
        // 先显式挡掉 IPv4：`1.2.3.0/24` 会带 `.`，IPv4 解析成功更不该混进来。
        if addr_str.contains('.') || addr_str.parse::<std::net::Ipv4Addr>().is_ok() {
            return Err(RouteError::Ipv4(s.to_owned()));
        }
        let addr: Ipv6Addr = addr_str
            .parse()
            .map_err(|_| RouteError::Invalid(s.to_owned()))?;
        let len: u8 = len_str
            .parse()
            .map_err(|_| RouteError::Invalid(s.to_owned()))?;
        Self::new(addr, len)
    }
}

// 序列化成 `Display` 的字符串形式（`2001:db8:dead::/64`），与配置里的写法一致，
// 也让 `state.json` / `status --json` 里的路由字段保持人类可读、可往返。
impl Serialize for Ipv6Route {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Ipv6Route {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// 由节点自己的 /64 site 与它通告的路由派生 WireGuard AllowedIPs。
///
/// AllowedIPs 的第一个条目永远是节点自己的 /64 site，随后是每一条通告路由
/// （与 site 重复的会被去掉）。这是 spec.rs 与 daemon 共用的**唯一**派生点，
/// 保证两处不会出现"一处加了 route 另一处没加"的分叉。
pub fn allowed_ips_for(site: Ipv6Addr, routes: &[Ipv6Route]) -> Vec<(Ipv6Addr, u8)> {
    let mut out = Vec::with_capacity(routes.len() + 1);
    out.push((site, 64));
    for r in routes {
        let entry = (r.prefix(), r.prefix_len());
        if !out.contains(&entry) {
            out.push(entry);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(s: &str) -> Ipv6Route {
        s.parse().unwrap()
    }

    #[test]
    fn parse_and_display_roundtrip() {
        for good in [
            "2001:db8:abcd::/64",
            "fd00::/8",
            "2001:db8::/48",
            "::/128",
            "2001:db8::1/128",
        ] {
            let route = r(good);
            assert_eq!(route.to_string(), good, "{good} 往返不一致");
        }
    }

    #[test]
    fn rejects_ipv4() {
        assert!(matches!(
            "1.2.3.0/24".parse::<Ipv6Route>(),
            Err(RouteError::Ipv4(_))
        ));
        assert!(matches!(
            "192.0.2.0/24".parse::<Ipv6Route>(),
            Err(RouteError::Ipv4(_))
        ));
    }

    #[test]
    fn rejects_bad_prefix_len() {
        assert!(matches!(
            "2001:db8::/0".parse::<Ipv6Route>(),
            Err(RouteError::BadPrefixLen(0))
        ));
        assert!(matches!(
            "2001:db8::/129".parse::<Ipv6Route>(),
            Err(RouteError::BadPrefixLen(129))
        ));
    }

    #[test]
    fn rejects_nonzero_host_bits() {
        // 网络地址必须 host 位全零：写了个主机地址却当 /64 通告，多半是用户笔误
        assert!(matches!(
            "2001:db8:abcd::1/64".parse::<Ipv6Route>(),
            Err(RouteError::HostBitsSet(_))
        ));
        assert!(matches!(
            "2001:db8:abcd:1::/48".parse::<Ipv6Route>(),
            Err(RouteError::HostBitsSet(_))
        ));
    }

    #[test]
    fn rejects_malformed() {
        assert!(matches!(
            "not-an-addr".parse::<Ipv6Route>(),
            Err(RouteError::Invalid(_))
        ));
        assert!(matches!(
            "2001:db8::".parse::<Ipv6Route>(),
            Err(RouteError::Invalid(_))
        ));
        assert!(matches!(
            "2001:db8::/".parse::<Ipv6Route>(),
            Err(RouteError::Invalid(_))
        ));
    }

    #[test]
    fn contains_boundaries() {
        let net = r("2001:db8:abcd::/64");
        assert!(net.contains(&"2001:db8:abcd::1".parse().unwrap()));
        assert!(net.contains(&"2001:db8:abcd::9".parse().unwrap()));
        // 第 3 个 hextet 不同 = 完全不同的 /48，绝不在这个 /64 里
        assert!(!net.contains(&"2001:db8:abce::1".parse().unwrap()));
        // 第 4 个 hextet 不同 = 同一 /48 下的另一个 /64
        assert!(!net.contains(&"2001:db8:abcd:1::1".parse().unwrap()));
        // /128 host route 只包含它自己
        let host = r("2001:db8::1/128");
        assert!(host.contains(&"2001:db8::1".parse().unwrap()));
        assert!(!host.contains(&"2001:db8::2".parse().unwrap()));
    }

    #[test]
    fn overlap_cases() {
        // 大前缀包含小前缀（/48 包含其下的 /64）
        assert!(r("2001:db8:abcd::/48").overlaps(&r("2001:db8:abcd::/64")));
        // 相同路由
        assert!(r("2001:db8:abcd::/64").overlaps(&r("2001:db8:abcd::/64")));
        // 不相交：第 3 个 hextet 不同
        assert!(!r("2001:db8:abcd::/64").overlaps(&r("2001:db8:abce::/64")));
        assert!(!r("2001:db8::/48").overlaps(&r("2001:db9::/48")));
    }

    #[test]
    fn allowed_ips_includes_site_then_routes() {
        let site = "fd12:3456:78:abcd::".parse().unwrap();
        let routes = [r("2001:db8:dead::/64"), r("2001:db8:beef::/48")];
        let ips = allowed_ips_for(site, &routes);
        assert_eq!(
            ips,
            vec![
                (site, 64),
                ("2001:db8:dead::".parse().unwrap(), 64),
                ("2001:db8:beef::".parse().unwrap(), 48),
            ]
        );
    }

    #[test]
    fn allowed_ips_empty_routes_is_just_site() {
        let site = "fd12:3456:78:abcd::".parse().unwrap();
        assert_eq!(allowed_ips_for(site, &[]), vec![(site, 64)]);
    }

    /// `state.json` / `status --json` 里的 routes 字段序列化成字符串形式，且能反序列化回来。
    #[test]
    fn serde_roundtrips_as_string() {
        let route = r("2001:db8:dead::/64");
        let json = serde_json::to_string(&route).unwrap();
        assert_eq!(json, "\"2001:db8:dead::/64\"");
        let back: Ipv6Route = serde_json::from_str(&json).unwrap();
        assert_eq!(back, route);

        // 数组形式（PeerState.routes 的真实形态）
        let list = vec![route, r("2001:db8:beef::/48")];
        let json_list = serde_json::to_string(&list).unwrap();
        assert_eq!(json_list, "[\"2001:db8:dead::/64\",\"2001:db8:beef::/48\"]");
        let back_list: Vec<Ipv6Route> = serde_json::from_str(&json_list).unwrap();
        assert_eq!(back_list, list);
    }
}
