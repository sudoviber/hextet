//! CLI command implementations

use std::net::{SocketAddr, SocketAddrV6};
use std::path::Path;

use hextet_core::config::Config;
use hextet_core::identity::NodeIdentity;

pub mod backend;
pub mod daemon;
pub mod ddns;
pub mod dht;
pub mod doctor;
pub mod down;
pub mod hosts;
pub mod init;
pub mod inspect;
pub mod invite;
pub mod join;
pub mod keygen;
pub mod member;
pub mod peer;
pub mod service;
pub mod status;
#[cfg(target_os = "linux")]
pub mod status_tui;
pub mod up;

/// 解析命令行给的 endpoint，拒绝 IPv4。
///
/// hextet 是 IPv6-only 的：IPv4 endpoint 必须在**进入配置之前**就被拒掉，
/// 而不是等到建 WireGuard 设备时才失败。
pub fn parse_endpoint(s: &str) -> anyhow::Result<SocketAddrV6> {
    match s.parse::<SocketAddr>() {
        Ok(SocketAddr::V6(v6)) => Ok(v6),
        Ok(SocketAddr::V4(_)) => anyhow::bail!("endpoint {s} 是 IPv4；hextet 是 IPv6-only 的"),
        Err(_) => anyhow::bail!("无法解析 endpoint {s}（形如 [2001:db8::1]:4193）"),
    }
}

/// 读配置 + 载身份（实现见 [`hextet_core::config::load_config_and_identity`]）。
///
/// M2 起 daemon 也要做同样的事，逻辑因此上移到 core；这里保留薄封装，
/// 让既有子命令的调用点不必改动。
pub fn load_config_and_identity(config_path: &Path) -> anyhow::Result<(Config, NodeIdentity)> {
    Ok(hextet_core::config::load_config_and_identity(config_path)?)
}

#[cfg(test)]
mod tests {
    #[test]
    fn parse_endpoint_accepts_ipv6_rejects_the_rest() {
        assert_eq!(
            super::parse_endpoint("[2001:db8::1]:4193").unwrap(),
            "[2001:db8::1]:4193"
                .parse::<std::net::SocketAddrV6>()
                .unwrap()
        );
        assert!(
            super::parse_endpoint("1.2.3.4:4193")
                .unwrap_err()
                .to_string()
                .contains("IPv6-only")
        );
        assert!(super::parse_endpoint("2001:db8::1:4193").is_err());
        assert!(super::parse_endpoint("nope").is_err());
        assert!(super::parse_endpoint("").is_err());
    }
}
