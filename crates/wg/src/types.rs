//! 后端无关的设备/peer 描述。

use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use std::time::SystemTime;

/// 期望的 WireGuard 设备状态（声明式，apply 幂等）。
#[derive(Debug, Clone)]
pub struct DeviceSpec {
    /// 接口名。
    pub interface: String,
    /// UDP 监听端口。
    pub listen_port: u16,
    /// WG 私钥字节。
    pub wg_secret: [u8; 32],
    /// 对端列表。
    pub peers: Vec<PeerSpec>,
}

/// 单个对端的期望状态。
#[derive(Debug, Clone)]
pub struct PeerSpec {
    /// 对端 WG 公钥。
    pub wg_public: [u8; 32],
    /// 静态 endpoint（M1：取配置中第一个）。
    pub endpoint: Option<SocketAddrV6>,
    /// AllowedIPs（IPv6-only）。
    pub allowed_ips: Vec<(Ipv6Addr, u8)>,
    /// keepalive 秒数。
    pub persistent_keepalive: Option<u16>,
}

/// 对端运行时状态。
#[derive(Debug, Clone)]
pub struct PeerStatus {
    /// 对端 WG 公钥。
    pub wg_public: [u8; 32],
    /// 内核记录的当前 endpoint。
    pub endpoint: Option<SocketAddr>,
    /// 最近一次握手时间。
    pub last_handshake: Option<SystemTime>,
    /// 接收字节数。
    pub rx_bytes: u64,
    /// 发送字节数。
    pub tx_bytes: u64,
}

/// WG 后端错误。
#[derive(Debug, thiserror::Error)]
pub enum WgError {
    /// 接口不存在。
    #[error("interface {0} not found")]
    NotFound(String),
    /// 底层系统错误。
    #[error("wireguard backend error: {0}")]
    Backend(String),
}
