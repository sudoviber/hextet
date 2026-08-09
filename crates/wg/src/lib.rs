//! WireGuard 后端抽象：设计 spec §3 D1 的 `WgBackend` trait。
#![deny(missing_docs)]

pub mod mock;
pub mod types;

#[cfg(target_os = "linux")]
pub mod kernel;

use std::net::SocketAddrV6;

use types::{DeviceSpec, PeerStatus, WgError};

/// WireGuard 数据面后端（kernel / 未来 userspace-gotatun）。
pub trait WgBackend {
    /// 幂等地把设备调到 spec 描述的状态（接口不存在则创建）。
    fn apply(&self, spec: &DeviceSpec) -> Result<(), WgError>;
    /// 读取设备的 peer 运行时状态。
    fn status(&self, interface: &str) -> Result<Vec<PeerStatus>, WgError>;
    /// 只更新单个 peer 的 endpoint，其余配置（AllowedIPs/keepalive/密钥）保持不变。
    ///
    /// 打洞时要以 2.5s 级别轮换候选 endpoint，走整设备 `apply` 会重放全部 peer
    /// 配置（`replace_peers`），既浪费又有把并发 roaming 结果覆盖掉的风险。
    fn set_peer_endpoint(
        &self,
        interface: &str,
        wg_public: &[u8; 32],
        endpoint: SocketAddrV6,
    ) -> Result<(), WgError>;
}
