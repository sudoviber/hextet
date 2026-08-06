//! WireGuard 后端抽象：设计 spec §3 D1 的 `WgBackend` trait。
#![deny(missing_docs)]

pub mod mock;
pub mod types;

#[cfg(target_os = "linux")]
pub mod kernel;

use types::{DeviceSpec, PeerStatus, WgError};

/// WireGuard 数据面后端（kernel / 未来 userspace-gotatun）。
pub trait WgBackend {
    /// 幂等地把设备调到 spec 描述的状态（接口不存在则创建）。
    fn apply(&self, spec: &DeviceSpec) -> Result<(), WgError>;
    /// 读取设备的 peer 运行时状态。
    fn status(&self, interface: &str) -> Result<Vec<PeerStatus>, WgError>;
}
