//! 平台集成：接口地址、MTU、生命周期（M1 仅 Linux）。
#![deny(missing_docs)]

/// 平台错误。
#[derive(Debug, thiserror::Error)]
pub enum PlatformError {
    /// 接口不存在。
    #[error("interface {0} not found")]
    NotFound(String),
    /// 当前平台未实现。
    #[error("unsupported platform")]
    Unsupported,
    /// netlink 错误。
    #[error("netlink: {0}")]
    Netlink(String),
}

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::{delete_interface, setup_interface};

#[cfg(not(target_os = "linux"))]
mod stub {
    use super::PlatformError;
    use std::net::Ipv6Addr;

    /// 非 Linux 平台暂不支持（M4 起支持 macOS）。
    pub async fn setup_interface(
        _name: &str,
        _address: Ipv6Addr,
        _prefix_len: u8,
        _mtu: u32,
    ) -> Result<(), PlatformError> {
        Err(PlatformError::Unsupported)
    }

    /// 非 Linux 平台暂不支持。
    pub async fn delete_interface(_name: &str) -> Result<(), PlatformError> {
        Err(PlatformError::Unsupported)
    }
}
#[cfg(not(target_os = "linux"))]
pub use stub::{delete_interface, setup_interface};
