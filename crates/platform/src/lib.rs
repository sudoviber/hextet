//! 平台集成：接口地址、MTU、生命周期、本机地址枚举与变化监听（M2 仅 Linux）。
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

/// 本机地址变化的方向。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddrEventKind {
    /// 新增地址（`RTM_NEWADDR`）。
    Added,
    /// 删除地址（`RTM_DELADDR`）。
    Removed,
}

/// 一次本机 IPv6 地址变化事件。
///
/// 中国家宽 PPPoE 重拨换前缀时，内核会连续发出多条 `RTM_NEWADDR`/`RTM_DELADDR`
/// （含 valid-lifetime=0 的静默换前缀），调用方需要自行去抖。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddrEvent {
    /// 新增还是删除。
    pub kind: AddrEventKind,
    /// 变化的 IPv6 地址。
    pub address: std::net::Ipv6Addr,
    /// 该地址所属接口的 netlink index。
    pub if_index: u32,
}

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::{delete_interface, list_global_ipv6, setup_interface, watch_ipv6_addresses};

#[cfg(not(target_os = "linux"))]
mod stub {
    use super::{AddrEvent, PlatformError};
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

    /// 非 Linux 平台暂不支持。
    pub async fn list_global_ipv6(
        _exclude_interface: Option<&str>,
    ) -> Result<Vec<Ipv6Addr>, PlatformError> {
        Err(PlatformError::Unsupported)
    }

    /// 非 Linux 平台暂不支持。
    pub async fn watch_ipv6_addresses(
        _tx: tokio::sync::mpsc::Sender<AddrEvent>,
    ) -> Result<(), PlatformError> {
        Err(PlatformError::Unsupported)
    }

    #[cfg(test)]
    mod tests {
        use super::{delete_interface, list_global_ipv6, setup_interface, watch_ipv6_addresses};
        use crate::PlatformError;

        /// 非 Linux 平台（本地 macOS 开发机）唯一真实执行的测试：
        /// 确认四个导出函数都如实返回 `Unsupported`，而不是静默 panic 或
        /// 误报别的错误变体。
        #[tokio::test]
        async fn stub_returns_unsupported() {
            let setup_err = setup_interface("hxt0", "fd00::1".parse().unwrap(), 48, 1400)
                .await
                .unwrap_err();
            assert!(matches!(setup_err, PlatformError::Unsupported));

            let delete_err = delete_interface("hxt0").await.unwrap_err();
            assert!(matches!(delete_err, PlatformError::Unsupported));

            let list_err = list_global_ipv6(None).await.unwrap_err();
            assert!(matches!(list_err, PlatformError::Unsupported));

            let (tx, _rx) = tokio::sync::mpsc::channel(1);
            let watch_err = watch_ipv6_addresses(tx).await.unwrap_err();
            assert!(matches!(watch_err, PlatformError::Unsupported));
        }
    }
}
#[cfg(not(target_os = "linux"))]
pub use stub::{delete_interface, list_global_ipv6, setup_interface, watch_ipv6_addresses};
