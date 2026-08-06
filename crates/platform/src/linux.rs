//! Linux rtnetlink 实现。

use std::net::{IpAddr, Ipv6Addr};

use futures::TryStreamExt as _;
use rtnetlink::LinkUnspec;

use crate::PlatformError;

fn nl(e: impl std::fmt::Display) -> PlatformError {
    PlatformError::Netlink(e.to_string())
}

async fn link_index(handle: &rtnetlink::Handle, name: &str) -> Result<u32, PlatformError> {
    let mut links = handle.link().get().match_name(name.to_owned()).execute();
    match links.try_next().await {
        Ok(Some(link)) => Ok(link.header.index),
        _ => Err(PlatformError::NotFound(name.to_owned())),
    }
}

/// 为接口配置地址/MTU 并拉起。
pub async fn setup_interface(
    name: &str,
    address: Ipv6Addr,
    prefix_len: u8,
    mtu: u32,
) -> Result<(), PlatformError> {
    let (conn, handle, _) = rtnetlink::new_connection().map_err(nl)?;
    tokio::spawn(conn);
    let index = link_index(&handle, name).await?;
    handle
        .address()
        .add(index, IpAddr::V6(address), prefix_len)
        .execute()
        .await
        .map_err(nl)?;
    handle
        .link()
        .set(LinkUnspec::new_with_index(index).mtu(mtu).up().build())
        .execute()
        .await
        .map_err(nl)?;
    Ok(())
}

/// 删除接口。
pub async fn delete_interface(name: &str) -> Result<(), PlatformError> {
    let (conn, handle, _) = rtnetlink::new_connection().map_err(nl)?;
    tokio::spawn(conn);
    let index = link_index(&handle, name).await?;
    handle.link().del(index).execute().await.map_err(nl)
}

#[cfg(test)]
mod tests {
    /// 需要 root + Linux：`sudo -E cargo test -p hextet-platform -- --ignored`
    /// 常规 CI 不跑（netns E2E 已覆盖同等路径）。
    #[tokio::test]
    #[ignore = "requires root"]
    async fn setup_missing_interface_is_not_found() {
        let err = super::setup_interface("hxt-noexist0", "fd00::1".parse().unwrap(), 48, 1400)
            .await
            .unwrap_err();
        assert!(matches!(err, crate::PlatformError::NotFound(_)));
    }
}
