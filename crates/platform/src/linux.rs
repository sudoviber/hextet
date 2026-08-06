//! Linux rtnetlink 实现。

use std::net::{IpAddr, Ipv6Addr};

use futures::TryStreamExt as _;
use rtnetlink::LinkUnspec;

use crate::PlatformError;

fn nl(e: impl std::fmt::Display) -> PlatformError {
    PlatformError::Netlink(e.to_string())
}

/// 判断 rtnetlink 错误是否代表"接口不存在"，而非权限不足、协议解析失败等其他故障。
///
/// 查证结论（对照 `netlink-packet-core-0.8.2/src/error.rs::ErrorMessage`
/// 与 `rtnetlink-0.21.0/src/macros.rs::try_rtnl!`）：
/// - netlink `NLMSG_ERROR` 消息把 errno 编码为**负数**放进 `ErrorMessage.code`；
///   `try_rtnl!`/`try_nl!` 遇到 `NetlinkPayload::Error(err)` 时统一包成
///   `rtnetlink::Error::NetlinkError(err)`，`err.raw_code()` 原样返回该负值
///   （`ErrorMessage::to_io()` 用 `io::Error::from_raw_os_error(raw_code().abs())`
///   转换，取绝对值才是标准 errno）。
/// - `RTM_GETLINK` 对不存在的接口名（`match_name` 查无匹配）返回的标准错误码是
///   **-ENODEV**（"No such device"，与 `ip link show <不存在接口>` 报错一致）；
///   这与 wireguard-control 侧对 ENODEV 的判定语义一致（见 crates/wg 的
///   e16a02b：接口不存在但内核模块已加载时同样是 ENODEV）。
/// - 其余变体——`UnexpectedMessage`（非预期消息类型）、非 ENODEV 的
///   `NetlinkError`（例如权限不足时内核返回的 -EPERM/-EACCES）——都不代表
///   "不存在"，一律经 `nl()` 保留原始错误文本进入 `PlatformError::Netlink`，
///   避免把权限问题误报成接口缺失。
fn is_missing_link(err: &rtnetlink::Error) -> bool {
    matches!(err, rtnetlink::Error::NetlinkError(msg) if msg.raw_code().abs() == libc::ENODEV)
}

async fn link_index(handle: &rtnetlink::Handle, name: &str) -> Result<u32, PlatformError> {
    let mut links = handle.link().get().match_name(name.to_owned()).execute();
    match links.try_next().await {
        Ok(Some(link)) => Ok(link.header.index),
        Ok(None) => Err(PlatformError::NotFound(name.to_owned())),
        Err(e) if is_missing_link(&e) => Err(PlatformError::NotFound(name.to_owned())),
        Err(e) => Err(nl(e)),
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
