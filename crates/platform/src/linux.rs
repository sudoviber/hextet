//! Linux rtnetlink 实现。

use std::net::{IpAddr, Ipv6Addr};

use futures::{StreamExt as _, TryStreamExt as _};
use rtnetlink::LinkUnspec;
use rtnetlink::packet_core::NetlinkPayload;
use rtnetlink::packet_route::AddressFamily;
use rtnetlink::packet_route::RouteNetlinkMessage;
use rtnetlink::packet_route::address::{AddressAttribute, AddressHeaderFlags, AddressScope};
use rtnetlink::{MulticastGroup, new_multicast_connection};

use crate::{AddrEvent, AddrEventKind, PlatformError};

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
///
/// 幂等：地址添加走 `NLM_F_REPLACE`（经 [`AddressAddRequest::replace`] 调用
/// 达成），对已存在的同一地址是 no-op 而非报错；重复调用本函数（例如重复
/// `up`）不会因为 `RTM_NEWADDR` 默认的 `NLM_F_EXCL` 语义而被内核拒绝为 EEXIST。
///
/// [`AddressAddRequest::replace`]: rtnetlink::AddressAddRequest::replace
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
        .replace()
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

/// 判断是否 ULA（RFC 4193 fc00::/7）。
///
/// hextet 自己的 overlay 地址就是 ULA，绝不能被当成"可对外的公网 endpoint"
/// 报给 doctor；LAN 上其他设备的 ULA 同理不可用。
fn is_ula(addr: &Ipv6Addr) -> bool {
    (addr.segments()[0] & 0xfe00) == 0xfc00
}

/// 枚举本机可用作公网 endpoint 的 IPv6 地址。
///
/// 过滤规则（顺序即代码顺序）：
/// 1. family 必须是 Inet6；
/// 2. scope 必须是 Universe（排除 link-local fe80::/10、host ::1）；
/// 3. `exclude_interface` 指定的接口上的地址全部排除（hextet0 自己的 overlay）；
/// 4. 打了 Deprecated / Tentative / Dadfailed 标记的排除——换前缀过程中旧地址
///    会先变 Deprecated，拿它当 endpoint 只会打洞到一个即将失效的地址；
/// 5. ULA / loopback / multicast 排除。
pub async fn list_global_ipv6(
    exclude_interface: Option<&str>,
) -> Result<Vec<Ipv6Addr>, PlatformError> {
    let (conn, handle, _) = rtnetlink::new_connection().map_err(nl)?;
    tokio::spawn(conn);

    let excluded = match exclude_interface {
        Some(name) => match link_index(&handle, name).await {
            Ok(idx) => Some(idx),
            // 接口还不存在（daemon 尚未建好）时无需排除任何东西
            Err(PlatformError::NotFound(_)) => None,
            Err(e) => return Err(e),
        },
        None => None,
    };

    let mut out = Vec::new();
    let mut stream = handle.address().get().execute();
    while let Some(msg) = stream.try_next().await.map_err(nl)? {
        if !matches!(msg.header.family, AddressFamily::Inet6) {
            continue;
        }
        if !matches!(msg.header.scope, AddressScope::Universe) {
            continue;
        }
        if excluded == Some(msg.header.index) {
            continue;
        }
        if msg.header.flags.intersects(
            AddressHeaderFlags::Deprecated
                | AddressHeaderFlags::Tentative
                | AddressHeaderFlags::Dadfailed,
        ) {
            continue;
        }
        for attr in &msg.attributes {
            let AddressAttribute::Address(IpAddr::V6(addr)) = attr else {
                continue;
            };
            if is_ula(addr) || addr.is_loopback() || addr.is_multicast() {
                continue;
            }
            out.push(*addr);
        }
    }
    out.sort();
    out.dedup();
    Ok(out)
}

/// 监听本机 IPv6 地址变化（`RTNLGRP_IPV6_IFADDR` 组播，等价于 `ip -6 monitor address`）。
///
/// 一直阻塞直到 netlink 流结束或 `tx` 的接收端被丢弃。**不做任何过滤**：
/// daemon 只需要"地址变了"这个信号来触发重新握手，把判断留给调用方更简单，
/// 也避免漏掉「新前缀先 Added、旧前缀后 Removed」这类多事件序列里的任一条。
pub async fn watch_ipv6_addresses(
    tx: tokio::sync::mpsc::Sender<AddrEvent>,
) -> Result<(), PlatformError> {
    let (conn, _handle, mut messages) =
        new_multicast_connection(&[MulticastGroup::Ipv6Ifaddr]).map_err(nl)?;
    tokio::spawn(conn);

    while let Some((message, _)) = messages.next().await {
        let NetlinkPayload::InnerMessage(inner) = message.payload else {
            continue;
        };
        let (kind, msg) = match inner {
            RouteNetlinkMessage::NewAddress(m) => (AddrEventKind::Added, m),
            RouteNetlinkMessage::DelAddress(m) => (AddrEventKind::Removed, m),
            _ => continue,
        };
        let if_index = msg.header.index;
        for attr in &msg.attributes {
            let AddressAttribute::Address(IpAddr::V6(address)) = attr else {
                continue;
            };
            if tx
                .send(AddrEvent {
                    kind,
                    address: *address,
                    if_index,
                })
                .await
                .is_err()
            {
                // 接收端已关闭（daemon 退出）：正常收尾，不算错误
                return Ok(());
            }
        }
    }
    Ok(())
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

    /// 不需要 root：ULA 判定是 `list_global_ipv6` 过滤逻辑的核心，单独测。
    #[test]
    fn ula_detection() {
        assert!(super::is_ula(&"fd00::1".parse().unwrap()));
        assert!(super::is_ula(&"fc00::1".parse().unwrap()));
        assert!(super::is_ula(&"fdff:ffff::1".parse().unwrap()));
        assert!(!super::is_ula(&"2001:db8::1".parse().unwrap()));
        assert!(!super::is_ula(&"fe80::1".parse().unwrap()));
        assert!(!super::is_ula(&"::1".parse().unwrap()));
    }

    /// 需要 Linux（不需要 root）：本机至少有 lo 的 ::1，但它必须被过滤掉，
    /// 所以这里只断言"调用不报错"，具体内容因机器而异。
    #[tokio::test]
    async fn list_global_ipv6_does_not_error() {
        let addrs = super::list_global_ipv6(None).await.unwrap();
        for a in &addrs {
            assert!(!a.is_loopback(), "loopback 未被过滤: {a}");
            assert!(!super::is_ula(a), "ULA 未被过滤: {a}");
        }
    }

    /// 需要 root + Linux：`sudo -E cargo test -p hextet-platform -- --ignored`
    /// 加地址 → 监听器应在 2s 内收到一个 Added 事件。
    #[tokio::test]
    #[ignore = "requires root"]
    async fn watch_reports_added_address() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(16);
        tokio::spawn(async move { super::watch_ipv6_addresses(tx).await });
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        let status = std::process::Command::new("ip")
            .args(["-6", "addr", "add", "fd00:dead:beef::1/64", "dev", "lo"])
            .status()
            .expect("run ip");
        assert!(status.success(), "ip addr add 失败（需要 root）");

        let event = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .expect("2s 内应收到地址事件")
            .expect("channel 未关闭");
        assert_eq!(event.kind, crate::AddrEventKind::Added);

        let _ = std::process::Command::new("ip")
            .args(["-6", "addr", "del", "fd00:dead:beef::1/64", "dev", "lo"])
            .status();
    }
}
