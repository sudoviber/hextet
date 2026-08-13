//! Windows（x86_64 / arm64）平台集成实现（ADR-0011 决策 4）。
//!
//! 本模块与 `macos.rs` 一样，是 workspace 内**少数允许 `unsafe`** 的地方（见模块级
//! `#![allow(unsafe_code)]`）：Windows 的网络 API（`GetAdaptersAddresses` 等）是原始
//! 指针 FFI，`windows` crate 提供类型化绑定但解引用仍须 `unsafe`。unsafe 只被圈在
//! 最小范围内，其余逻辑零 unsafe。诚实边界：本机无法运行 Windows，仅
//! `cargo check --target x86_64-pc-windows-gnu` 编译验证（ADR-0011 决策 5）；真实
//! 适配器枚举/路由/地址配装的运行时行为待 Windows 真机或 CI 验证。
//!
//! 已落地：`list_global_ipv6`（GetAdaptersAddresses）、`add_route`/`remove_route`
//! （Create/DeleteIpForwardEntry2）、`setup_interface`（CreateUnicastIpAddressEntry，
//! MTU no-op）、`list_multicast_interfaces`、`watch_ipv6_addresses`（2s 轮询）。
//! 仍为 `Unsupported`：`delete_interface`（wintun 适配器随句柄 drop 关闭，显式删除
//! 涉及适配器持久化生命周期，留作后续切片）。

#![allow(unsafe_code)]

use std::mem::size_of;
use std::net::Ipv6Addr;

use hextet_core::addr::is_usable_endpoint_addr;
use windows::Win32::NetworkManagement::IpHelper::{
    ConvertInterfaceNameToLuidW, CreateIpForwardEntry2, CreateUnicastIpAddressEntry,
    DeleteIpForwardEntry2, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER,
    GAA_FLAG_SKIP_MULTICAST, GetAdaptersAddresses, IP_ADAPTER_ADDRESSES_LH, IP_ADDRESS_PREFIX,
    InitializeIpForwardEntry, InitializeUnicastIpAddressEntry, MIB_IPFORWARD_ROW2,
    MIB_UNICASTIPADDRESS_ROW,
};
use windows::Win32::NetworkManagement::Ndis::{IfOperStatusUp, NET_LUID_LH};
use windows::Win32::Networking::WinSock::{
    AF_INET6, IpPrefixOriginManual, IpSuffixOriginManual, MIB_IPPROTO_NETMGMT, SOCKADDR_IN6,
    SOCKADDR_INET,
};

use crate::{AddrEvent, AddrEventKind, PlatformError};

fn os(e: impl std::fmt::Display) -> PlatformError {
    PlatformError::Os(e.to_string())
}

/// 把 `windows` 的 `GetAdaptersAddresses` 返回的 `u32` 错误码转成 `PlatformError`。
fn win32_error(what: &str, code: u32) -> PlatformError {
    os(format!("{what}（错误码 {code}）"))
}

/// 把以 NUL 结尾的 UTF-16 字符串转成 `String`（空指针或空串返回 `None`）。
///
/// # Safety
/// `p` 必须为空指针，或指向一个以 `0` 结尾的、长度有界的 UTF-16 数组。
unsafe fn wide_to_string(p: *const u16) -> Option<String> {
    if p.is_null() {
        return None;
    }
    let mut len = 0usize;
    while unsafe { *p.add(len) } != 0 {
        len += 1;
    }
    if len == 0 {
        return None;
    }
    let slice = unsafe { std::slice::from_raw_parts(p, len) };
    Some(String::from_utf16_lossy(slice))
}

/// 把以 NUL 结尾的 ANSI（单字节）字符串转成 `String`（空指针或空串返回 `None`）。
///
/// # Safety
/// `p` 必须为空指针，或指向一个以 `0` 结尾的、长度有界的字节数组。
unsafe fn ansi_to_string(p: *const u8) -> Option<String> {
    if p.is_null() {
        return None;
    }
    let mut len = 0usize;
    while unsafe { *p.add(len) } != 0 {
        len += 1;
    }
    if len == 0 {
        return None;
    }
    let slice = unsafe { std::slice::from_raw_parts(p, len) };
    Some(String::from_utf8_lossy(slice).into_owned())
}

/// 判断某适配器是否是要排除的 hextet 接口（按名匹配）。
///
/// Windows 上 wintun 适配器的名字在 `tun` crate 里由配置名决定（默认 `wintun`），
/// 体现在 `FriendlyName`；同时匹配 `AdapterName`（GUID 串）兜底。名字匹配失败时
/// 宁可**不**排除（多枚举一个地址，去重/打洞流程会兜底），也不误排除别的接口。
fn is_excluded(adapter: &IP_ADAPTER_ADDRESSES_LH, exclude: Option<&str>) -> bool {
    let Some(exclude) = exclude else {
        return false;
    };
    let friendly = unsafe { wide_to_string(adapter.FriendlyName.0) };
    if friendly.as_deref() == Some(exclude) {
        return true;
    }
    let name = unsafe { ansi_to_string(adapter.AdapterName.0 as *const u8) };
    name.as_deref() == Some(exclude)
}

/// 同步版本的 [`list_global_ipv6`]（`GetAdaptersAddresses` 是阻塞 FFI）。
fn list_global_ipv6_sync(exclude: Option<&str>) -> Result<Vec<Ipv6Addr>, PlatformError> {
    let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    // 第一次调用拿所需缓冲区大小。
    let mut size: u32 = 0;
    let ret = unsafe { GetAdaptersAddresses(AF_INET6.0 as u32, flags, None, None, &mut size) };
    if ret != 111 && ret != 232 {
        // 111 = ERROR_BUFFER_OVERFLOW（拿到了 size）；232 = ERROR_NO_DATA（本机无 IPv6）。
        if ret == 232 {
            return Ok(Vec::new());
        }
        return Err(win32_error("GetAdaptersAddresses 探测缓冲区大小失败", ret));
    }
    if size == 0 {
        return Ok(Vec::new());
    }
    let mut buf = vec![0u8; size as usize];
    let ret = unsafe {
        GetAdaptersAddresses(
            AF_INET6.0 as u32,
            flags,
            None,
            Some(buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH),
            &mut size,
        )
    };
    if ret != 0 {
        return Err(win32_error("GetAdaptersAddresses 失败", ret));
    }

    let mut addrs = Vec::new();
    let mut current = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
    while !current.is_null() {
        let adapter = unsafe { &*current };
        if !is_excluded(adapter, exclude) {
            let mut ua = adapter.FirstUnicastAddress;
            while !ua.is_null() {
                let entry = unsafe { &*ua };
                let sockaddr = entry.Address.lpSockaddr;
                if !sockaddr.is_null()
                    && entry.Address.iSockaddrLength >= size_of::<SOCKADDR_IN6>() as i32
                {
                    let sin6 = unsafe { &*(sockaddr as *const SOCKADDR_IN6) };
                    if sin6.sin6_family == AF_INET6 {
                        // IN6_ADDR 是 union，读 Byte 分支需 unsafe（见模块级文档）。
                        let ip = Ipv6Addr::from(unsafe { sin6.sin6_addr.u.Byte });
                        if is_usable_endpoint_addr(&ip) {
                            addrs.push(ip);
                        }
                    }
                }
                ua = entry.Next;
            }
        }
        current = adapter.Next;
    }
    Ok(addrs)
}

/// 枚举本机可作为 endpoint 的全局 IPv6 地址（过滤 ULA/链路本地等，排除 hextet 接口）。
pub async fn list_global_ipv6(
    exclude_interface: Option<&str>,
) -> Result<Vec<Ipv6Addr>, PlatformError> {
    let exclude = exclude_interface.map(str::to_owned);
    tokio::task::spawn_blocking(move || list_global_ipv6_sync(exclude.as_deref()))
        .await
        .map_err(|e| os(format!("spawn_blocking 失败: {e}")))?
}

/// 给接口配一个 IPv6 地址（`CreateUnicastIpAddressEntry`，ADR-0011 决策 4）。
///
/// MTU 在 Windows 上由 wintun 适配器创建时决定（`tun` crate 的 `Configuration::mtu`），
/// 此处 no-op（与 macOS `setup_interface` 的 no-op 一致）。
pub async fn setup_interface(
    name: &str,
    address: Ipv6Addr,
    prefix_len: u8,
    _mtu: u32,
) -> Result<(), PlatformError> {
    let name = name.to_owned();
    tokio::task::spawn_blocking(move || {
        let luid = iface_luid(&name)?;
        let mut row: MIB_UNICASTIPADDRESS_ROW = unsafe { std::mem::zeroed() };
        unsafe { InitializeUnicastIpAddressEntry(&mut row) };
        row.InterfaceLuid = luid;
        let mut sin6: SOCKADDR_IN6 = unsafe { std::mem::zeroed() };
        sin6.sin6_family = AF_INET6;
        sin6.sin6_addr.u.Byte = address.octets();
        row.Address = SOCKADDR_INET { Ipv6: sin6 };
        row.PrefixOrigin = IpPrefixOriginManual;
        row.SuffixOrigin = IpSuffixOriginManual;
        row.OnLinkPrefixLength = prefix_len;
        row.ValidLifetime = u32::MAX;
        row.PreferredLifetime = u32::MAX;
        let ret = unsafe { CreateUnicastIpAddressEntry(&row) };
        if ret.0 != 0 {
            return Err(win32_error("CreateUnicastIpAddressEntry 失败", ret.0));
        }
        Ok(())
    })
    .await
    .map_err(|e| os(format!("spawn_blocking 失败: {e}")))?
}

/// Windows 侧暂未落地（wintun 适配器随句柄 drop 关闭；显式删除待后续切片）。
pub async fn delete_interface(_name: &str) -> Result<(), PlatformError> {
    Err(PlatformError::Unsupported)
}

/// 把接口名解析成 `NET_LUID_LH`（`ConvertInterfaceNameToLuidW`）。
fn iface_luid(name: &str) -> Result<NET_LUID_LH, PlatformError> {
    let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    let mut luid: NET_LUID_LH = unsafe { std::mem::zeroed() };
    let ret =
        unsafe { ConvertInterfaceNameToLuidW(windows::core::PCWSTR(wide.as_ptr()), &mut luid) };
    if ret.0 != 0 {
        return Err(win32_error("ConvertInterfaceNameToLuidW 失败", ret.0));
    }
    Ok(luid)
}

/// 构造一条 on-link 的 IPv6 路由行（`NextHop` 为未指定 `::`，`SitePrefixLength` =
/// `prefix_len`，与 Linux `ip -6 route add <prefix> dev <iface>` 语义对齐）。
fn route_row(luid: NET_LUID_LH, prefix: Ipv6Addr, prefix_len: u8) -> MIB_IPFORWARD_ROW2 {
    let mut row: MIB_IPFORWARD_ROW2 = unsafe { std::mem::zeroed() };
    unsafe { InitializeIpForwardEntry(&mut row) };
    row.InterfaceLuid = luid;
    let mut sin6: SOCKADDR_IN6 = unsafe { std::mem::zeroed() };
    sin6.sin6_family = AF_INET6;
    // union 字段「写入」在 Copy 字段上是安全操作（只有「读」需 unsafe）。
    sin6.sin6_addr.u.Byte = prefix.octets();
    row.DestinationPrefix = IP_ADDRESS_PREFIX {
        Prefix: SOCKADDR_INET { Ipv6: sin6 },
        PrefixLength: prefix_len,
    };
    row.SitePrefixLength = prefix_len;
    row.Protocol = MIB_IPPROTO_NETMGMT;
    row
}

/// 添加一条 on-link IPv6 路由（`CreateIpForwardEntry2`，ADR-0011 决策 4）。
pub async fn add_route(name: &str, prefix: Ipv6Addr, prefix_len: u8) -> Result<(), PlatformError> {
    let name = name.to_owned();
    tokio::task::spawn_blocking(move || {
        let luid = iface_luid(&name)?;
        let row = route_row(luid, prefix, prefix_len);
        let ret = unsafe { CreateIpForwardEntry2(&row) };
        if ret.0 != 0 {
            return Err(win32_error("CreateIpForwardEntry2 失败", ret.0));
        }
        Ok(())
    })
    .await
    .map_err(|e| os(format!("spawn_blocking 失败: {e}")))?
}

/// 删除一条 on-link IPv6 路由（`DeleteIpForwardEntry2`，ADR-0011 决策 4）。
pub async fn remove_route(
    name: &str,
    prefix: Ipv6Addr,
    prefix_len: u8,
) -> Result<(), PlatformError> {
    let name = name.to_owned();
    tokio::task::spawn_blocking(move || {
        let luid = iface_luid(&name)?;
        let row = route_row(luid, prefix, prefix_len);
        let ret = unsafe { DeleteIpForwardEntry2(&row) };
        if ret.0 != 0 {
            return Err(win32_error("DeleteIpForwardEntry2 失败", ret.0));
        }
        Ok(())
    })
    .await
    .map_err(|e| os(format!("spawn_blocking 失败: {e}")))?
}

/// 枚举 UP 且支持组播的非 loopback 接口（`(if_index, name)`，供 LAN 组播发现 join
/// `ff02::4193` 使用）。Windows 上按 `OperStatus == Up` 判定，名字用 `FriendlyName`。
pub async fn list_multicast_interfaces(
    exclude: Option<&str>,
) -> Result<Vec<(u32, String)>, PlatformError> {
    let exclude = exclude.map(str::to_owned);
    tokio::task::spawn_blocking(move || list_multicast_interfaces_sync(exclude.as_deref()))
        .await
        .map_err(|e| os(format!("spawn_blocking 失败: {e}")))?
}

/// 同步版本的 [`list_multicast_interfaces`]。
fn list_multicast_interfaces_sync(
    exclude: Option<&str>,
) -> Result<Vec<(u32, String)>, PlatformError> {
    let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    let mut size: u32 = 0;
    let ret = unsafe { GetAdaptersAddresses(AF_INET6.0 as u32, flags, None, None, &mut size) };
    if ret != 111 && ret != 232 {
        if ret == 232 {
            return Ok(Vec::new());
        }
        return Err(win32_error("GetAdaptersAddresses 探测缓冲区大小失败", ret));
    }
    if size == 0 {
        return Ok(Vec::new());
    }
    let mut buf = vec![0u8; size as usize];
    let ret = unsafe {
        GetAdaptersAddresses(
            AF_INET6.0 as u32,
            flags,
            None,
            Some(buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH),
            &mut size,
        )
    };
    if ret != 0 {
        return Err(win32_error("GetAdaptersAddresses 失败", ret));
    }
    let mut out = Vec::new();
    let mut current = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
    while !current.is_null() {
        let adapter = unsafe { &*current };
        if adapter.OperStatus == IfOperStatusUp && !is_excluded(adapter, exclude) {
            let name = unsafe { wide_to_string(adapter.FriendlyName.0) }.unwrap_or_default();
            out.push((adapter.Ipv6IfIndex, name));
        }
        current = adapter.Next;
    }
    Ok(out)
}

/// 监听本机全局 IPv6 地址变化（2s 轮询 + 差集发事件，与 macOS 的 `getifaddrs` 轮询
/// 同款策略，ADR-0008 决策 3 / ADR-0011 决策 4）。`if_index` 暂填 0（daemon 只据此
/// 触发重新打洞，不做按接口过滤；如实标注）。
pub async fn watch_ipv6_addresses(
    tx: tokio::sync::mpsc::Sender<AddrEvent>,
) -> Result<(), PlatformError> {
    let mut prev: std::collections::BTreeSet<Ipv6Addr> =
        list_global_ipv6(None).await?.into_iter().collect();
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(2));
    loop {
        tick.tick().await;
        if tx.is_closed() {
            return Ok(());
        }
        let cur: std::collections::BTreeSet<Ipv6Addr> = match list_global_ipv6(None).await {
            Ok(v) => v.into_iter().collect(),
            Err(e) => {
                tracing::debug!(error = %e, "Windows 地址轮询失败，跳过本轮");
                continue;
            }
        };
        for addr in cur.difference(&prev) {
            if tx
                .send(AddrEvent {
                    kind: AddrEventKind::Added,
                    address: *addr,
                    if_index: 0,
                })
                .await
                .is_err()
            {
                return Ok(());
            }
        }
        for addr in prev.difference(&cur) {
            if tx
                .send(AddrEvent {
                    kind: AddrEventKind::Removed,
                    address: *addr,
                    if_index: 0,
                })
                .await
                .is_err()
            {
                return Ok(());
            }
        }
        prev = cur;
    }
}
