//! macOS（arm64 / x86_64）平台集成实现（ADR-0008 决策 1/2 的落地）。
//!
//! 本模块是 workspace 内**唯一**允许 `unsafe` 的地方（见模块级 `#![allow(unsafe_code)]`
//! 与 [`assign_ipv6`] 的文档）。理由与边界写在
//! `docs/adr/ADR-0008-macos-platform-networking.md` 决策 1：macOS 上给 utun 配 IPv6
//! 地址没有维护中的安全 crate 可承接——`tun` crate 的 macOS 地址配装是 IPv4 专用
//! （`SIOCAIFADDR` + `ifaliasreq`，无 `sockaddr_in6`）；`nix` 的 ioctl 宏生成的仍是
//! `unsafe fn`；`net-route` 只做路由。于是这里被迫手写一个 ~30 行的最小 ioctl 封装，
//! 只封 `SIOCAIFADDR_IN6` / `SIOCDIFADDR_IN6` 两个 ioctl。一旦出现维护中的安全替代
//! （或 `net-route` 补上地址配装），即删除本封装（ADR-0008 重新评估触发条件 2）。
//!
//! 其余能力**零 unsafe**：路由走 `net-route`（PF_ROUTE 安全封装）、地址枚举走
//! `getifaddrs`（安全、无 root）。unsafe 只被圈在地址配装的 ioctl 里；MTU 在 macOS
//! 上不施加（boringtun 的 `DeviceConfig` 无 mtu 字段，ADR-0009 决策 3 第一片 no-op，
//! 必要时补 `SIOCSIFMTU` 按名 ioctl）。

#![allow(unsafe_code)]

use std::collections::BTreeSet;
use std::mem::size_of;
use std::net::{IpAddr, Ipv6Addr};

use hextet_core::addr::is_usable_endpoint_addr;
use net_route::{Handle, Route, ifname_to_index};

use crate::{AddrEvent, AddrEventKind, PlatformError};

/// 把 `std::io::Error` 等可展示错误统一收进 [`PlatformError::Os`]。
fn os(e: impl std::fmt::Display) -> PlatformError {
    PlatformError::Os(e.to_string())
}

// ---------------------------------------------------------------------------
// 最小安全封装：`SIOCAIFADDR_IN6` / `SIOCDIFADDR_IN6`（见模块级文档）。
// ---------------------------------------------------------------------------

/// `struct in6_aliasreq`（Darwin `netinet6/in6_var.h`）的精确镜像，`#[repr(C)]`。
///
/// 布局逐字节对齐 SDK 头文件：`char ifra_name[IFNAMSIZ]` + 三个 `sockaddr_in6` +
/// `int ifra_flags` + `in6_addrlifetime`，总大小 128 字节（有编译期断言兜底）。
/// 未读取的字段只参与内存布局，供内核读取，故 `#[allow(dead_code)]`。
#[repr(C)]
#[allow(dead_code)]
struct In6Aliasreq {
    ifra_name: [libc::c_char; libc::IFNAMSIZ],
    ifra_addr: libc::sockaddr_in6,
    ifra_dstaddr: libc::sockaddr_in6,
    ifra_prefixmask: libc::sockaddr_in6,
    ifra_flags: libc::c_int,
    ifra_lifetime: libc::in6_addrlifetime,
}

/// `struct in6_ifreq`（Darwin `netinet6/in6_var.h`）的精确镜像，`#[repr(C)]`。
///
/// 我们只用 `ifr_name` + `ifru_addr`（`SIOCDIFADDR_IN6` 只读这两者）；union 的其余
/// 成员用显式 padding 对齐到 `sizeof(struct in6_ifreq) == 288` 字节（编译期断言兜底），
/// 保证 ioctl 编码里的长度字段与内核一致。
#[repr(C)]
struct In6Ifreq {
    ifr_name: [libc::c_char; libc::IFNAMSIZ],
    ifru_addr: libc::sockaddr_in6,
    _pad: [u8; 288 - libc::IFNAMSIZ - size_of::<libc::sockaddr_in6>()],
}

const _: () = {
    assert!(size_of::<In6Aliasreq>() == 128, "in6_aliasreq 布局漂移");
    assert!(size_of::<In6Ifreq>() == 288, "in6_ifreq 布局漂移");
    assert!(
        size_of::<libc::sockaddr_in6>() == 28,
        "sockaddr_in6 布局漂移"
    );
};

/// `SIOCAIFADDR_IN6`（`_IOW('i', 26, struct in6_aliasreq)`）。
const SIOCAIFADDR_IN6: libc::c_ulong = libc::_IOW::<In6Aliasreq>(b'i' as libc::c_ulong, 26);

/// `SIOCDIFADDR_IN6`（`_IOW('i', 25, struct in6_ifreq)`）。
const SIOCDIFADDR_IN6: libc::c_ulong = libc::_IOW::<In6Ifreq>(b'i' as libc::c_ulong, 25);

/// 构造一个 `sockaddr_in6`（`sin6_len` 显式填 28，BSD 惯例）。
fn v6_sockaddr(addr: Ipv6Addr) -> libc::sockaddr_in6 {
    libc::sockaddr_in6 {
        sin6_len: size_of::<libc::sockaddr_in6>() as u8,
        sin6_family: libc::AF_INET6 as libc::sa_family_t,
        sin6_port: 0,
        sin6_flowinfo: 0,
        sin6_addr: libc::in6_addr {
            s6_addr: addr.octets(),
        },
        sin6_scope_id: 0,
    }
}

/// 由前缀长度构造网段掩码地址（`/48` → `ffff:ffff:ffff::`）。
fn prefix_mask(prefix_len: u8) -> Ipv6Addr {
    let mut octets = [0u8; 16];
    let mut remaining = prefix_len;
    for octet in &mut octets {
        *octet = match remaining {
            0 => 0,
            n if n >= 8 => 0xff,
            n => 0xff << (8 - n),
        };
        remaining = remaining.saturating_sub(8);
    }
    Ipv6Addr::from(octets)
}

/// 把接口名复制进 `ifr_name`（0 填充、NUL 结尾）。名字过长视为不存在。
fn copy_ifname(dst: &mut [libc::c_char; libc::IFNAMSIZ], name: &str) -> Result<(), PlatformError> {
    let bytes = name.as_bytes();
    if bytes.len() >= libc::IFNAMSIZ {
        return Err(PlatformError::NotFound(name.to_owned()));
    }
    dst.fill(0);
    for (d, b) in dst.iter_mut().zip(bytes) {
        *d = *b as libc::c_char;
    }
    Ok(())
}

/// 用任意一个 AF_INET6 socket 承载接口级 ioctl，把 errno 映射为 [`PlatformError`]。
fn ioctl_in6<T>(request: libc::c_ulong, arg: &mut T, name: &str) -> Result<(), PlatformError> {
    let fd = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(PlatformError::Os(
            std::io::Error::last_os_error().to_string(),
        ));
    }
    let rc = unsafe { libc::ioctl(fd, request, arg as *mut T as *mut libc::c_void) };
    let err = std::io::Error::last_os_error();
    unsafe { libc::close(fd) };
    if rc < 0 {
        // ENXIO/ENODEV：接口不存在 → 与 Linux 侧 ENODEV 判定同构，映射为 NotFound。
        match err.raw_os_error() {
            Some(e) if e == libc::ENXIO || e == libc::ENODEV => {
                Err(PlatformError::NotFound(name.to_owned()))
            }
            _ => Err(PlatformError::Os(err.to_string())),
        }
    } else {
        Ok(())
    }
}

/// 给接口配一个 IPv6 地址（`SIOCAIFADDR_IN6`，等价 `ifconfig <if> inet6 <addr>/<len>`）。
///
/// 这是 ADR-0008 决策 1 的「最小安全封装」对外暴露的**安全**函数：unsafe 被圈在
/// [`ioctl_in6`] 里，调用方零 unsafe。需要 root（utun 是特权资源）。
///
/// `in6_aliasreq` 里两个刻意留空/留零、需真机确认的语义（见 ADR-0008「未能验证」）：
/// - `ifra_dstaddr` 保持 `::`（未指定），与 `ifconfig ... inet6 ...` 默认一致；utun 是
///   点到多点，是否应填 site 地址未在真机确认。
/// - `ifra_lifetime` 保持全 0 = 永久地址（`ia6t_expire/preferred/vltime/pltime` 全 0）。
pub fn assign_ipv6(name: &str, addr: Ipv6Addr, prefix_len: u8) -> Result<(), PlatformError> {
    // 名字合法性前置检查（也落实 ADR 里 if_nametoindex 的语义：不存在 → NotFound）。
    getifaddrs::if_nametoindex(name).map_err(|_| PlatformError::NotFound(name.to_owned()))?;

    let mut req: In6Aliasreq = unsafe { std::mem::zeroed() };
    copy_ifname(&mut req.ifra_name, name)?;
    req.ifra_addr = v6_sockaddr(addr);
    req.ifra_prefixmask = v6_sockaddr(prefix_mask(prefix_len));

    ioctl_in6(SIOCAIFADDR_IN6, &mut req, name)
}

/// 删除接口上的一个 IPv6 地址（`SIOCDIFADDR_IN6`，等价 `ifconfig <if> inet6 <addr> delete`）。
///
/// 与 [`assign_ipv6`] 同为 ADR-0008 决策 1 的安全封装，需要 root。
pub fn unassign_ipv6(name: &str, addr: Ipv6Addr) -> Result<(), PlatformError> {
    getifaddrs::if_nametoindex(name).map_err(|_| PlatformError::NotFound(name.to_owned()))?;

    let mut req: In6Ifreq = unsafe { std::mem::zeroed() };
    copy_ifname(&mut req.ifr_name, name)?;
    req.ifru_addr = v6_sockaddr(addr);

    ioctl_in6(SIOCDIFADDR_IN6, &mut req, name)
}

// ---------------------------------------------------------------------------
// 平台能力（镜像 Linux 语义）。
// ---------------------------------------------------------------------------

/// 为已存在的接口按名配置 overlay 地址（macOS 版，ADR-0009 决策 1/3）。
///
/// 设备**不**由本函数创建：utun 归 boringtun 后端（`wg-userspace`）独占并持有，本
/// 函数只按后端上报的真实设备名（`utunN`）做「配地址」这一件事——即
/// [`assign_ipv6`](`assign_ipv6(name, address, prefix_len)`)，与 Linux 版「内核 WG
/// 持有设备、platform 只按名配地址」同构，**绝不自己再开第二个设备**（已删除旧的
/// `open_tun` 步骤）。
///
/// `name` 的语义已从「我们想开的名字」变为「backend 上报的真实名字」（ADR-0009
/// 决策 3 的 `WgBackend::apply -> Result<String>` 返回值）。`mtu` 在 macOS/boringtun
/// 上无法经后端施加（`DeviceConfig` 无 mtu 字段），第一片按 no-op 处理并如实标注
/// （ADR-0009 决策 3 与「未能验证」），必要时补 `SIOCSIFMTU` 按名 ioctl（ADR-0008
/// 最小封装）。
pub async fn setup_interface(
    name: &str,
    address: Ipv6Addr,
    prefix_len: u8,
    mtu: u32,
) -> Result<(), PlatformError> {
    // macOS/boringtun 无法设置 MTU，第一片 no-op（见函数 doc 与 ADR-0009 决策 3）。
    let _ = mtu;
    assign_ipv6(name, address, prefix_len)
}

/// 删除接口：macOS 上**仍为 `Unsupported`**，阻塞于 Task 35 的设备句柄生命周期架构。
///
/// macOS 的 utun 在**所有 fd 关闭时自动销毁**——`tun` crate 的 `close_tun` 已覆盖「关闭
/// 设备句柄」这一步。但 [`setup_interface`] 目前是一次性「建 + 配」：函数返回时
/// [`crate::tun::TunHandle`] 被 drop、设备随即消失，调用方拿不到一个跨生命周期持有的
/// 句柄。因此「按名字删除接口」在这里没有可操作的落点：既没有常驻句柄可关，也没有
/// Linux 侧 `ip link del` 那样的显式删除 ioctl。要真正支持 `delete_interface`，须先把
/// 设备句柄的持有权提升到 platform/engine/cli 的生命周期（Task 35 的 handle-lifetime
/// 调整），届时本函数 = 关闭那个句柄；在那之前**不假装**支持。
pub async fn delete_interface(_name: &str) -> Result<(), PlatformError> {
    Err(PlatformError::Unsupported)
}

/// 为 `name` 接口添加一条到 `prefix/prefix_len` 的 IPv6 路由（等价 `route -n add -inet6`）。
///
/// 与 Linux 版同构：只设 `oif`（出接口）不设网关——WG 隧道是点到多点链路，对端地址由
/// AllowedIPs 决定，OS 路由表里只需要「这个前缀从这条接口出去」。映射到 net-route 的
/// `Route { destination, prefix, gateway: None, ifindex: Some(ifname_to_index(name)?) }`。
pub async fn add_route(name: &str, prefix: Ipv6Addr, prefix_len: u8) -> Result<(), PlatformError> {
    let ifindex = ifname_to_index(name).ok_or_else(|| PlatformError::NotFound(name.to_owned()))?;
    let route = Route::new(IpAddr::V6(prefix), prefix_len).with_ifindex(ifindex);
    let handle = Handle::new().map_err(os)?;
    handle.add(&route).await.map_err(os)
}

/// 删除 [`add_route`] 装上的那条路由（按同样的 `prefix/prefix_len` + 出接口精确匹配）。
pub async fn remove_route(
    name: &str,
    prefix: Ipv6Addr,
    prefix_len: u8,
) -> Result<(), PlatformError> {
    let ifindex = ifname_to_index(name).ok_or_else(|| PlatformError::NotFound(name.to_owned()))?;
    let route = Route::new(IpAddr::V6(prefix), prefix_len).with_ifindex(ifindex);
    let handle = Handle::new().map_err(os)?;
    handle.delete(&route).await.map_err(os)
}

/// 抓取一帧「当前可用作公网 endpoint 的全局 IPv6 地址」快照（getifaddrs，同步，无需 root）。
///
/// 过滤复用 [`is_usable_endpoint_addr`]（排除 ULA / 链路本地 / loopback / 组播 /
/// unspecified）+ 排除 `exclude_interface`（hextet 自己的 overlay 接口）。结果排序去重。
///
/// 这是 [`list_global_ipv6`] 与 [`watch_ipv6_addresses`] **唯一**的过滤真相来源：两者共用
/// 这一份过滤逻辑，避免「轮询监听」与「一次性枚举」各写一套、逐渐漂移。
///
/// 与 Linux 版的**诚实差异**（ADR-0008 决策 2）：Linux 额外用 netlink 的
/// `scope == Universe` 与 `Deprecated/Tentative/Dadfailed` 逐地址标志过滤；`getifaddrs`
/// 拿不到每个地址的 Deprecated/Tentative 标志（那是 `SIOCGIFAFLAG_IN6` / 路由套接字
/// 才有的，unsafe），只能拿到接口级 `IFF_*`。好在 `is_usable_endpoint_addr` 已把链路
/// 本地/loopback/ULA 都排了，剩余差异只有「Deprecated/Tentative 旧地址会短暂出现在结果
/// 里」——代价是 endpoint 探测偶尔试一个即将失效的地址，engine 的候选轮换本就容忍，
/// 本实现**不假装**过滤了这些标志。
fn current_global_addrs(exclude_interface: Option<&str>) -> Result<Vec<Ipv6Addr>, PlatformError> {
    let interfaces = getifaddrs::getifaddrs().map_err(os)?;
    let mut out = Vec::new();
    for iface in interfaces {
        if Some(iface.name.as_str()) == exclude_interface {
            continue;
        }
        let Some(IpAddr::V6(addr)) = iface.address.ip_addr() else {
            continue;
        };
        if is_usable_endpoint_addr(&addr) {
            out.push(addr);
        }
    }
    out.sort();
    out.dedup();
    Ok(out)
}

/// 计算两帧地址快照的差集，返回 `(added, removed)`（各自已按序排好）。
///
/// 纯函数、无 I/O、无时间依赖：`watch_ipv6_addresses` 拿它对比「上一帧 vs 当前帧」。
/// 轮询循环本身依赖真实时间、无法确定性测试，这里把唯一可测的部分（新增/删除判定）
/// 抽出来单测（见 [`tests::diff_addrs_detects_added_and_removed`]）。
fn diff_addrs(previous: &[Ipv6Addr], current: &[Ipv6Addr]) -> (Vec<Ipv6Addr>, Vec<Ipv6Addr>) {
    let prev: BTreeSet<Ipv6Addr> = previous.iter().copied().collect();
    let curr: BTreeSet<Ipv6Addr> = current.iter().copied().collect();
    let added: Vec<Ipv6Addr> = curr.difference(&prev).copied().collect();
    let removed: Vec<Ipv6Addr> = prev.difference(&curr).copied().collect();
    (added, removed)
}

/// 枚举本机可用作公网 endpoint 的 IPv6 地址（getifaddrs，无需 root）。
///
/// 直接转发给 [`current_global_addrs`]；过滤规则与诚实差异见该函数（同 ADR-0008 决策 2）。
pub async fn list_global_ipv6(
    exclude_interface: Option<&str>,
) -> Result<Vec<Ipv6Addr>, PlatformError> {
    current_global_addrs(exclude_interface)
}

/// 枚举可用于链路本地组播的接口（getifaddrs，无需 root）。
///
/// 过滤规则（镜像 Linux 版 [`crate::list_multicast_interfaces`]）：必须 `IFF_UP` 且
/// `IFF_MULTICAST`，排除 `IFF_LOOPBACK` 与 `exclude` 指定的接口（hextet 自己的 overlay
/// 接口——往它上面发 LAN 公告只会走进隧道）。不看 `IFF_RUNNING`（carrier），理由同
/// Linux 版：容器与虚拟接口上这个位的语义不一致，宁可多 join 一个没插线的接口。
///
/// 返回 `(ifindex, name)`；index 来自 getifaddrs 的 `Interface::index`（底层即
/// `if_nametoindex`）。
///
/// 与 Linux 版的**诚实差异**：`getifaddrs` 只枚举「有地址」的接口——它按地址族对同一
/// 接口各产出一条记录（AF_LINK/AF_INET/AF_INET6），所以同一接口会出现多次，这里用
/// sort+dedup 归并；也因此，一个既无 MAC 又无 IPv4/IPv6 地址的接口对 getifaddrs 完全
/// 不可见，会被漏掉。对 LAN 组播的真实用例（物理网卡 en0 等既有 MAC 又有 IP）没有影响，
/// 但严格意义上不如 Linux netlink 的「列全所有 link」完整。
pub async fn list_multicast_interfaces(
    exclude: Option<&str>,
) -> Result<Vec<(u32, String)>, PlatformError> {
    use getifaddrs::InterfaceFlags;

    let interfaces = getifaddrs::getifaddrs().map_err(os)?;
    let mut out: Vec<(u32, String)> = Vec::new();
    for iface in interfaces {
        let flags = iface.flags;
        if flags.contains(InterfaceFlags::LOOPBACK) {
            continue;
        }
        if !flags.contains(InterfaceFlags::UP) || !flags.contains(InterfaceFlags::MULTICAST) {
            continue;
        }
        if exclude == Some(iface.name.as_str()) {
            continue;
        }
        let Some(index) = iface.index else {
            continue;
        };
        out.push((index, iface.name));
    }
    out.sort();
    out.dedup();
    Ok(out)
}

/// 监听本机 IPv6 地址变化（ADR-0008 决策 2：2s `getifaddrs` 轮询）。
///
/// 每 2s 抓一帧可用全局 IPv6 地址（复用 [`current_global_addrs`]，与
/// [`list_global_ipv6`] 同一份过滤），与上一帧做差集，对新增/删除的地址分别发
/// [`AddrEventKind::Added`]/[`AddrEventKind::Removed`]。**不做去抖**——[`AddrEvent`]
/// 文档已声明调用方（daemon）自行去抖；前缀轮换时「新前缀 Added、旧前缀 Removed」的
/// 多事件序列会被逐条发出，与 Linux 版「不过滤、全量转发」的契约一致。
///
/// 退出契约：当 `tx` 的接收端被 drop（`tx.send` 返回 `Err`）时干净退出并返回 `Ok`，
/// 与 Linux 版「接收端关闭 = 正常收尾，不算错误」一致。
///
/// 诚实差异：轮询最多有 2s 延迟（Linux netlink 是毫秒级推送），落在 spec「恢复 <5s」
/// 内；`AddrEvent::if_index` 在 macOS 上没有对应物（地址快照只记地址、不记接口），
/// 统一填 `0`，调用方（daemon）只把事件当「地址变了」的信号、不读 `if_index`。
pub async fn watch_ipv6_addresses(
    tx: tokio::sync::mpsc::Sender<AddrEvent>,
) -> Result<(), PlatformError> {
    // 先取一帧作为基线：第一帧没有「上一帧」可比，不 diff，与 Linux 版「只报变化、
    // 不报初始全量」的语义一致。
    let mut previous = current_global_addrs(None)?;
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(2));
    // 立刻消耗第一个 tick（interval 的首个 tick 是即时的），避免拿到基线后马上空转一轮。
    interval.tick().await;

    loop {
        interval.tick().await;
        let current = current_global_addrs(None)?;
        let (added, removed) = diff_addrs(&previous, &current);
        previous = current;

        for address in removed {
            let event = AddrEvent {
                kind: AddrEventKind::Removed,
                address,
                if_index: 0,
            };
            if tx.send(event).await.is_err() {
                return Ok(());
            }
        }
        for address in added {
            let event = AddrEvent {
                kind: AddrEventKind::Added,
                address,
                if_index: 0,
            };
            if tx.send(event).await.is_err() {
                return Ok(());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::net::{IpAddr, Ipv6Addr};

    use super::*;

    /// 无需 root：ioctl 常量必须与 Darwin 头文件逐位一致（值来自
    /// `sys/ioccom.h` 的 `_IOW('i', 26, struct in6_aliasreq)` 与
    /// `_IOW('i', 25, struct in6_ifreq)`，以及 `sizeof(in6_aliasreq)=128`、
    /// `sizeof(in6_ifreq)=288`）。
    #[test]
    fn ioctl_numbers_match_darwin_headers() {
        assert_eq!(SIOCAIFADDR_IN6, 0x8080_691a);
        assert_eq!(SIOCDIFADDR_IN6, 0x8120_6919);
    }

    /// 无需 root：前缀掩码构造的边界（/0、/48、/64、/128）。
    #[test]
    fn prefix_mask_boundaries() {
        assert_eq!(prefix_mask(0), Ipv6Addr::UNSPECIFIED);
        assert_eq!(
            prefix_mask(48),
            Ipv6Addr::from(0xffff_ffff_ffff_0000_0000_0000_0000_0000)
        );
        assert_eq!(
            prefix_mask(64),
            Ipv6Addr::from(0xffff_ffff_ffff_ffff_0000_0000_0000_0000)
        );
        assert_eq!(
            prefix_mask(128),
            Ipv6Addr::from(0xffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff)
        );
    }

    /// 无需 root：断言 `list_global_ipv6` 的结果都过 `is_usable_endpoint_addr`，
    /// 且排除接口上的地址一个都不出现。用 getifaddrs 直接枚举一遍作 ground truth，
    /// 与 `list_global_ipv6(None)` 的结果（排序去重后）对拍。
    #[tokio::test]
    async fn list_global_ipv6_filters_usable_and_excludes_interface() {
        // ground truth：本机所有"会被判定为可用 endpoint"的全局 IPv6 地址，按接口归组。
        let mut usable_by_iface: BTreeMap<String, Vec<Ipv6Addr>> = BTreeMap::new();
        for iface in getifaddrs::getifaddrs().unwrap() {
            if let Some(IpAddr::V6(a)) = iface.address.ip_addr()
                && is_usable_endpoint_addr(&a)
            {
                usable_by_iface
                    .entry(iface.name.clone())
                    .or_default()
                    .push(a);
            }
        }

        let all = super::list_global_ipv6(None).await.unwrap();
        let mut expected: Vec<Ipv6Addr> = usable_by_iface.values().flatten().copied().collect();
        expected.sort();
        expected.dedup();
        assert_eq!(all, expected, "不排除接口时应等于全量可用地址");

        // 每个结果都必须过 endpoint 可用性判定。
        for a in &all {
            assert!(is_usable_endpoint_addr(a), "不该出现在结果里的地址: {a}");
        }

        // 排除一个真实存在且带可用地址的接口（若有），其地址一个都不应再出现。
        if let Some((name, addrs)) = usable_by_iface.iter().next() {
            let filtered = super::list_global_ipv6(Some(name)).await.unwrap();
            for a in addrs {
                assert!(
                    !filtered.contains(a),
                    "{a} 在排除接口 {name} 上，不应出现在结果里"
                );
            }
        }
    }

    /// 无需 root：`list_multicast_interfaces` 应只返回 getifaddrs 里
    /// `IFF_UP | IFF_MULTICAST` 且非 `IFF_LOOPBACK` 的接口，并排除指定接口。
    /// 与直接 getifaddrs 枚举出的 ground truth 对拍。
    #[tokio::test]
    async fn list_multicast_interfaces_filters_up_multicast_nonloopback() {
        use getifaddrs::InterfaceFlags;

        // ground truth：独立重算一遍「UP+MULTICAST+!LOOPBACK」的接口集合，按 ifindex 去重。
        let mut expected: BTreeMap<u32, String> = BTreeMap::new();
        for iface in getifaddrs::getifaddrs().unwrap() {
            let flags = iface.flags;
            if flags.contains(InterfaceFlags::LOOPBACK) {
                continue;
            }
            if !flags.contains(InterfaceFlags::UP) || !flags.contains(InterfaceFlags::MULTICAST) {
                continue;
            }
            let Some(index) = iface.index else { continue };
            expected.entry(index).or_insert(iface.name);
        }
        let mut expected: Vec<(u32, String)> = expected.into_iter().collect();
        expected.sort();

        let mut actual = super::list_multicast_interfaces(None).await.unwrap();
        actual.sort();
        actual.dedup();
        assert_eq!(
            actual, expected,
            "不排除接口时应等于 UP+MULTICAST+!LOOPBACK 的接口集合"
        );

        // 排除一个真实存在的接口（若有），它不应再出现。
        if let Some((_, ex_name)) = expected.first() {
            let filtered = super::list_multicast_interfaces(Some(ex_name.as_str()))
                .await
                .unwrap();
            assert!(
                !filtered.iter().any(|(_, name)| name == ex_name),
                "排除接口 {ex_name} 不应出现在结果里"
            );
        }
    }

    /// 无需 root：纯 diff 逻辑。轮询循环本身依赖真实时间、无法确定性测试，这里只测
    /// 可抽离的新增/删除判定（`watch_ipv6_addresses` 用它对比「上一帧 vs 当前帧」）。
    #[test]
    fn diff_addrs_detects_added_and_removed() {
        let prev: Vec<Ipv6Addr> = ["2001:db8::1", "2001:db8::2", "2001:db8::3"]
            .iter()
            .map(|s| s.parse().unwrap())
            .collect();
        let curr: Vec<Ipv6Addr> = ["2001:db8::2", "2001:db8::3", "2001:db8::4"]
            .iter()
            .map(|s| s.parse().unwrap())
            .collect();

        // ::2 与 ::3 两帧都在；::1 只在前一帧（Removed）；::4 只在当前帧（Added）。
        let (added, removed) = super::diff_addrs(&prev, &curr);
        assert_eq!(added, vec!["2001:db8::4".parse::<Ipv6Addr>().unwrap()]);
        assert_eq!(removed, vec!["2001:db8::1".parse::<Ipv6Addr>().unwrap()]);

        // 无变化 → 空差集。
        let (added, removed) = super::diff_addrs(&prev, &prev);
        assert!(added.is_empty() && removed.is_empty());

        // 空基线 → 全部判定为新增。
        let (added, removed) = super::diff_addrs(&[], &prev);
        assert_eq!(added.len(), prev.len());
        assert!(removed.is_empty());
    }

    /// 需要 root + macOS：`sudo -E cargo test -p hextet-platform -- --ignored`。
    /// 在真实 utun 上配/删一个 ULA 地址（`fd00:dead:beef::1/48`）。
    #[tokio::test]
    #[ignore = "requires root"]
    async fn assign_and_unassign_ipv6_on_utun() {
        let cfg = crate::tun::TunConfig {
            name: "utun".into(),
            mtu: 1400,
        };
        let t = crate::tun::open_tun(&cfg)
            .await
            .expect("需要 root 才能打开 utun");
        let name = t.name().to_owned();
        let addr: Ipv6Addr = "fd00:dead:beef::1".parse().unwrap();

        assign_ipv6(&name, addr, 48).expect("配地址");
        unassign_ipv6(&name, addr).expect("删地址");

        crate::tun::close_tun(t).await.expect("close_tun 不应报错");
    }

    /// 需要 root + macOS：`sudo -E cargo test -p hextet-platform -- --ignored`。
    /// 在真实 utun 上加/删一条「仅 oif、无网关」的 ULA 路由。
    #[tokio::test]
    #[ignore = "requires root"]
    async fn add_and_remove_route_on_utun() {
        let cfg = crate::tun::TunConfig {
            name: "utun".into(),
            mtu: 1400,
        };
        let t = crate::tun::open_tun(&cfg)
            .await
            .expect("需要 root 才能打开 utun");
        let name = t.name().to_owned();
        let addr: Ipv6Addr = "fd00:dead:beef::1".parse().unwrap();
        let prefix: Ipv6Addr = "fd00:dead:beef::".parse().unwrap();

        assign_ipv6(&name, addr, 48).expect("配地址");
        add_route(&name, prefix, 48).await.expect("加路由");
        remove_route(&name, prefix, 48).await.expect("删路由");
        unassign_ipv6(&name, addr).expect("删地址");

        crate::tun::close_tun(t).await.expect("close_tun 不应报错");
    }
}
