//! Windows 10+（wintun）平台集成实现（ADR-0010 的落地）。
//!
//! 与 macOS（ADR-0008）的关键差异：**本模块零 `unsafe`**。macOS 上「给 utun 配 IPv6
//! 地址」没有安全 crate 可承接，被迫写了 ~30 行的 `#![allow(unsafe_code)]` ioctl 封装；
//! Windows 上这条路的等价物是 **shell 出 `netsh`**（`std::process::Command`，完全安全，
//! 按名操作、不依赖句柄、不需要 unsafe）——`wintun` crate 自己配地址也 shell 出 netsh，
//! 说明这是被维护中的 crate 认可的既定做法。因此本模块满足 workspace 的
//! `unsafe_code = "deny"`，一行 unsafe 都不写（ADR-0010 决策 2）。
//!
//! 平台分工（镜像 macOS）：路由走 `net-route`（`with_ifindex`，与 macOS/Linux 同构）、
//! 地址枚举走 `ipconfig`（getifaddrs 的 Windows 等价物，安全无 root）、地址配装走
//! `netsh`、地址变化监听走 2s 轮询。MTU 不在此处施加——wintun 的 MTU 由 `tun` crate 在
//! `open_tun` 时用 `config.mtu()` 设置（同 macOS 的 no-op 语义）。

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv6Addr};
use std::process::Command;

use hextet_core::addr::is_usable_endpoint_addr;
use net_route::{Handle, Route};

use crate::{AddrEvent, AddrEventKind, PlatformError};

/// 把 `std::io::Error` 等可展示错误统一收进 [`PlatformError::Os`]。
fn os(e: impl std::fmt::Display) -> PlatformError {
    PlatformError::Os(e.to_string())
}

// ---------------------------------------------------------------------------
// 地址配装：`netsh interface ipv6 add/delete address`（ADR-0010 决策 2，零 unsafe）。
// ---------------------------------------------------------------------------

/// 运行 `netsh` 并把它映射为 [`PlatformError`]。
///
/// 参数是 `netsh` 之后的整条命令行（不含 `netsh` 本身）。退出码非 0 时把 stderr
/// 拼进 [`PlatformError::Os`]，便于真机排障（stderr 是 locale 相关的，见 ADR-0010
/// 「未能验证」）。
fn run_netsh(args: &[&str]) -> Result<(), PlatformError> {
    let output = Command::new("netsh")
        .args(args)
        .output()
        .map_err(|e| os(format!("failed to spawn netsh: {e}")))?;
    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(os(format!(
            "netsh {} failed: {}",
            args.join(" "),
            stderr.trim()
        )))
    }
}

/// 给接口配一个 IPv6 地址（`netsh interface ipv6 add address "<name>" <addr>/<len>`）。
///
/// 这是 ADR-0010 决策 2 的「零 unsafe 地址配装」：`windows` crate 的
/// `CreateUnicastIpAddressEntry` 是 `unsafe fn`、`wintun` crate 加载 DLL 也是
/// `unsafe fn`，因此按名 shell 出 `netsh`——完全安全、按名操作、无需接口句柄。
/// 需要管理员权限（wintun 适配器本身也是特权资源）。
///
/// 未验证（ADR-0010）：`netsh` 的退出码/locale、以及 `store=` 默认值（persistent）对
/// 「VPN 反复重建适配器」场景是否合适；必要时改用 `store=active`。
pub fn assign_ipv6(name: &str, addr: Ipv6Addr, prefix_len: u8) -> Result<(), PlatformError> {
    let quoted = format!("\"{name}\"");
    let addr_prefix = format!("{addr}/{prefix_len}");
    run_netsh(&["interface", "ipv6", "add", "address", &quoted, &addr_prefix])
}

/// 删除接口上的一个 IPv6 地址（`netsh interface ipv6 delete address "<name>" <addr>`）。
///
/// 与 [`assign_ipv6`] 同为 ADR-0010 决策 2 的零 unsafe 封装，需要管理员权限。
pub fn unassign_ipv6(name: &str, addr: Ipv6Addr) -> Result<(), PlatformError> {
    let quoted = format!("\"{name}\"");
    let addr = addr.to_string();
    run_netsh(&["interface", "ipv6", "delete", "address", &quoted, &addr])
}

// ---------------------------------------------------------------------------
// 平台能力（镜像 macOS 语义，见 `macos.rs`）。
// ---------------------------------------------------------------------------

/// 按接口名查 `ipconfig` 里的 IPv6 接口索引。
///
/// 同时匹配 `friendly_name()` 与 `adapter_name()`：wintun adapter 经 `tun` crate 上报的
/// 名字（friendly name）与 `GetAdaptersAddresses` 的 AdapterName（GUID 形）哪一个对得上
/// 就用哪个（ADR-0010「未能验证」：二者与 `tun::Device::name()` 的逐字一致性需真机确认）。
fn ifindex_by_name(name: &str) -> Result<u32, PlatformError> {
    let adapters = ipconfig::get_adapters().map_err(os)?;
    adapters
        .iter()
        .find(|a| a.friendly_name() == name || a.adapter_name() == name)
        .map(|a| a.ipv6_if_index())
        .ok_or_else(|| PlatformError::NotFound(name.to_owned()))
}

/// 为已存在的接口按名配置 overlay 地址（Windows 版，ADR-0010 决策 2/3）。
///
/// 设备**不**由本函数创建：wintun adapter 归 boringtun 后端（`wg-userspace` 经 `tun`
/// crate）独占并持有，本函数只按后端上报的真实设备名（wintun friendly name）做「配地址」
/// 这一件事——即 [`assign_ipv6`]，与 macOS 版「backend 持有设备、platform 只按名配地址」
/// 同构，**绝不自己再开第二个设备**。
///
/// `mtu` 在 Windows/boringtun 上无法经后端施加（wintun MTU 由 `tun` crate 在 `open_tun`
/// 时设置），第一片按 no-op 处理并如实标注（同 macOS 的 ADR-0009 决策 3）。
pub async fn setup_interface(
    name: &str,
    address: Ipv6Addr,
    prefix_len: u8,
    mtu: u32,
) -> Result<(), PlatformError> {
    // wintun MTU 已由 open_tun 施加，这里 no-op（见函数 doc 与 ADR-0010 决策 2）。
    let _ = mtu;
    assign_ipv6(name, address, prefix_len)
}

/// 删除接口：Windows 上**仍为 `Unsupported`**。
///
/// 与 macOS 的差异：macOS 的 utun 在所有 fd 关闭时自动销毁；Windows 的 wintun adapter 在
/// 所有 session 关闭后**仍持久**（须显式 `WintunDeleteAdapter` 或注册表删除），而 `tun`
/// crate 的 `close_tun`（drop）只关 handle 不删 adapter。因此「按名字删除接口」在 Windows
/// 上没有可操作的落点，须先把 adapter 显式删除能力接进 backend（ADR-0010 决策 3），
/// 在那之前**不假装**支持。
pub async fn delete_interface(_name: &str) -> Result<(), PlatformError> {
    Err(PlatformError::Unsupported)
}

/// 为 `name` 接口添加一条到 `prefix/prefix_len` 的 IPv6 路由（等价 `netsh interface ipv6 add route`）。
///
/// 与 Linux/macOS 版同构：只设 `oif`（出接口）不设网关——WG 隧道是点到多点链路，对端地址由
/// AllowedIPs 决定，OS 路由表里只需要「这个前缀从这条接口出去」。映射到 net-route 的
/// `Route { destination, prefix, gateway: None, ifindex: Some(ifindex) }`，Windows 侧把
/// `ifindex` 写进 `MIB_IPFORWARD_ROW2.InterfaceIndex`（net-route 0.4.6 `windows.rs`）。
pub async fn add_route(name: &str, prefix: Ipv6Addr, prefix_len: u8) -> Result<(), PlatformError> {
    let ifindex = ifindex_by_name(name)?;
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
    let ifindex = ifindex_by_name(name)?;
    let route = Route::new(IpAddr::V6(prefix), prefix_len).with_ifindex(ifindex);
    let handle = Handle::new().map_err(os)?;
    handle.delete(&route).await.map_err(os)
}

/// 抓取一帧「当前可用作公网 endpoint 的全局 IPv6 地址」快照（ipconfig，同步，无需 root）。
///
/// 过滤复用 [`is_usable_endpoint_addr`]（排除 ULA / 链路本地 / loopback / 组播 /
/// unspecified）+ 排除 `exclude_interface`（hextet 自己的 overlay 接口）。结果排序去重。
///
/// 这是 [`list_global_ipv6`] 与 [`watch_ipv6_addresses`] **唯一**的过滤真相来源：两者共用
/// 这一份过滤逻辑，避免「轮询监听」与「一次性枚举」各写一套、逐渐漂移。
///
/// 与 Linux/macOS 版的**诚实差异**（ADR-0010 决策 2）：`ipconfig`（`GetAdaptersAddresses`）
/// 拿不到每个地址的 Deprecated/Tentative 标志（那是逐地址 unicast-entry 标志），只能拿到
/// 接口级 oper_status/if_type。好在 `is_usable_endpoint_addr` 已把链路本地/loopback/ULA 都
/// 排了，剩余差异只有「Deprecated/Tentative 旧地址会短暂出现在结果里」——代价是 endpoint
/// 探测偶尔试一个即将失效的地址，engine 的候选轮换本就容忍，本实现**不假装**过滤了这些标志。
fn current_global_addrs(exclude_interface: Option<&str>) -> Result<Vec<Ipv6Addr>, PlatformError> {
    let adapters = ipconfig::get_adapters().map_err(os)?;
    let mut out = Vec::new();
    for adapter in adapters {
        if exclude_interface
            .is_some_and(|n| adapter.friendly_name() == n || adapter.adapter_name() == n)
        {
            continue;
        }
        for addr in adapter.ip_addresses() {
            let IpAddr::V6(addr) = addr else { continue };
            if is_usable_endpoint_addr(addr) {
                out.push(*addr);
            }
        }
    }
    out.sort();
    out.dedup();
    Ok(out)
}

/// 计算两帧地址快照的差集，返回 `(added, removed)`（各自已按序排好）。
///
/// 纯函数、无 I/O、无时间依赖：`watch_ipv6_addresses` 拿它对比「上一帧 vs 当前帧」。
/// 与 `macos.rs::diff_addrs` 逐行同构（模块按 `cfg` 隔离，不能共享，只能复制）。
fn diff_addrs(previous: &[Ipv6Addr], current: &[Ipv6Addr]) -> (Vec<Ipv6Addr>, Vec<Ipv6Addr>) {
    let prev: BTreeSet<Ipv6Addr> = previous.iter().copied().collect();
    let curr: BTreeSet<Ipv6Addr> = current.iter().copied().collect();
    let added: Vec<Ipv6Addr> = curr.difference(&prev).copied().collect();
    let removed: Vec<Ipv6Addr> = prev.difference(&curr).copied().collect();
    (added, removed)
}

/// 枚举本机可用作公网 endpoint 的 IPv6 地址（ipconfig，无需 root）。
///
/// 直接转发给 [`current_global_addrs`]；过滤规则与诚实差异见该函数（同 ADR-0010 决策 2）。
pub async fn list_global_ipv6(
    exclude_interface: Option<&str>,
) -> Result<Vec<Ipv6Addr>, PlatformError> {
    current_global_addrs(exclude_interface)
}

/// 枚举可用于链路本地组播的接口（ipconfig，无需 root）。
///
/// 过滤规则（镜像 Linux/macOS 版）：排除 `IfType::SoftwareLoopback`、要求
/// `OperStatus::IfOperStatusUp`、排除 `exclude` 指定的接口（hextet 自己的 overlay 接口——
/// 往它上面发 LAN 公告只会走进隧道）。
///
/// 返回 `(ifindex, name)`；index 来自 `Adapter::ipv6_if_index()`（底层即
/// `IP_ADAPTER_ADDRESSES.Ipv6IfIndex`），name 来自 `friendly_name()`。
///
/// 与 Linux 版的**诚实差异**（ADR-0010 决策 2/3）：`ipconfig` 不暴露
/// `IP_ADAPTER_ADDRESSES.Flags` 里的 `IP_ADAPTER_NO_MULTICAST` 位，所以「支持组播」只能
/// 用「非 loopback 且 Up」近似；绝大多数物理/虚拟适配器都支持组播，代价是可能多 join 一个
/// 不支持组播的罕见接口（为零）。与 macOS 版同理，不读 carrier（Windows 上没有
/// `IFF_RUNNING` 的直接对应）。
pub async fn list_multicast_interfaces(
    exclude: Option<&str>,
) -> Result<Vec<(u32, String)>, PlatformError> {
    use ipconfig::{IfType, OperStatus};

    let adapters = ipconfig::get_adapters().map_err(os)?;
    let mut out: Vec<(u32, String)> = Vec::new();
    for adapter in adapters {
        if adapter.if_type() == IfType::SoftwareLoopback {
            continue;
        }
        if adapter.oper_status() != OperStatus::IfOperStatusUp {
            continue;
        }
        if exclude.is_some_and(|n| adapter.friendly_name() == n || adapter.adapter_name() == n) {
            continue;
        }
        out.push((adapter.ipv6_if_index(), adapter.friendly_name().to_owned()));
    }
    out.sort();
    out.dedup();
    Ok(out)
}

/// 监听本机 IPv6 地址变化（ADR-0010 决策 2：2s `ipconfig` 轮询）。
///
/// 每 2s 抓一帧可用全局 IPv6 地址（复用 [`current_global_addrs`]，与
/// [`list_global_ipv6`] 同一份过滤），与上一帧做差集，对新增/删除的地址分别发
/// [`AddrEventKind::Added`]/[`AddrEventKind::Removed`]。**不做去抖**——[`AddrEvent`]
/// 文档已声明调用方（daemon）自行去抖；前缀轮换时「新前缀 Added、旧前缀 Removed」的
/// 多事件序列会被逐条发出，与 Linux/macOS 版「不过滤、全量转发」的契约一致。
///
/// 退出契约：当 `tx` 的接收端被 drop（`tx.send` 返回 `Err`）时干净退出并返回 `Ok`，
/// 与 Linux/macOS 版「接收端关闭 = 正常收尾，不算错误」一致。
///
/// 诚实差异：轮询最多有 2s 延迟（Linux netlink 是毫秒级推送），落在 spec「恢复 <5s」
/// 内；`AddrEvent::if_index` 镜像 macOS 统一填 `0`（地址快照只记地址、不记接口），
/// 调用方（daemon）只把事件当「地址变了」的信号、不读 `if_index`。
pub async fn watch_ipv6_addresses(
    tx: tokio::sync::mpsc::Sender<AddrEvent>,
) -> Result<(), PlatformError> {
    // 先取一帧作为基线：第一帧没有「上一帧」可比，不 diff，与 Linux/macOS 版「只报变化、
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
    use std::net::Ipv6Addr;

    use super::*;

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
}
