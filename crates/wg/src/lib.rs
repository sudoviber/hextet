//! WireGuard 后端抽象：设计 spec §3 D1 的 `WgBackend` trait。
#![deny(missing_docs)]

pub mod mock;
pub mod types;

#[cfg(target_os = "linux")]
pub mod kernel;

use std::net::SocketAddrV6;

use types::{DeviceSpec, PeerSpec, PeerStatus, WgError};

/// WireGuard 数据面后端（kernel / 未来 userspace-gotatun）。
pub trait WgBackend {
    /// 幂等地把设备调到 spec 描述的状态（接口不存在则创建），并返回 OS 层真实设备名，
    /// 供调用方随后按名配地址/路由（ADR-0009 决策 3）。
    ///
    /// Linux：恒等于 `spec.interface`（内核 WG 设备名即配置名）；
    /// macOS/gotatun：将是真实 `utunN`（配置名 `hextet0` 经 ADR-0009 决策 2 的
    /// 映射/读回得到）——决策 2 落地前各后端均恒等返回 `spec.interface`。
    fn apply(&self, spec: &DeviceSpec) -> Result<String, WgError>;
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

    /// 运行时新增一个 peer（gossip 准入时，不必重放整设备配置）。
    fn add_peer(&self, interface: &str, spec: &PeerSpec) -> Result<(), WgError>;

    /// 运行时移除一个 peer（gossip 吊销时，立即从数据面拒绝该公钥）。
    fn remove_peer(&self, interface: &str, wg_public: &[u8; 32]) -> Result<(), WgError>;

    /// 拆除设备（ADR-0009 决策 5）。
    ///
    /// Linux：**不是** Linux 的拆除路径——内核 WG 设备由内核持有，删除走
    /// `platform::delete_interface`（rtnetlink）；`hextet-wg` 不依赖 platform，因此
    /// 内核后端如实返回错误，把分派留给 CLI。macOS：drop 后端持有的设备句柄，utun
    /// 随句柄释放而销毁（设备生命周期 == 持有它的进程生命周期）。
    fn down(&self, interface: &str) -> Result<(), WgError>;
}
