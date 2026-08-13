//! hextet 用户态 WireGuard 后端（gotatun，ADR-0007 决策 1 / ADR-0012 定方向）。
//!
//! 本 crate 实现 [`hextet_wg::WgBackend`] trait，用 gotatun 0.8.1 的
//! [`Device`] 承载用户态数据面（macOS/Windows/Android 的
//! WireGuard 数据面）。gotatun 类型**不**暴露到 crate 之外——对外只有
//! [`UserspaceBackend`]，与 boringtun 时代的隔离策略一致。
//!
//! ## sync→async 桥（关键设计）
//!
//! [`WgBackend`] trait 是**同步**的（`fn apply(...) -> Result<...>`），而 gotatun 的
//! `Device` 是**异步**（tokio）的。桥接方式：`UserspaceBackend` 内嵌一个
//! `tokio::runtime::Runtime`，每个 trait 方法用 `self.rt.block_on(async { ... })` 包裹。
//! `DeviceBuilder::build().await` 内部会 `Connection::set_up` 并 `spawn` 后台任务
//! （TUN 出站/入站、定时器）到**当前 runtime**；只要 build 与后续 read/write 都走
//! **同一个** runtime 的 `block_on`，后台任务就持续跑在该 runtime 的 worker 上。
//! 这是「在同步库里内嵌 runtime」的标准姿势（见 docs/dev/gotatun-migration.md §5）。
//!
//! ## 诚实边界
//!
//! `apply`/`down` 需要 root（真实 utun/TUN + 绑 UDP 端口）。本机（macOS 无 root）
//! 只做编译验证 + 无 root 的单元测试（`resolve` 逻辑、`tests/gotatun_noise.rs` 的
//! 进程内噪声冒烟）；**真实 TUN 那一层**（`Device` + `TunDevice` 的建/读/改/删）由
//! `tests/userspace_backend_tun.rs` 覆盖：Linux 上在 `scripts/e2e-docker.sh` 的
//! `--privileged` 容器里跑通（开真实 `/dev/net/tun`），macOS 上 `sudo cargo test -p
//! hextet-wg-userspace --test userspace_backend_tun` 真机 root 跑（`apply` 请求裸
//! `utun` 并读回真实 `utunN`）；非 root 一律跳过。macOS 的 utun 路径尚未在本机真跑
//! （需要 sudo，且会动宿主机的 utun/路由，按「不搞乱系统环境」的约束留真机）。

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, SocketAddrV6};
use std::sync::Mutex;
use std::time::SystemTime;

use gotatun::device::{DefaultDeviceTransports, Device, DeviceBuilder, DeviceTransports, Peer};
use gotatun::tun::tun_async_device::TunDevice;
use gotatun::udp::socket::UdpSocketFactory;
use gotatun::x25519::{PublicKey, StaticSecret};
use hextet_wg::WgBackend;
use hextet_wg::types::{DeviceSpec, PeerSpec, PeerStatus, WgError};
use ipnetwork::IpNetwork;

/// 裸 fd 的 TUN 传输（M7 切片 C：Android VpnService fd 适配 gotatun `IpSend`/`IpRecv`）。
#[cfg(unix)]
pub mod raw_fd;

#[cfg(unix)]
use crate::raw_fd::RawFdTun;

/// 登记在 `devices` 表里的一个 gotatun 设备：命名 TUN（桌面）或裸 fd（Android）。
///
/// gotatun 的 `Device` 是 `Device<T: DeviceTransports>`（T 里含着 TUN 传输类型），
/// 命名 TUN 与裸 fd 是两个不同的 `T`，没法装进同一个 `HashMap<String, Device<...>>`；
/// 用枚举统一。
enum DeviceHandle {
    /// 命名 TUN（Linux `/dev/net/tun` / macOS `utun` / Windows wintun）。
    Named(Device<DefaultDeviceTransports>),
    /// 裸 fd（Android VpnService；M7 切片 C）。
    #[cfg(unix)]
    Fd(Device<(UdpSocketFactory, RawFdTun, RawFdTun)>),
}

/// 用户态（gotatun）WireGuard 后端。
///
/// 内嵌一个 tokio runtime 桥接 gotatun 的异步 `Device`；`devices` 按**真实设备名**
/// 登记、`aliases` 存「逻辑名 → 真实名」映射（ADR-0009 决策 2）。
pub struct UserspaceBackend {
    rt: tokio::runtime::Runtime,
    devices: Mutex<HashMap<String, DeviceHandle>>,
    aliases: Mutex<HashMap<String, String>>,
}

impl Default for UserspaceBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl UserspaceBackend {
    /// 构造一个空的用户态后端（内嵌一个多线程 tokio runtime）。
    pub fn new() -> Self {
        let rt = tokio::runtime::Runtime::new().expect("构建 tokio runtime 失败");
        Self {
            rt,
            devices: Mutex::new(HashMap::new()),
            aliases: Mutex::new(HashMap::new()),
        }
    }

    /// 把「接口名」解析为真实设备名（ADR-0009 决策 2 的映射层）。
    ///
    /// `interface` 既可能是逻辑名（配置里的 `hextet0`）也可能是真实名（`apply` 读回的
    /// `utunN`）。`aliases` 里查得到逻辑名就用映射后的真实名；查不到则原样返回。
    fn resolve(&self, interface: &str) -> Result<String, WgError> {
        let aliases = self
            .aliases
            .lock()
            .map_err(|_| WgError::Backend("aliases 注册表锁中毒".into()))?;
        Ok(aliases
            .get(interface)
            .cloned()
            .unwrap_or_else(|| interface.to_owned()))
    }

    /// 用裸 fd（Android `VpnService.Builder.establish()` 返回的 fd）而非命名 TUN
    /// 应用设备（M7 切片 C）。fd 的 IP 包语义与 Linux TUN 相同，但没有「设备名」，
    /// 所以登记名与返回值都是 `spec.interface`（无别名映射）。
    #[cfg(unix)]
    pub fn apply_with_fd(
        &self,
        spec: &DeviceSpec,
        tun_fd: std::os::fd::RawFd,
        mtu: u16,
    ) -> Result<String, WgError> {
        let interface = spec.interface.clone();
        let listen_port = spec.listen_port;
        let secret = StaticSecret::from(spec.wg_secret);
        let peers = spec
            .peers
            .iter()
            .map(peer_spec_to_peer)
            .collect::<Result<Vec<_>, _>>()?;

        self.rt.block_on(async move {
            let tun = RawFdTun::from_fd(tun_fd, mtu)
                .map_err(|e| WgError::Backend(format!("包装裸 fd 失败: {e}")))?;
            let dev = DeviceBuilder::default()
                .with_private_key(secret)
                .with_peers(peers)
                .with_listen_port(listen_port)
                .with_default_udp()
                .with_ip(tun)
                .build()
                .await
                .map_err(|e| WgError::Backend(format!("gotatun 构建设备失败: {e}")))?;
            let mut devices = self
                .devices
                .lock()
                .map_err(|_| WgError::Backend("devices 注册表锁中毒".into()))?;
            devices.insert(interface.clone(), DeviceHandle::Fd(dev));
            Ok(interface)
        })
    }

    // ---- 泛型 helper：把「对 Device<T> 的操作」从 T 里抽象出来，供 WgBackend 方法
    //      对 DeviceHandle 两个 variant 复用，避免每个方法都写一遍 match。----

    fn status_of<T: DeviceTransports>(&self, dev: &Device<T>) -> Vec<PeerStatus> {
        let stats = self.rt.block_on(async { dev.peers().await });
        stats
            .into_iter()
            .map(|ps| PeerStatus {
                wg_public: ps.peer.public_key.to_bytes(),
                endpoint: ps.peer.endpoint,
                // gotatun 给的是「距上次握手的时长」，换算成近似绝对时间。
                last_handshake: ps.stats.last_handshake.map(|d| {
                    SystemTime::now()
                        .checked_sub(d)
                        .unwrap_or(SystemTime::UNIX_EPOCH)
                }),
                rx_bytes: ps.stats.rx_bytes as u64,
                tx_bytes: ps.stats.tx_bytes as u64,
            })
            .collect()
    }

    fn set_endpoint_of<T: DeviceTransports>(
        &self,
        dev: &mut Device<T>,
        wg_public: &[u8; 32],
        endpoint: SocketAddrV6,
    ) -> Result<(), WgError> {
        let pk = PublicKey::from(*wg_public);
        // 增量更新 endpoint（收敛 ADR-0007 记录的 boringtun remove+re-add 缺口）。
        let updated = self
            .rt
            .block_on(async {
                dev.modify_peer(&pk, |p| p.set_endpoint(Some(SocketAddr::V6(endpoint))))
                    .await
            })
            .map_err(|e| WgError::Backend(format!("gotatun modify_peer 失败: {e}")))?;
        if updated {
            Ok(())
        } else {
            Err(WgError::Backend("peer 不存在".to_string()))
        }
    }

    fn add_peer_of<T: DeviceTransports>(&self, dev: &Device<T>, peer: Peer) -> Result<(), WgError> {
        self.rt
            .block_on(async { dev.add_peer(peer).await })
            .map_err(|e| WgError::Backend(format!("gotatun add_peer 失败: {e}")))?;
        Ok(())
    }

    fn remove_peer_of<T: DeviceTransports>(
        &self,
        dev: &Device<T>,
        wg_public: &[u8; 32],
    ) -> Result<(), WgError> {
        let pk = PublicKey::from(*wg_public);
        let removed = self
            .rt
            .block_on(async { dev.remove_peer(&pk).await })
            .map_err(|e| WgError::Backend(format!("gotatun remove_peer 失败: {e}")))?;
        if removed {
            Ok(())
        } else {
            Err(WgError::Backend("peer 不存在".to_string()))
        }
    }

    fn down_of<T: DeviceTransports>(&self, dev: Device<T>) {
        self.rt.block_on(async move { dev.stop().await });
    }
}

/// 把 [`PeerSpec`]（WG 公钥 + endpoint + AllowedIPs + keepalive）映射成 gotatun 的
/// [`Peer`]。AllowedIPs 的 `(Ipv6Addr, u8)` 转成 `ipnetwork::IpNetwork`。
fn peer_spec_to_peer(spec: &PeerSpec) -> Result<Peer, WgError> {
    let mut peer = Peer::new(PublicKey::from(spec.wg_public));
    if let Some(ep) = spec.endpoint {
        peer = peer.with_endpoint(SocketAddr::V6(ep));
    }
    peer.allowed_ips = spec
        .allowed_ips
        .iter()
        .map(|(ip, prefix)| IpNetwork::new(IpAddr::V6(*ip), *prefix))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| WgError::Backend(format!("非法 AllowedIPs 前缀: {e}")))?;
    // gotatun 的 Peer.keepalive 字段是 pub 的（无 with_keepalive builder），直接赋值。
    peer.keepalive = spec.persistent_keepalive;
    Ok(peer)
}

impl WgBackend for UserspaceBackend {
    fn apply(&self, spec: &DeviceSpec) -> Result<String, WgError> {
        let interface = spec.interface.clone();
        let listen_port = spec.listen_port;
        let secret = StaticSecret::from(spec.wg_secret);
        let peers = spec
            .peers
            .iter()
            .map(peer_spec_to_peer)
            .collect::<Result<Vec<_>, _>>()?;

        self.rt.block_on(async move {
            let builder = DeviceBuilder::default()
                .with_private_key(secret)
                .with_peers(peers)
                .with_listen_port(listen_port)
                .with_default_udp();
            // macOS 上 `tun` crate 要求 `utun`/`utunN` 前缀（否则 InvalidName），且必须
            // 请求裸 `utun` 让内核分配最低可用 index（避开 Tailscale 等既有 utun，
            // ADR-0009 决策 2）；其余平台（Linux/Windows）直接用配置名。
            #[cfg(target_os = "macos")]
            let request_name = "utun".to_string();
            #[cfg(not(target_os = "macos"))]
            let request_name = interface.clone();
            // 手动开 TUN：既拿到真实设备名（macOS 上读回真实 utunN），又能经 with_ip
            // 把它交给 DeviceBuilder（ADR-0009 决策 2 的读回）。
            let tun = TunDevice::from_name(&request_name)
                .map_err(|e| WgError::Backend(format!("创建 TUN 设备失败: {e}")))?;
            let real_name = tun
                .name()
                .map_err(|e| WgError::Backend(format!("读回 TUN 真实名失败: {e}")))?;
            let dev = builder
                .with_ip(tun)
                .build()
                .await
                .map_err(|e| WgError::Backend(format!("gotatun 构建设备失败: {e}")))?;

            let mut devices = self
                .devices
                .lock()
                .map_err(|_| WgError::Backend("devices 注册表锁中毒".into()))?;
            devices.insert(real_name.clone(), DeviceHandle::Named(dev));
            drop(devices);
            let mut aliases = self
                .aliases
                .lock()
                .map_err(|_| WgError::Backend("aliases 注册表锁中毒".into()))?;
            aliases.insert(interface, real_name.clone());
            Ok(real_name)
        })
    }

    fn status(&self, interface: &str) -> Result<Vec<PeerStatus>, WgError> {
        let name = self.resolve(interface)?;
        let devices = self
            .devices
            .lock()
            .map_err(|_| WgError::Backend("devices 注册表锁中毒".into()))?;
        let dev = devices
            .get(&name)
            .ok_or_else(|| WgError::NotFound(interface.to_owned()))?;
        Ok(match dev {
            DeviceHandle::Named(d) => self.status_of(d),
            #[cfg(unix)]
            DeviceHandle::Fd(d) => self.status_of(d),
        })
    }

    fn set_peer_endpoint(
        &self,
        interface: &str,
        wg_public: &[u8; 32],
        endpoint: SocketAddrV6,
    ) -> Result<(), WgError> {
        let name = self.resolve(interface)?;
        let mut devices = self
            .devices
            .lock()
            .map_err(|_| WgError::Backend("devices 注册表锁中毒".into()))?;
        // `Device::modify_peer` 需要 `&mut self`（其内部用 `write` 拿独占写锁）。
        let dev = devices
            .get_mut(&name)
            .ok_or_else(|| WgError::NotFound(interface.to_owned()))?;
        match dev {
            DeviceHandle::Named(d) => self.set_endpoint_of(d, wg_public, endpoint),
            #[cfg(unix)]
            DeviceHandle::Fd(d) => self.set_endpoint_of(d, wg_public, endpoint),
        }
    }

    fn add_peer(&self, interface: &str, spec: &PeerSpec) -> Result<(), WgError> {
        let name = self.resolve(interface)?;
        let devices = self
            .devices
            .lock()
            .map_err(|_| WgError::Backend("devices 注册表锁中毒".into()))?;
        let dev = devices
            .get(&name)
            .ok_or_else(|| WgError::NotFound(interface.to_owned()))?;
        let peer = peer_spec_to_peer(spec)?;
        match dev {
            DeviceHandle::Named(d) => self.add_peer_of(d, peer),
            #[cfg(unix)]
            DeviceHandle::Fd(d) => self.add_peer_of(d, peer),
        }
    }

    fn remove_peer(&self, interface: &str, wg_public: &[u8; 32]) -> Result<(), WgError> {
        let name = self.resolve(interface)?;
        let devices = self
            .devices
            .lock()
            .map_err(|_| WgError::Backend("devices 注册表锁中毒".into()))?;
        let dev = devices
            .get(&name)
            .ok_or_else(|| WgError::NotFound(interface.to_owned()))?;
        match dev {
            DeviceHandle::Named(d) => self.remove_peer_of(d, wg_public),
            #[cfg(unix)]
            DeviceHandle::Fd(d) => self.remove_peer_of(d, wg_public),
        }
    }

    fn down(&self, interface: &str) -> Result<(), WgError> {
        let name = self.resolve(interface)?;
        let dev = {
            let mut devices = self
                .devices
                .lock()
                .map_err(|_| WgError::Backend("devices 注册表锁中毒".into()))?;
            devices.remove(&name)
        }
        .ok_or_else(|| WgError::NotFound(interface.to_owned()))?;
        // 清掉指向该真实名的别名（幂等）。
        if let Ok(mut aliases) = self.aliases.lock() {
            aliases.retain(|_, real| *real != name);
        }
        match dev {
            DeviceHandle::Named(d) => self.down_of(d),
            #[cfg(unix)]
            DeviceHandle::Fd(d) => self.down_of(d),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_maps_logical_name_to_real_device() {
        let backend = UserspaceBackend::new();
        backend
            .aliases
            .lock()
            .unwrap()
            .insert("hextet0".to_owned(), "utun3".to_owned());
        // 逻辑名 → 真实名；真实名 → 原样；未知名 → 原样。
        assert_eq!(backend.resolve("hextet0").unwrap(), "utun3");
        assert_eq!(backend.resolve("utun3").unwrap(), "utun3");
        assert_eq!(backend.resolve("unknown").unwrap(), "unknown");
    }

    /// 无需 root：对空后端（无任何设备）调用 status/add_peer/remove_peer/
    /// set_peer_endpoint/down，都应得到 `NotFound`，而不是 panic 或触碰真实设备。
    #[test]
    fn operations_on_unknown_interface_err_without_root() {
        let backend = UserspaceBackend::new();
        let ep: SocketAddrV6 = "[2001:db8::9]:4193".parse().unwrap();
        assert!(matches!(
            backend.status("hextet0"),
            Err(WgError::NotFound(_))
        ));
        let peer = PeerSpec {
            wg_public: [0xab; 32],
            endpoint: None,
            allowed_ips: vec![],
            persistent_keepalive: None,
        };
        assert!(matches!(
            backend.add_peer("hextet0", &peer),
            Err(WgError::NotFound(_))
        ));
        assert!(matches!(
            backend.remove_peer("hextet0", &[9u8; 32]),
            Err(WgError::NotFound(_))
        ));
        assert!(matches!(
            backend.set_peer_endpoint("hextet0", &[9u8; 32], ep),
            Err(WgError::NotFound(_))
        ));
        assert!(matches!(backend.down("hextet0"), Err(WgError::NotFound(_))));
    }

    /// PeerSpec → gotatun Peer 的映射：公钥/endpoint/AllowedIPs（含掩码）/keepalive
    /// 都要逐项正确，且非法前缀（>128）要报错而不是 panic。
    #[test]
    fn peer_spec_to_peer_maps_fields_and_rejects_bad_prefix() {
        let spec = PeerSpec {
            wg_public: [0xab; 32],
            endpoint: Some("[2001:db8::9]:4193".parse().unwrap()),
            allowed_ips: vec![
                ("fd00::1".parse().unwrap(), 64),
                ("fd00:2::".parse().unwrap(), 128),
            ],
            persistent_keepalive: Some(25),
        };
        let peer = peer_spec_to_peer(&spec).unwrap();
        assert_eq!(peer.public_key, PublicKey::from([0xab; 32]));
        assert_eq!(
            peer.endpoint,
            Some(SocketAddr::V6("[2001:db8::9]:4193".parse().unwrap()))
        );
        assert_eq!(peer.allowed_ips.len(), 2);
        // AllowedIPs 是网络（掩码掉 host 位）：fd00::1/64 → fd00::/64。
        assert_eq!(peer.allowed_ips[0].prefix(), 64);
        assert_eq!(
            peer.allowed_ips[0].network(),
            IpAddr::V6("fd00::".parse().unwrap())
        );
        assert_eq!(peer.allowed_ips[1].prefix(), 128);
        assert_eq!(peer.keepalive, Some(25));

        // 非法前缀长度（>128）→ 报错。
        let bad = PeerSpec {
            wg_public: [0xab; 32],
            endpoint: None,
            allowed_ips: vec![("fd00::1".parse().unwrap(), 129)],
            persistent_keepalive: None,
        };
        assert!(peer_spec_to_peer(&bad).is_err());
    }

    /// `apply_with_fd`（M7 切片 C 的 fd 接线）：用 socketpair fd 而非命名 TUN 构建
    /// 一个完整 gotatun Device，status 读回 peer、down 干净拆除——**无需 root**。
    #[cfg(unix)]
    #[test]
    fn apply_with_fd_builds_device_and_status_works() {
        use std::os::fd::AsRawFd;
        use std::os::unix::net::UnixStream;

        let backend = UserspaceBackend::new();
        let (_app, b) = UnixStream::pair().unwrap();

        let spec = DeviceSpec {
            interface: "hextet0".into(),
            listen_port: 41_932,
            wg_secret: [0x42u8; 32],
            peers: vec![PeerSpec {
                wg_public: [0xab; 32],
                endpoint: None,
                allowed_ips: vec![("2001:db8::2".parse().unwrap(), 64)],
                persistent_keepalive: Some(25),
            }],
        };

        // fd 没有「设备名」，登记名与返回值都是 spec.interface。
        let name = backend
            .apply_with_fd(&spec, b.as_raw_fd(), 1500)
            .expect("apply_with_fd 应成功");
        assert_eq!(name, "hextet0");

        let status = backend.status("hextet0").expect("status 应成功");
        assert_eq!(status.len(), 1, "应读回 apply 配的那一个 peer");
        assert_eq!(status[0].wg_public, [0xab; 32]);

        backend.down("hextet0").expect("down 应成功");
        assert!(matches!(
            backend.status("hextet0"),
            Err(WgError::NotFound(_))
        ));
    }
}
