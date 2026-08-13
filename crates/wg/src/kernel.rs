//! 内核 WireGuard 后端（netlink，经 wireguard-control）。

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use wireguard_control::{Backend, Device, DeviceUpdate, InterfaceName, Key, PeerConfigBuilder};

use crate::WgBackend;
use crate::types::{DeviceSpec, PeerStatus, WgError};

/// 内核后端。
pub struct KernelBackend;

/// 由原始字节构造 wireguard-control 的 Key（经 base64 桥接，避免依赖内部布局）。
pub fn key_from_bytes(bytes: &[u8; 32]) -> Key {
    Key::from_base64(&B64.encode(bytes)).expect("32 bytes always encode to valid key")
}

fn iface(name: &str) -> Result<InterfaceName, WgError> {
    name.parse()
        .map_err(|_| WgError::Backend(format!("invalid interface name {name}")))
}

/// 判断 `Device::get` 的底层 `io::Error` 是否代表"接口不存在"，而非权限/netlink
/// 通信等其他后端故障。
///
/// 查证结论（详见 fix report）：
/// - **ENODEV**（"No such device"）：wireguard 内核模块已加载，但目标 ifname 不存在——
///   这是 WireGuard 内核驱动 `lookup_interface()` 对 `dev_get_by_name()` 查找失败的
///   标准返回码（与 `wg show <不存在的接口>` 报错 "Unable to access interface:
///   No such device" 一致）。**Rust std 的 unix `decode_error_kind` 不映射 ENODEV**
///   （落入 `Uncategorized`），因此只判断 `io::ErrorKind::NotFound` 会漏掉这个最常见
///   的场景，把它误判为 `WgError::Backend`。必须额外用 `raw_os_error()` 匹配。
/// - **ENOENT** → `io::ErrorKind::NotFound`：wireguard 内核模块**未加载**时，
///   `netlink_request_genl` 内部为解析 "wireguard" 通用网络协议族 ID 而发起的
///   `CTRL_CMD_GETFAMILY` 请求会先失败（Linux 通用 netlink 对未知协议族名的标准
///   返回码是 ENOENT，等价于 `genl_ctrl_resolve` 的语义），经
///   `netlink-packet-core` 的 `ErrorMessage::to_io()`
///   （`io::Error::from_raw_os_error(raw_code.abs())`）转成 io::Error，其
///   `.kind()` 被 std 正确映射为 `NotFound`。
/// - **EACCES/EPERM**：均映射为 `PermissionDenied`（不是 NotFound 也不是 ENODEV），
///   会正确落入下面的 `WgError::Backend` 分支，保留原始错误文本，不会被误报为
///   "interface not found"。
fn is_missing_interface(err: &std::io::Error) -> bool {
    err.kind() == std::io::ErrorKind::NotFound || err.raw_os_error() == Some(libc::ENODEV)
}

impl WgBackend for KernelBackend {
    fn apply(&self, spec: &DeviceSpec) -> Result<String, WgError> {
        let ifname = iface(&spec.interface)?;
        let mut update = DeviceUpdate::new()
            .set_private_key(key_from_bytes(&spec.wg_secret))
            .set_listen_port(spec.listen_port)
            .replace_peers();
        for p in &spec.peers {
            let mut pc = PeerConfigBuilder::new(&key_from_bytes(&p.wg_public));
            if let Some(ep) = p.endpoint {
                pc = pc.set_endpoint(std::net::SocketAddr::V6(ep));
            }
            for (net, len) in &p.allowed_ips {
                pc = pc.add_allowed_ip(std::net::IpAddr::V6(*net), *len);
            }
            if let Some(ka) = p.persistent_keepalive {
                pc = pc.set_persistent_keepalive_interval(ka);
            }
            update = update.add_peer(pc);
        }
        update
            .apply(&ifname, Backend::Kernel)
            .map_err(|e| WgError::Backend(e.to_string()))?;
        // Linux 内核 WG 设备名即配置名（ADR-0009 决策 3：恒等）。
        Ok(spec.interface.clone())
    }

    fn status(&self, interface: &str) -> Result<Vec<PeerStatus>, WgError> {
        let ifname = iface(interface)?;
        let dev = Device::get(&ifname, Backend::Kernel).map_err(|e| {
            if is_missing_interface(&e) {
                WgError::NotFound(interface.to_owned())
            } else {
                WgError::Backend(e.to_string())
            }
        })?;
        Ok(dev
            .peers
            .iter()
            .map(|p| PeerStatus {
                wg_public: p
                    .config
                    .public_key
                    .as_bytes()
                    .try_into()
                    .expect("wg key is 32 bytes"),
                endpoint: p.config.endpoint,
                last_handshake: p.stats.last_handshake_time,
                rx_bytes: p.stats.rx_bytes,
                tx_bytes: p.stats.tx_bytes,
            })
            .collect())
    }

    fn set_peer_endpoint(
        &self,
        interface: &str,
        wg_public: &[u8; 32],
        endpoint: std::net::SocketAddrV6,
    ) -> Result<(), WgError> {
        let ifname = iface(interface)?;
        // 不调用 .replace_peers()：内核 WireGuard 在没有 WGDEVICE_F_REPLACE_PEERS
        // 时对列出的 peer 做"合并更新"，未列出的 peer 与本 peer 的其他属性
        // （AllowedIPs/keepalive）都原样保留。同理不调用 .replace_allowed_ips()。
        DeviceUpdate::new()
            .add_peer(
                PeerConfigBuilder::new(&key_from_bytes(wg_public))
                    .set_endpoint(std::net::SocketAddr::V6(endpoint)),
            )
            .apply(&ifname, Backend::Kernel)
            .map_err(|e| WgError::Backend(e.to_string()))
    }

    fn add_peer(&self, interface: &str, spec: &crate::types::PeerSpec) -> Result<(), WgError> {
        let ifname = iface(interface)?;
        let mut pc = PeerConfigBuilder::new(&key_from_bytes(&spec.wg_public));
        if let Some(ep) = spec.endpoint {
            pc = pc.set_endpoint(std::net::SocketAddr::V6(ep));
        }
        for (net, len) in &spec.allowed_ips {
            pc = pc.add_allowed_ip(std::net::IpAddr::V6(*net), *len);
        }
        if let Some(ka) = spec.persistent_keepalive {
            pc = pc.set_persistent_keepalive_interval(ka);
        }
        DeviceUpdate::new()
            .add_peer(pc)
            .apply(&ifname, Backend::Kernel)
            .map_err(|e| WgError::Backend(e.to_string()))
    }

    fn remove_peer(&self, interface: &str, wg_public: &[u8; 32]) -> Result<(), WgError> {
        let ifname = iface(interface)?;
        DeviceUpdate::new()
            .remove_peer_by_key(&key_from_bytes(wg_public))
            .apply(&ifname, Backend::Kernel)
            .map_err(|e| WgError::Backend(e.to_string()))
    }

    fn down(&self, _interface: &str) -> Result<(), WgError> {
        // Linux 内核 WG 设备由内核持有，拆除走 `platform::delete_interface`（rtnetlink
        // `ip link del`），不是本后端（ADR-0009 决策 5）。`hextet-wg` 不依赖 platform，
        // 因此这里返回错误、把分派留给 CLI，而不是加一个 platform 依赖。
        Err(WgError::Backend(
            "Linux 后端无 down：请用 platform::delete_interface".into(),
        ))
    }
}
