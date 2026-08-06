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

impl WgBackend for KernelBackend {
    fn apply(&self, spec: &DeviceSpec) -> Result<(), WgError> {
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
            .map_err(|e| WgError::Backend(e.to_string()))
    }

    fn status(&self, interface: &str) -> Result<Vec<PeerStatus>, WgError> {
        let ifname = iface(interface)?;
        let dev = Device::get(&ifname, Backend::Kernel)
            .map_err(|_| WgError::NotFound(interface.to_owned()))?;
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
}
