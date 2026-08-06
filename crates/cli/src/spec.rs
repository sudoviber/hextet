//! 配置 → WG DeviceSpec 的纯映射（可单测）。

use hextet_core::config::Config;
use hextet_core::identity::NodeIdentity;
use hextet_wg::types::{DeviceSpec, PeerSpec};

/// M1 常电节点 keepalive（设计 spec §5）。
const KEEPALIVE_SECS: u16 = 25;

/// 由配置与身份构建设备期望状态。
pub fn build_device_spec(cfg: &Config, id: &NodeIdentity) -> DeviceSpec {
    DeviceSpec {
        interface: cfg.node.interface.clone(),
        listen_port: cfg.node.listen_port,
        wg_secret: id.wg_secret_bytes(),
        peers: cfg
            .peers
            .iter()
            .map(|p| PeerSpec {
                wg_public: p.public_key.wg_public_bytes(),
                endpoint: p.endpoints.first().copied(),
                allowed_ips: vec![(p.addr.site, 64)],
                persistent_keepalive: Some(KEEPALIVE_SECS),
            })
            .collect(),
    }
}
