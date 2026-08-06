//! 配置 → WG DeviceSpec 的纯映射（可单测）。

use hextet_core::config::Config;
use hextet_core::identity::NodeIdentity;
use hextet_wg::types::{DeviceSpec, PeerSpec};

/// M1 常电节点 keepalive（设计 spec §5）。
const KEEPALIVE_SECS: u16 = 25;

/// 由配置与身份构建设备期望状态。
///
/// 每个 peer 的 `endpoint` 取配置里的第一个（可能为 `None`）。M2 起真正的
/// endpoint 由打洞状态机（`crate::fsm`，Task 5 引入）在运行时用
/// `set_peer_endpoint` 逐个校正，所以这里不需要知道端点缓存的存在。
///
/// 注意上面那句里的 `crate::fsm` 用反引号而不是 rustdoc 链接 `[...]`：`fsm`
/// 模块此刻还不存在，写成链接会触发 `broken_intra_doc_links` 警告，而
/// `-D warnings` 会让它变成编译失败。
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
