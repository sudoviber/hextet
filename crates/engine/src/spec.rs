//! 配置 → WG DeviceSpec 的纯映射（可单测）。

use hextet_core::config::Config;
use hextet_core::identity::NodeIdentity;
use hextet_core::route::allowed_ips_for;
use hextet_wg::types::{DeviceSpec, PeerSpec};

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
                allowed_ips: allowed_ips_for(p.addr.site, &p.routes),
                persistent_keepalive: (cfg.node.keepalive != 0).then_some(cfg.node.keepalive),
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hextet_core::config::render_peer_block;
    use hextet_core::route::Ipv6Route;
    use std::net::SocketAddrV6;

    /// 配置里带通告路由的 peer，其 AllowedIPs 必须 = site/64 + 各路由。
    #[test]
    fn device_spec_includes_advertised_routes_in_allowed_ips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hextet.toml");
        let nk = hextet_core::network::NetworkKey::generate();
        let peer_id = NodeIdentity::generate();
        let routes: Vec<Ipv6Route> = ["2001:db8:dead::/64", "2001:db8:beef::/48"]
            .iter()
            .map(|s| s.parse().unwrap())
            .collect();
        let mut text =
            Config::render_template("home", &nk, std::path::Path::new("node.key"), 4193, None);
        text.push_str(&render_peer_block(
            "nas",
            &peer_id.public(),
            &["[2001:db8::1]:4193".parse::<SocketAddrV6>().unwrap()],
            &routes,
        ));
        std::fs::write(&path, text).unwrap();

        let cfg = Config::load(&path, None).unwrap();
        let spec = build_device_spec(&cfg, &peer_id);
        assert_eq!(spec.peers.len(), 1);
        let expected = hextet_core::route::allowed_ips_for(cfg.peers[0].addr.site, &routes);
        assert_eq!(spec.peers[0].allowed_ips, expected);
        assert_eq!(spec.peers[0].allowed_ips.len(), 3);
        assert_eq!(spec.peers[0].allowed_ips[0], (cfg.peers[0].addr.site, 64));
        assert_eq!(
            spec.peers[0].allowed_ips[1],
            ("2001:db8:dead::".parse().unwrap(), 64)
        );
    }

    /// `[node] keepalive = 0` → `persistent_keepalive = None`（移动端按需连接省电）；
    /// 缺省 / `keepalive = 25` → `Some(25)`（常电节点）。ADR-0015。
    #[test]
    fn keepalive_config_controls_persistent_keepalive() {
        let dir = tempfile::tempdir().unwrap();
        let nk = hextet_core::network::NetworkKey::generate();
        let peer_id = NodeIdentity::generate();
        let peer_block = render_peer_block(
            "nas",
            &peer_id.public(),
            &["[2001:db8::1]:4193".parse::<SocketAddrV6>().unwrap()],
            &[],
        );

        // 缺省（模板不写 keepalive）→ 25
        let path_default = dir.path().join("default.toml");
        let text =
            Config::render_template("home", &nk, std::path::Path::new("node.key"), 4193, None);
        std::fs::write(&path_default, format!("{text}{peer_block}")).unwrap();
        let cfg = Config::load(&path_default, None).unwrap();
        let spec = build_device_spec(&cfg, &peer_id);
        assert_eq!(spec.peers[0].persistent_keepalive, Some(25));

        // 显式 keepalive = 0 → None
        let path_zero = dir.path().join("zero.toml");
        let text =
            Config::render_template("home", &nk, std::path::Path::new("node.key"), 4193, None)
                .replace(
                    "key_file = \"node.key\"",
                    "key_file = \"node.key\"\nkeepalive = 0",
                );
        std::fs::write(&path_zero, format!("{text}{peer_block}")).unwrap();
        let cfg = Config::load(&path_zero, None).unwrap();
        let spec = build_device_spec(&cfg, &peer_id);
        assert_eq!(spec.peers[0].persistent_keepalive, None);

        // 显式 keepalive = 25 → Some(25)（与缺省一致，行为保持）
        let path_25 = dir.path().join("twentyfive.toml");
        let text =
            Config::render_template("home", &nk, std::path::Path::new("node.key"), 4193, None)
                .replace(
                    "key_file = \"node.key\"",
                    "key_file = \"node.key\"\nkeepalive = 25",
                );
        std::fs::write(&path_25, format!("{text}{peer_block}")).unwrap();
        let cfg = Config::load(&path_25, None).unwrap();
        let spec = build_device_spec(&cfg, &peer_id);
        assert_eq!(spec.peers[0].persistent_keepalive, Some(25));
    }
}
