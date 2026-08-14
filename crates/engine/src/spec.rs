//! 配置 → WG DeviceSpec 的纯映射（可单测）。

use hextet_core::config::{Config, Peer};
use hextet_core::identity::NodeIdentity;
use hextet_core::route::allowed_ips_for;
use hextet_wg::types::{DeviceSpec, PeerSpec};

/// 把配置里的 keepalive 秒数映射成 WG `persistent_keepalive`。
///
/// `0` = 关闭（移动端按需连接，见 `[node] keepalive` 文档），其余原样返回。
pub fn keepalive_secs(cfg: &Config) -> Option<u16> {
    keepalive_opt(cfg.node.keepalive)
}

/// 单个 peer 的 keepalive：`[[peers]] keepalive` 覆盖优先，否则用 `[node] keepalive`。
pub fn peer_keepalive_secs(peer: &Peer, node_keepalive: u16) -> Option<u16> {
    keepalive_opt(peer.keepalive.unwrap_or(node_keepalive))
}

/// 把 keepalive 秒数 `n` 映射成 WG `persistent_keepalive`：`0` → `None`，其余 `Some(n)`。
pub fn keepalive_opt(secs: u16) -> Option<u16> {
    match secs {
        0 => None,
        n => Some(n),
    }
}

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
                persistent_keepalive: peer_keepalive_secs(p, cfg.node.keepalive),
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

    /// 写一份含 `[node] keepalive` 覆盖的配置并返回 `Config`。
    fn config_with_keepalive(keepalive: Option<&str>) -> Config {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hextet.toml");
        let nk = hextet_core::network::NetworkKey::generate();
        let peer_id = NodeIdentity::generate();
        let mut text =
            Config::render_template("home", &nk, std::path::Path::new("node.key"), 4193, None);
        if let Some(k) = keepalive {
            // render_template 只留注释示例；这里追加一条生效的 keepalive 覆盖项。
            text.push_str(&format!("\nkeepalive = {k}\n"));
        }
        text.push_str(&render_peer_block(
            "nas",
            &peer_id.public(),
            &["[2001:db8::1]:4193".parse::<SocketAddrV6>().unwrap()],
            &[],
        ));
        std::fs::write(&path, text).unwrap();
        Config::load(&path, None).unwrap()
    }

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

    /// 未显式配置 keepalive 时，默认 25s（常电节点）。
    #[test]
    fn keepalive_defaults_to_25() {
        let cfg = config_with_keepalive(None);
        assert_eq!(cfg.node.keepalive, 25);
        assert_eq!(keepalive_secs(&cfg), Some(25));
        let spec = build_device_spec(&cfg, &NodeIdentity::generate());
        assert_eq!(spec.peers[0].persistent_keepalive, Some(25));
    }

    /// `keepalive = 0` 关闭持久 keepalive（移动端按需连接）。
    #[test]
    fn keepalive_zero_means_on_demand() {
        let cfg = config_with_keepalive(Some("0"));
        assert_eq!(cfg.node.keepalive, 0);
        assert_eq!(keepalive_secs(&cfg), None);
        let spec = build_device_spec(&cfg, &NodeIdentity::generate());
        assert_eq!(spec.peers[0].persistent_keepalive, None);
    }

    /// 显式 keepalive 秒数原样透传（例如纯 IPv6 路径放宽到 ~110s 的手动配置）。
    #[test]
    fn keepalive_explicit_value_passthrough() {
        let cfg = config_with_keepalive(Some("110"));
        assert_eq!(cfg.node.keepalive, 110);
        assert_eq!(keepalive_secs(&cfg), Some(110));
        let spec = build_device_spec(&cfg, &NodeIdentity::generate());
        assert_eq!(spec.peers[0].persistent_keepalive, Some(110));
    }

    /// 写一份 `[[peers]] keepalive` 覆盖的配置（`[node] keepalive` 保持默认 25）。
    fn config_with_peer_keepalive(peer_keepalive: Option<&str>) -> Config {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hextet.toml");
        let nk = hextet_core::network::NetworkKey::generate();
        let peer_id = NodeIdentity::generate();
        let mut text =
            Config::render_template("home", &nk, std::path::Path::new("node.key"), 4193, None);
        let mut block = render_peer_block(
            "nas",
            &peer_id.public(),
            &["[2001:db8::1]:4193".parse::<SocketAddrV6>().unwrap()],
            &[],
        );
        if let Some(k) = peer_keepalive {
            block.push_str(&format!("keepalive = {k}\n"));
        }
        text.push_str(&block);
        std::fs::write(&path, text).unwrap();
        Config::load(&path, None).unwrap()
    }

    /// `[[peers]] keepalive` 覆盖 `[node] keepalive`（手动把纯 IPv6 路径的对端放宽）。
    #[test]
    fn peer_keepalive_overrides_node_default() {
        let cfg = config_with_peer_keepalive(Some("110"));
        assert_eq!(cfg.node.keepalive, 25, "节点默认仍是 25");
        assert_eq!(cfg.peers[0].keepalive, Some(110));
        let spec = build_device_spec(&cfg, &NodeIdentity::generate());
        assert_eq!(spec.peers[0].persistent_keepalive, Some(110));
    }

    /// `[[peers]] keepalive = 0`：只对这个 peer 关闭持久 keepalive（按需连接）。
    #[test]
    fn peer_keepalive_zero_means_on_demand_for_that_peer() {
        let cfg = config_with_peer_keepalive(Some("0"));
        assert_eq!(cfg.node.keepalive, 25);
        assert_eq!(cfg.peers[0].keepalive, Some(0));
        let spec = build_device_spec(&cfg, &NodeIdentity::generate());
        assert_eq!(spec.peers[0].persistent_keepalive, None);
    }

    /// 没设 `[[peers]] keepalive` 时回落到节点默认。
    #[test]
    fn peer_keepalive_none_falls_back_to_node_default() {
        let cfg = config_with_peer_keepalive(None);
        assert_eq!(cfg.peers[0].keepalive, None);
        let spec = build_device_spec(&cfg, &NodeIdentity::generate());
        assert_eq!(spec.peers[0].persistent_keepalive, Some(25));
    }
}
