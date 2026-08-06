use hextet_core::config::Config;
use hextet_core::identity::NodeIdentity;

fn write_two_node_setup(dir: &std::path::Path) -> (std::path::PathBuf, NodeIdentity) {
    let id = NodeIdentity::generate();
    let peer = NodeIdentity::generate();
    let key_path = dir.join("node.key");
    id.save(&key_path).unwrap();
    let nk = hextet_core::network::NetworkKey::generate();
    let cfg = format!(
        r#"
[network]
name = "t"
key = "{nk}"

[node]
key_file = "node.key"

[[peers]]
name = "b"
public_key = "{pk}"
endpoints = ["[2001:db8::2]:4193"]
"#,
        nk = nk.to_base64(),
        pk = peer.public().to_base64(),
    );
    let cfg_path = dir.join("hextet.toml");
    std::fs::write(&cfg_path, cfg).unwrap();
    (cfg_path, id)
}

#[test]
fn device_spec_maps_config() {
    let dir = tempfile::tempdir().unwrap();
    let (cfg_path, id) = write_two_node_setup(dir.path());
    let cfg = Config::load(&cfg_path, Some(&id.public())).unwrap();
    let spec = hextet_engine::spec::build_device_spec(&cfg, &id);

    assert_eq!(spec.interface, "hextet0");
    assert_eq!(spec.listen_port, 4193);
    assert_eq!(spec.wg_secret, id.wg_secret_bytes());
    assert_eq!(spec.peers.len(), 1);
    let p = &spec.peers[0];
    assert_eq!(p.wg_public, cfg.peers[0].public_key.wg_public_bytes());
    assert_eq!(p.endpoint.unwrap().to_string(), "[2001:db8::2]:4193");
    // AllowedIPs = peer 的 site /64
    assert_eq!(p.allowed_ips, vec![(cfg.peers[0].addr.site, 64)]);
    assert_eq!(p.persistent_keepalive, Some(25));
}

#[test]
fn status_state_classification() {
    use std::time::{Duration, SystemTime};
    let now = SystemTime::now();
    assert_eq!(
        hextet_cli::commands::status::classify(Some(now - Duration::from_secs(10)), now),
        "connected"
    );
    assert_eq!(
        hextet_cli::commands::status::classify(Some(now - Duration::from_secs(600)), now),
        "stale"
    );
    assert_eq!(
        hextet_cli::commands::status::classify(None, now),
        "no-handshake"
    );
}

#[test]
fn daemon_freshness_classification() {
    use hextet_cli::commands::status::daemon_freshness;

    // 刚写过 → running
    assert_eq!(daemon_freshness(1_000, 1_000), (true, 0));
    assert_eq!(daemon_freshness(1_000, 1_010), (true, 10));
    // 超过 10s 未更新 → 认为 daemon 已停
    assert_eq!(daemon_freshness(1_000, 1_011), (false, 11));
    assert_eq!(daemon_freshness(1_000, 9_999), (false, 8_999));
    // 状态文件时间戳比现在新（时钟回拨）→ 视为 0 秒前，仍算 running
    assert_eq!(daemon_freshness(2_000, 1_000), (true, 0));
}
