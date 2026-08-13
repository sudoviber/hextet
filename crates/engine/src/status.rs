//! `hextet status` / HTTP `/api/status` 共用的报告组装：内核 WG 状态 + daemon 状态文件
//! → [`hextet_proto::StatusReport`]。
//!
//! 这是纯逻辑（无 I/O、无 root、无平台依赖），从 `hextet-cli` 抽出后由 CLI
//! （`--json`/人类表格/TUI）与 `crate::http` 的 axum 状态服务器共享，避免
//! 「读状态 → 拼行」逻辑在多个展示入口间漂移。

use std::time::{Duration, SystemTime};

use hextet_core::config::Config;
use hextet_proto::{DaemonInfo, StatusReport, StatusRow};

/// 状态文件多久没更新就认为 daemon 已停。
///
/// daemon 每秒重写一次，10s 容忍度足够覆盖负载抖动，又能让"daemon 挂了"
/// 在 10s 内被 status 如实报出来。
const DAEMON_FRESH_SECS: u64 = 10;

/// 按最近握手时间归类连接状态（<180s = connected）。
pub fn classify(last_handshake: Option<SystemTime>, now: SystemTime) -> &'static str {
    match last_handshake {
        Some(t) => match now.duration_since(t) {
            Ok(d) if d < Duration::from_secs(180) => "connected",
            _ => "stale",
        },
        None => "no-handshake",
    }
}

/// 由状态文件时间戳判断 daemon 是否在跑，以及"多久之前更新的"。
///
/// 时间戳比当前时间新（时钟回拨、或 daemon 与 CLI 看到的时钟有偏差）时按 0 秒前
/// 处理，而不是让 `u64` 减法回绕成一个巨大的数字把 daemon 误报成已停。
pub fn daemon_freshness(updated_unix: u64, now_unix: u64) -> (bool, u64) {
    let secs_ago = now_unix.saturating_sub(updated_unix);
    (secs_ago <= DAEMON_FRESH_SECS, secs_ago)
}

/// 从内核 WG 状态 + daemon 状态文件组装完整报告。
///
/// `--json`、人类表格、`--tui` 与 HTTP `/api/status` 四条路径共用它，避免
/// 「读状态 → 拼行」逻辑在多处漂移。状态文件版本不认识时按"没有 daemon 状态"
/// 处理（见 [`crate::state`] 与 docs/dev/state-files.md）。
pub fn build_report(
    cfg: &Config,
    backend: &(impl hextet_wg::WgBackend + ?Sized),
    now: SystemTime,
) -> anyhow::Result<StatusReport> {
    let statuses = backend.status(&cfg.node.interface)?;
    let now_unix = crate::state::unix_secs(now);

    let state_path = cfg.node.state_dir.join("state.json");
    // 版本不认识就当作"没有 daemon 状态"：老版本的 daemon 配新版本的 CLI 时，
    // 报"没有 daemon"比报出字段缺失的半截状态更诚实（状态文件是纯派生数据，
    // 见 docs/dev/state-files.md）。
    let engine_state = crate::state::read(&state_path)
        .ok()
        .filter(|s| s.version == crate::state::STATE_VERSION);
    let daemon = engine_state.as_ref().map(|s| {
        let (running, updated_secs_ago) = daemon_freshness(s.updated_unix, now_unix);
        DaemonInfo {
            running,
            updated_secs_ago,
            state_file: state_path.display().to_string(),
        }
    });

    let rows: Vec<StatusRow> = statuses
        .iter()
        .map(|s| {
            let peer = cfg
                .peers
                .iter()
                .find(|p| p.public_key.wg_public_bytes() == s.wg_public);
            let key_b64 = peer.map(|p| p.public_key.to_base64());
            let engine_peer = engine_state
                .as_ref()
                .zip(key_b64.as_ref())
                .and_then(|(state, key)| state.peers.iter().find(|ps| &ps.public_key == key));
            StatusRow {
                peer: peer.map_or_else(|| "<unknown>".to_string(), |p| p.name.clone()),
                address: peer.map_or_else(String::new, |p| p.addr.address.to_string()),
                endpoint: s.endpoint.map(|e| e.to_string()),
                last_handshake_secs: s
                    .last_handshake
                    .and_then(|t| now.duration_since(t).ok())
                    .map(|d| d.as_secs()),
                rx_bytes: s.rx_bytes,
                tx_bytes: s.tx_bytes,
                state: classify(s.last_handshake, now).to_string(),
                endpoint_source: engine_peer.map(|p| p.endpoint_source.clone()),
                punch_state: engine_peer.map(|p| p.punch_state.clone()),
                candidates: engine_peer.map(|p| p.candidates),
                candidate_index: engine_peer.map(|p| p.candidate_index),
                lan_endpoints: engine_peer.map(|p| p.lan_endpoints),
                gossip_endpoints: engine_peer.map(|p| p.gossip_endpoints),
                ddns_endpoints: engine_peer.map(|p| p.ddns_endpoints),
                relay_via: engine_peer.and_then(|p| p.relay_via.clone()),
                routes: engine_peer
                    .map(|p| p.routes.iter().map(|r| r.to_string()).collect())
                    .unwrap_or_default(),
            }
        })
        .collect();

    Ok(StatusReport {
        daemon,
        peers: rows,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::UNIX_EPOCH;

    #[test]
    fn classify_states() {
        let now = UNIX_EPOCH + Duration::from_secs(1000);
        assert_eq!(classify(None, now), "no-handshake");
        assert_eq!(
            classify(Some(now - Duration::from_secs(10)), now),
            "connected"
        );
        assert_eq!(classify(Some(now - Duration::from_secs(181)), now), "stale");
        // 握手时间比现在还晚（时钟偏差）：duration_since 失败 → stale，而不是 panic
        assert_eq!(classify(Some(now + Duration::from_secs(10)), now), "stale");
    }

    #[test]
    fn daemon_freshness_bounds() {
        assert_eq!(daemon_freshness(1000, 1000), (true, 0));
        assert_eq!(daemon_freshness(1000, 1010), (true, 10)); // 恰好在阈值上仍算活着
        assert_eq!(daemon_freshness(1000, 1011), (false, 11));
        // 时钟回拨：updated 比 now 新 → 按 0s 前处理，不会回绕成巨大秒数
        assert_eq!(daemon_freshness(2000, 1000), (true, 0));
    }

    mod build_report_tests {
        use super::*;
        use crate::state::{EngineState, PeerState, STATE_VERSION, write};
        use hextet_core::config::{Config, render_peer_block};
        use hextet_core::identity::NodeIdentity;
        use hextet_wg::mock::MockBackend;
        use hextet_wg::types::PeerStatus;

        /// 渲染一份含一个已知 peer 的配置，`state_dir` 指向临时目录。
        fn build_config(state_dir: &std::path::Path, peer_id: &NodeIdentity) -> Config {
            let nk = hextet_core::network::NetworkKey::generate();
            let mut text = Config::render_template(
                "home",
                &nk,
                std::path::Path::new("node.key"),
                4193,
                Some(state_dir),
            );
            text.push_str(&render_peer_block("nas", &peer_id.public(), &[], &[]));
            let path = state_dir.join("hextet.toml");
            std::fs::write(&path, text).unwrap();
            Config::load(&path, None).unwrap()
        }

        #[test]
        fn build_report_maps_known_and_unknown_peers() {
            let dir = tempfile::tempdir().unwrap();
            let peer_id = NodeIdentity::generate();
            let cfg = build_config(dir.path(), &peer_id);
            let wg_public = peer_id.public().wg_public_bytes();

            let mock = MockBackend::default();
            mock.statuses.lock().unwrap().push(PeerStatus {
                wg_public,
                endpoint: Some("[2001:db8::9]:4193".parse().unwrap()),
                last_handshake: None,
                rx_bytes: 11,
                tx_bytes: 22,
            });
            // 内核里有个配置里不认识的 peer → 映射为 <unknown>
            mock.statuses.lock().unwrap().push(PeerStatus {
                wg_public: [99u8; 32],
                endpoint: None,
                last_handshake: None,
                rx_bytes: 0,
                tx_bytes: 0,
            });

            let now = UNIX_EPOCH + Duration::from_secs(1_770_000_000);
            let report = build_report(&cfg, &mock, now).unwrap();

            assert_eq!(report.peers.len(), 2);
            assert_eq!(report.peers[0].peer, "nas");
            assert_eq!(
                report.peers[0].address,
                cfg.peers[0].addr.address.to_string()
            );
            assert_eq!(report.peers[0].rx_bytes, 11);
            assert_eq!(report.peers[0].state, "no-handshake");
            assert_eq!(report.peers[1].peer, "<unknown>");
            assert_eq!(report.peers[1].address, "");
            // 没有 state.json → daemon 字段为 None
            assert!(report.daemon.is_none());
        }

        #[test]
        fn build_report_passes_through_engine_fields_and_daemon_freshness() {
            let dir = tempfile::tempdir().unwrap();
            let peer_id = NodeIdentity::generate();
            let cfg = build_config(dir.path(), &peer_id);

            // 写一份当前版本的 state.json
            let updated_unix = 1_770_000_000u64;
            let state = EngineState {
                version: STATE_VERSION,
                updated_unix,
                interface: "hextet0".into(),
                node_address: "fd12:3456:78::1".parse().unwrap(),
                node_public_key: "AAAA".into(),
                peers: vec![PeerState {
                    name: "nas".into(),
                    public_key: peer_id.public().to_base64(),
                    address: cfg.peers[0].addr.address,
                    punch_state: "relayed".into(),
                    endpoint: Some("[2001:db8::9]:4193".parse().unwrap()),
                    endpoint_source: "relay".into(),
                    lan_endpoints: 1,
                    gossip_endpoints: 2,
                    ddns_endpoints: 3,
                    relay_via: Some("relay-node".into()),
                    routes: vec!["2001:db8:dead::/64".parse().unwrap()],
                    last_handshake_secs: Some(7),
                    rx_bytes: 111,
                    tx_bytes: 222,
                    candidates: 3,
                    candidate_index: 1,
                    rounds: 0,
                }],
            };
            write(&dir.path().join("state.json"), &state).unwrap();

            let mock = MockBackend::default();
            mock.statuses.lock().unwrap().push(PeerStatus {
                wg_public: peer_id.public().wg_public_bytes(),
                endpoint: Some("[2001:db8::9]:4193".parse().unwrap()),
                last_handshake: None,
                rx_bytes: 0,
                tx_bytes: 0,
            });

            // 刚更新 → daemon 活着
            let now = UNIX_EPOCH + Duration::from_secs(updated_unix);
            let report = build_report(&cfg, &mock, now).unwrap();
            let daemon = report.daemon.as_ref().unwrap();
            assert!(daemon.running);
            assert_eq!(daemon.updated_secs_ago, 0);

            let row = &report.peers[0];
            assert_eq!(row.endpoint_source.as_deref(), Some("relay"));
            assert_eq!(row.punch_state.as_deref(), Some("relayed"));
            assert_eq!(row.relay_via.as_deref(), Some("relay-node"));
            assert_eq!(row.lan_endpoints, Some(1));
            assert_eq!(row.gossip_endpoints, Some(2));
            assert_eq!(row.ddns_endpoints, Some(3));
            assert_eq!(row.candidates, Some(3));
            assert_eq!(row.candidate_index, Some(1));
            assert_eq!(row.routes, vec!["2001:db8:dead::/64".to_string()]);
        }

        #[test]
        fn build_report_daemon_not_running_when_state_is_stale() {
            let dir = tempfile::tempdir().unwrap();
            let peer_id = NodeIdentity::generate();
            let cfg = build_config(dir.path(), &peer_id);

            let state = EngineState {
                version: STATE_VERSION,
                updated_unix: 1_000_000,
                interface: "hextet0".into(),
                node_address: "fd12:3456:78::1".parse().unwrap(),
                node_public_key: "AAAA".into(),
                peers: vec![],
            };
            write(&dir.path().join("state.json"), &state).unwrap();

            let now = UNIX_EPOCH + Duration::from_secs(1_000_000 + 100);
            let report = build_report(&cfg, &MockBackend::default(), now).unwrap();
            let daemon = report.daemon.as_ref().unwrap();
            assert!(!daemon.running);
            assert_eq!(daemon.updated_secs_ago, 100);
        }
    }
}
