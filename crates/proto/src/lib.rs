//! daemon 与 UI 之间共享的 serde 状态类型（`hextet status --json` 的线格式）。
//!
//! 这些类型从 `hextet-cli` 的 `status` 命令抽出，供 CLI（`--json`/人类表格/TUI）
//! 与 `hextet_engine::http` 的 axum HTTP 状态服务器共用同一 JSON 形状——`hextet status --json`
//! 与 `/api/status` 的字段完全一致。字段名与 JSON 形状冻结，不得改动。
#![deny(missing_docs)]

use serde::{Deserialize, Serialize};

/// daemon 存活信息（`--json` 的 `daemon` 字段）。
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DaemonInfo {
    /// daemon 是否在跑（由状态文件新鲜度判定）。
    pub running: bool,
    /// 状态文件距上次更新的秒数。
    pub updated_secs_ago: u64,
    /// 状态文件路径（用于人类输出提示）。
    pub state_file: String,
}

/// 一行 peer 状态。
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StatusRow {
    /// peer 名（配置里不认识的内核 peer 记为 `<unknown>`）。
    pub peer: String,
    /// peer 的 overlay IPv6 地址。
    pub address: String,
    /// 内核记录的当前 endpoint。
    pub endpoint: Option<String>,
    /// 距最近握手的秒数。
    pub last_handshake_secs: Option<u64>,
    /// 接收字节数。
    pub rx_bytes: u64,
    /// 发送字节数。
    pub tx_bytes: u64,
    /// 连接状态：`connected` / `stale` / `no-handshake`。
    pub state: String,
    /// endpoint 来源（`relay`/`config`/`lan`/`gossip`/`cache`/`roamed`/`none`）。
    pub endpoint_source: Option<String>,
    /// 打洞状态（`probing`/`connected`/`relayed`）。
    pub punch_state: Option<String>,
    /// 候选 endpoint 总数。
    pub candidates: Option<usize>,
    /// 当前候选下标。
    pub candidate_index: Option<usize>,
    /// LAN 组播发现当前给出的 endpoint 数量。
    pub lan_endpoints: Option<usize>,
    /// gossip 转介当前给出的 endpoint 数量。
    pub gossip_endpoints: Option<usize>,
    /// 正在经哪个中继（peer 名）；None = 没在中继。
    pub relay_via: Option<String>,
    /// 这个 peer 通告、且本机当前已装进路由表的子网路由（site-to-site）。
    pub routes: Vec<String>,
}

/// 一次完整的 peer 连接状态报告。
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StatusReport {
    /// daemon 存活信息；没有状态文件时为 `None`。
    pub daemon: Option<DaemonInfo>,
    /// 每个 peer 的状态行。
    pub peers: Vec<StatusRow>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 锁定线格式：序列化→反序列化往返一致，且字段名/嵌套结构如 `hextet status --json`。
    #[test]
    fn status_report_roundtrips() {
        let report = StatusReport {
            daemon: Some(DaemonInfo {
                running: true,
                updated_secs_ago: 1,
                state_file: "/var/lib/hextet/state.json".into(),
            }),
            peers: vec![StatusRow {
                peer: "nas".into(),
                address: "fd00::2".into(),
                endpoint: Some("[2001:db8::9]:4193".into()),
                last_handshake_secs: Some(42),
                rx_bytes: 11,
                tx_bytes: 22,
                state: "connected".into(),
                endpoint_source: Some("config".into()),
                punch_state: Some("relayed".into()),
                candidates: Some(3),
                candidate_index: Some(1),
                lan_endpoints: Some(1),
                gossip_endpoints: Some(2),
                relay_via: Some("relay-node".into()),
                routes: vec!["2001:db8:dead::/64".into()],
            }],
        };
        let json = serde_json::to_string(&report).unwrap();
        let back: StatusReport = serde_json::from_str(&json).unwrap();
        assert!(back.daemon.as_ref().unwrap().running);
        assert_eq!(back.daemon.as_ref().unwrap().updated_secs_ago, 1);
        assert_eq!(back.peers[0].peer, "nas");
        assert_eq!(back.peers[0].state, "connected");
        assert_eq!(back.peers[0].relay_via.as_deref(), Some("relay-node"));
        assert_eq!(back.peers[0].routes, vec!["2001:db8:dead::/64".to_string()]);
    }
}
