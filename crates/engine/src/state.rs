//! 运行时状态快照：daemon 每 tick 原子重写一次，`hextet status` 读它。
//!
//! M2 不做 IPC（见 ADR-0001）：状态文件是 daemon 唯一对外的可观测面。它是
//! **只写不读**的派生数据——daemon 重启后完全从配置与端点缓存重建，因此格式
//! 变更不需要迁移，只需要 [`STATE_VERSION`] 对不上时让读者忽略。

use std::net::{Ipv6Addr, SocketAddrV6};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::cache::CachedEndpoint;
use crate::candidates::normalize;

/// 状态文件格式版本。
pub const STATE_VERSION: u32 = 1;

/// daemon 的运行时状态快照。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineState {
    /// 文件格式版本。
    pub version: u32,
    /// 本次写入时刻（Unix 秒）。读者据此判断 daemon 是否还活着。
    pub updated_unix: u64,
    /// WireGuard 接口名。
    pub interface: String,
    /// 本节点 overlay 地址。
    pub node_address: Ipv6Addr,
    /// 本节点 ed25519 公钥 base64。
    pub node_public_key: String,
    /// 每个 peer 的状态。
    pub peers: Vec<PeerState>,
}

/// 单个 peer 的运行时状态。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerState {
    /// peer 名。
    pub name: String,
    /// peer 的 ed25519 公钥 base64。
    pub public_key: String,
    /// peer 的 overlay 地址。
    pub address: Ipv6Addr,
    /// 打洞状态机状态："probing" 或 "connected"。
    pub punch_state: String,
    /// 当前 endpoint（`probing` 时是正在试的候选）。
    pub endpoint: Option<SocketAddrV6>,
    /// endpoint 的来源："config" / "cache" / "roamed" / "none"。
    pub endpoint_source: String,
    /// 候选 endpoint 总数。
    pub candidates: usize,
    /// 当前候选下标。
    pub candidate_index: usize,
    /// 已走完的完整轮换轮次数。
    pub rounds: u32,
}

/// 原子写入状态文件。
pub fn write(path: &Path, state: &EngineState) -> std::io::Result<()> {
    crate::atomic::write_json(path, state)
}

/// 读取状态文件。
pub fn read(path: &Path) -> std::io::Result<EngineState> {
    crate::atomic::read_json(path)
}

/// `SystemTime` → Unix 秒（早于 epoch 的时间归零）。
pub fn unix_secs(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

/// 判断当前 endpoint 是从哪来的（供 `hextet status` 展示"这条连接是怎么建起来的"）。
///
/// 判定顺序：配置 → 缓存 → 其余（只能是内核 roaming 学到的新地址）。
pub fn endpoint_source(
    endpoint: Option<SocketAddrV6>,
    configured: &[SocketAddrV6],
    cached: &[CachedEndpoint],
) -> &'static str {
    let Some(ep) = endpoint.map(normalize) else {
        return "none";
    };
    if configured.iter().any(|c| normalize(*c) == ep) {
        return "config";
    }
    if cached.iter().any(|c| normalize(c.endpoint) == ep) {
        return "cache";
    }
    "roamed"
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ep(s: &str) -> SocketAddrV6 {
        s.parse().unwrap()
    }

    fn sample() -> EngineState {
        EngineState {
            version: STATE_VERSION,
            updated_unix: 1_770_000_000,
            interface: "hextet0".into(),
            node_address: "fd12:3456:78::1".parse().unwrap(),
            node_public_key: "AAAA".into(),
            peers: vec![PeerState {
                name: "b".into(),
                public_key: "BBBB".into(),
                address: "fd12:3456:78:abcd::2".parse().unwrap(),
                punch_state: "connected".into(),
                endpoint: Some(ep("[2001:db8::b]:4193")),
                endpoint_source: "config".into(),
                candidates: 2,
                candidate_index: 0,
                rounds: 0,
            }],
        }
    }

    #[test]
    fn write_read_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        write(&path, &sample()).unwrap();
        let back = read(&path).unwrap();
        assert_eq!(back.version, STATE_VERSION);
        assert_eq!(back.interface, "hextet0");
        assert_eq!(back.peers.len(), 1);
        assert_eq!(back.peers[0].endpoint, Some(ep("[2001:db8::b]:4193")));
        assert_eq!(back.peers[0].punch_state, "connected");
    }

    #[test]
    fn read_missing_file_is_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let err = read(&dir.path().join("nope.json")).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    }

    #[test]
    fn endpoint_source_classification() {
        let configured = vec![ep("[2001:db8::1]:4193")];
        let cached = vec![CachedEndpoint {
            endpoint: ep("[2001:db8::7]:4193"),
            last_seen_unix: 1,
        }];
        assert_eq!(endpoint_source(None, &configured, &cached), "none");
        assert_eq!(
            endpoint_source(Some(ep("[2001:db8::1]:4193")), &configured, &cached),
            "config"
        );
        assert_eq!(
            endpoint_source(Some(ep("[2001:db8::7]:4193")), &configured, &cached),
            "cache"
        );
        assert_eq!(
            endpoint_source(Some(ep("[2001:db8:9::9]:4193")), &configured, &cached),
            "roamed"
        );
    }

    #[test]
    fn endpoint_source_ignores_scope_id_differences() {
        let configured = vec![ep("[2001:db8::1]:4193")];
        let with_scope = SocketAddrV6::new("2001:db8::1".parse().unwrap(), 4193, 0, 4);
        assert_eq!(
            endpoint_source(Some(with_scope), &configured, &[]),
            "config"
        );
    }

    #[test]
    fn unix_secs_of_epoch_is_zero() {
        assert_eq!(unix_secs(SystemTime::UNIX_EPOCH), 0);
        assert_eq!(
            unix_secs(SystemTime::UNIX_EPOCH + Duration::from_secs(42)),
            42
        );
    }
}
