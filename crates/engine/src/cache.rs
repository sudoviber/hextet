//! 端点缓存：把"上次能连上的 endpoint"持久化，重启后直接复用。
//!
//! 这是**软状态**——丢了只会让重连慢一点（退回配置里的 endpoint），所以读取
//! 路径上的任何错误都降级为空缓存，绝不阻断 daemon 启动。

use std::collections::BTreeMap;
use std::net::SocketAddrV6;
use std::path::Path;

use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::candidates::normalize;

/// 缓存文件格式版本。
const CACHE_VERSION: u32 = 1;

/// 每个 peer 保留的历史 endpoint 条数上限。
pub const CACHE_SEEN_MAX: usize = 8;

/// 一个曾经见到过的 endpoint 及其最后一次被证实可用的时间。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CachedEndpoint {
    /// endpoint 本体（存储前已 [`normalize`]）。
    pub endpoint: SocketAddrV6,
    /// 最后一次被证实可用的 Unix 时间戳（秒）。
    pub last_seen_unix: u64,
}

/// 单个 peer 的缓存条目。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PeerCacheEntry {
    /// 最近一次被证实可用的 endpoint（候选列表里排第一）。
    #[serde(default)]
    pub last_good: Option<SocketAddrV6>,
    /// 历史 endpoint，按 `last_seen_unix` 由新到旧排列，最多 [`CACHE_SEEN_MAX`] 条。
    #[serde(default)]
    pub seen: Vec<CachedEndpoint>,
}

/// 全部 peer 的端点缓存。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointCache {
    /// 文件格式版本。
    pub version: u32,
    /// key = peer 的 ed25519 公钥 base64。
    pub peers: BTreeMap<String, PeerCacheEntry>,
}

impl Default for EndpointCache {
    fn default() -> Self {
        Self::new()
    }
}

impl EndpointCache {
    /// 新建空缓存。
    pub fn new() -> Self {
        Self {
            version: CACHE_VERSION,
            peers: BTreeMap::new(),
        }
    }

    /// 从磁盘读取；文件缺失、损坏或版本不认识时返回空缓存（并 warn）。
    pub fn load(path: &Path) -> Self {
        match crate::atomic::read_json::<Self>(path) {
            Ok(cache) if cache.version == CACHE_VERSION => cache,
            Ok(cache) => {
                warn!(
                    path = %path.display(),
                    found = cache.version,
                    expected = CACHE_VERSION,
                    "端点缓存版本不认识，忽略"
                );
                Self::new()
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Self::new(),
            Err(e) => {
                warn!(path = %path.display(), error = %e, "端点缓存不可读，忽略");
                Self::new()
            }
        }
    }

    /// 原子写入磁盘。
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        crate::atomic::write_json(path, self)
    }

    /// 取某个 peer 的缓存条目。
    pub fn entry(&self, peer_key: &str) -> Option<&PeerCacheEntry> {
        self.peers.get(peer_key)
    }

    /// 记录"该 endpoint 已被证实可用"。
    ///
    /// 同一个 endpoint 重复记录只更新时间戳；`seen` 始终保持由新到旧且不超过
    /// [`CACHE_SEEN_MAX`] 条。
    pub fn record_good(&mut self, peer_key: &str, endpoint: SocketAddrV6, now_unix: u64) {
        let endpoint = normalize(endpoint);
        let entry = self.peers.entry(peer_key.to_owned()).or_default();
        entry.last_good = Some(endpoint);
        match entry.seen.iter_mut().find(|c| c.endpoint == endpoint) {
            Some(existing) => existing.last_seen_unix = now_unix,
            None => entry.seen.push(CachedEndpoint {
                endpoint,
                last_seen_unix: now_unix,
            }),
        }
        entry
            .seen
            .sort_by_key(|c| std::cmp::Reverse(c.last_seen_unix));
        entry.seen.truncate(CACHE_SEEN_MAX);
    }

    /// 逐出某个 peer 的一个 endpoint（会合层判定它已失效，如对端换址后的旧地址）。
    ///
    /// 同时从 `last_good` 与 `seen` 移除，避免死地址被 [`build_candidates`] 喂回
    /// 候选列表、让打洞状态机在「死地址 / 活地址」之间来回轮换收敛不了。
    pub fn evict(&mut self, peer_key: &str, endpoint: SocketAddrV6) {
        let endpoint = normalize(endpoint);
        let Some(entry) = self.peers.get_mut(peer_key) else {
            return;
        };
        if entry.last_good == Some(endpoint) {
            entry.last_good = None;
        }
        entry.seen.retain(|c| c.endpoint != endpoint);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ep(s: &str) -> SocketAddrV6 {
        s.parse().unwrap()
    }

    #[test]
    fn record_then_roundtrip_through_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("endpoints.json");

        let mut cache = EndpointCache::new();
        cache.record_good("peer-a", ep("[2001:db8::1]:4193"), 1000);
        cache.save(&path).unwrap();

        let loaded = EndpointCache::load(&path);
        let entry = loaded.entry("peer-a").expect("entry exists");
        assert_eq!(entry.last_good, Some(ep("[2001:db8::1]:4193")));
        assert_eq!(entry.seen.len(), 1);
        assert_eq!(entry.seen[0].last_seen_unix, 1000);
        assert_eq!(loaded.version, 1);
    }

    #[test]
    fn missing_file_yields_empty_cache() {
        let dir = tempfile::tempdir().unwrap();
        let cache = EndpointCache::load(&dir.path().join("nope.json"));
        assert!(cache.peers.is_empty());
        assert_eq!(cache.version, 1);
    }

    #[test]
    fn corrupt_file_yields_empty_cache() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("endpoints.json");
        std::fs::write(&path, "{ this is not json").unwrap();
        // 缓存是软状态：损坏时必须降级为空，绝不能让 daemon 起不来
        let cache = EndpointCache::load(&path);
        assert!(cache.peers.is_empty());
    }

    #[test]
    fn unknown_version_yields_empty_cache() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("endpoints.json");
        std::fs::write(&path, r#"{"version":999,"peers":{}}"#).unwrap();
        let cache = EndpointCache::load(&path);
        assert!(cache.peers.is_empty());
        assert_eq!(cache.version, 1);
    }

    #[test]
    fn recording_same_endpoint_updates_timestamp_not_length() {
        let mut cache = EndpointCache::new();
        cache.record_good("p", ep("[2001:db8::1]:4193"), 10);
        cache.record_good("p", ep("[2001:db8::1]:4193"), 99);
        let entry = cache.entry("p").unwrap();
        assert_eq!(entry.seen.len(), 1);
        assert_eq!(entry.seen[0].last_seen_unix, 99);
    }

    #[test]
    fn seen_is_newest_first_and_capped() {
        let mut cache = EndpointCache::new();
        for i in 0..(CACHE_SEEN_MAX as u64 + 5) {
            cache.record_good("p", ep(&format!("[2001:db8::{:x}]:4193", i + 1)), i);
        }
        let entry = cache.entry("p").unwrap();
        assert_eq!(entry.seen.len(), CACHE_SEEN_MAX);
        // 最新的排最前
        assert!(entry.seen[0].last_seen_unix > entry.seen[1].last_seen_unix);
        // 最旧的被挤掉
        assert!(entry.seen.iter().all(|c| c.last_seen_unix >= 5));
    }

    #[test]
    fn record_normalizes_endpoint() {
        let mut cache = EndpointCache::new();
        let raw = SocketAddrV6::new("2001:db8::1".parse().unwrap(), 4193, 3, 5);
        cache.record_good("p", raw, 1);
        let entry = cache.entry("p").unwrap();
        assert_eq!(entry.last_good, Some(ep("[2001:db8::1]:4193")));
        assert_eq!(entry.seen[0].endpoint.scope_id(), 0);
    }

    #[test]
    fn last_good_switches_when_a_new_endpoint_works() {
        let mut cache = EndpointCache::new();
        cache.record_good("p", ep("[2001:db8::1]:4193"), 1);
        cache.record_good("p", ep("[2001:db8:2::1]:4193"), 2);
        assert_eq!(
            cache.entry("p").unwrap().last_good,
            Some(ep("[2001:db8:2::1]:4193"))
        );
    }

    #[test]
    fn evict_removes_from_both_last_good_and_seen() {
        let mut cache = EndpointCache::new();
        cache.record_good("p", ep("[2001:db8::1]:4193"), 1);
        cache.record_good("p", ep("[2001:db8::2]:4193"), 2);
        cache.evict("p", ep("[2001:db8::2]:4193"));
        let entry = cache.entry("p").unwrap();
        assert_eq!(entry.last_good, None, "被逐出的不该再是 last_good");
        assert!(
            entry
                .seen
                .iter()
                .all(|c| c.endpoint != ep("[2001:db8::2]:4193")),
            "被逐出的 endpoint 不该留在 seen"
        );
        assert_eq!(entry.seen.len(), 1, "另一个 endpoint 应保留");
        assert_eq!(entry.seen[0].endpoint, ep("[2001:db8::1]:4193"));
    }

    #[test]
    fn evict_unknown_peer_is_a_noop() {
        let mut cache = EndpointCache::new();
        cache.evict("nobody", ep("[2001:db8::1]:4193"));
        assert!(cache.peers.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn saved_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("endpoints.json");
        let mut cache = EndpointCache::new();
        cache.record_good("p", ep("[2001:db8::1]:4193"), 1);
        cache.save(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn save_leaves_no_tmp_file_behind() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("endpoints.json");
        EndpointCache::new().save(&path).unwrap();
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
            .filter(|n| n.ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "leftover tmp files: {leftovers:?}");
    }
}
