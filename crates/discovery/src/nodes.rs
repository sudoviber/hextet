//! DHT 节点表持久化（`<state_dir>/dht-nodes.json`）。
//!
//! Mainline DHT 的 bootstrap 只在**首次冷启动**时用；之后每次运行时把路由表里的
//! 节点持久化，下次启动直接用它们 bootstrap，避免每次冷启动都依赖公开节点
//! （`docs/protocol/dht-record.md` §5）。
//!
//! 与 `hextet-engine` 的 `endpoints.json` 同风格：**软状态**——丢了只会让下次冷启动
//! 退回公开 bootstrap 节点，读取路径上的任何错误都降级为空列表，绝不阻断 daemon。
//! 写盘用「临时文件 → fsync → rename」的原子替换。

use std::io;
use std::net::Ipv4Addr;
use std::path::Path;

use serde::{Deserialize, Serialize};
use tracing::warn;

/// 节点表文件格式版本。
const NODES_VERSION: u32 = 1;

/// 一条 bootstrap 节点记录：`"ip:port"` 字符串（mainline 的 `to_bootstrap` 格式）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DhtNodesFile {
    /// 文件格式版本。
    pub version: u32,
    /// 持久化的 bootstrap 节点（`"ip:port"`）。
    #[serde(default)]
    pub nodes: Vec<String>,
}

impl Default for DhtNodesFile {
    fn default() -> Self {
        Self::new()
    }
}

impl DhtNodesFile {
    /// 新建空表。
    pub fn new() -> Self {
        Self {
            version: NODES_VERSION,
            nodes: Vec::new(),
        }
    }

    /// 从磁盘读取；文件缺失、损坏或版本不认识时返回空表（并 warn）。
    pub fn load(path: &Path) -> Self {
        match read_json::<Self>(path) {
            Ok(n) if n.version == NODES_VERSION => n,
            Ok(n) => {
                warn!(
                    path = %path.display(),
                    found = n.version,
                    expected = NODES_VERSION,
                    "DHT 节点表版本不认识，忽略"
                );
                Self::new()
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Self::new(),
            Err(e) => {
                warn!(path = %path.display(), error = %e, "DHT 节点表不可读，忽略");
                Self::new()
            }
        }
    }

    /// 原子写入磁盘。
    pub fn save(&self, path: &Path) -> io::Result<()> {
        write_json(path, self)
    }

    /// 用路由表里新学到的节点刷新本表（去重、截断到 [`MAX_NODES`]）。
    pub fn refresh(&mut self, bootstrap: Vec<String>) {
        let mut merged = bootstrap;
        for n in &self.nodes {
            if !merged.contains(n) {
                merged.push(n.clone());
            }
        }
        merged.truncate(MAX_NODES);
        self.nodes = merged;
    }
}

/// 持久化的 bootstrap 节点上限。
pub const MAX_NODES: usize = 128;

/// 解析一条 `"ip:port"` 字符串为 IPv4 地址（校验其是合法 IPv4，避免坏数据进 DHT）。
pub fn parse_ipv4(s: &str) -> Option<Ipv4Addr> {
    let ip = s.split(':').next()?;
    ip.parse::<Ipv4Addr>().ok()
}

fn invalid_data(e: serde_json::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e)
}

/// 原子写入 JSON（Unix 下权限 0600）——与 `hextet-engine::atomic` 同语义，但 discovery
/// 是低层 crate，不依赖 engine（避免分层倒挂）。
fn write_json<T: Serialize>(path: &Path, value: &T) -> io::Result<()> {
    use std::io::Write as _;

    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let stem = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "nodes".to_string());
    let tmp = dir.join(format!(".{stem}.tmp"));

    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let mut f = opts.open(&tmp)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    }
    serde_json::to_writer_pretty(&mut f, value).map_err(invalid_data)?;
    f.write_all(b"\n")?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(&tmp, path)
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> io::Result<T> {
    let text = std::fs::read_to_string(path)?;
    serde_json::from_str(&text).map_err(invalid_data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_through_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dht-nodes.json");
        let mut n = DhtNodesFile::new();
        n.refresh(vec!["1.2.3.4:6881".into(), "5.6.7.8:6881".into()]);
        n.save(&path).unwrap();
        let loaded = DhtNodesFile::load(&path);
        assert_eq!(loaded.version, NODES_VERSION);
        assert_eq!(loaded.nodes, n.nodes);
    }

    #[test]
    fn refresh_dedupes_and_caps() {
        let mut n = DhtNodesFile::new();
        n.refresh(vec!["1.2.3.4:6881".into()]);
        n.refresh(vec!["1.2.3.4:6881".into(), "5.6.7.8:6881".into()]);
        assert_eq!(n.nodes.len(), 2, "去重后仍只有两条");

        // 超过上限时截断
        let many: Vec<String> = (0..(MAX_NODES as u32 + 50))
            .map(|i| format!("10.0.{}.{}:6881", i / 256, i % 256))
            .collect();
        n.refresh(many);
        assert_eq!(n.nodes.len(), MAX_NODES);
    }

    #[test]
    fn missing_or_corrupt_yields_empty() {
        let dir = tempfile::tempdir().unwrap();
        assert!(
            DhtNodesFile::load(&dir.path().join("nope.json"))
                .nodes
                .is_empty()
        );
        let p = dir.path().join("bad.json");
        std::fs::write(&p, "{ not json").unwrap();
        assert!(DhtNodesFile::load(&p).nodes.is_empty());
        let p2 = dir.path().join("old.json");
        std::fs::write(&p2, r#"{"version":999,"nodes":[]}"#).unwrap();
        assert!(DhtNodesFile::load(&p2).nodes.is_empty());
    }

    #[test]
    fn parse_ipv4_accepts_valid_rejects_invalid() {
        assert_eq!(parse_ipv4("1.2.3.4:6881"), Some("1.2.3.4".parse().unwrap()));
        assert!(parse_ipv4("not-an-ip:6881").is_none());
        assert!(parse_ipv4(":6881").is_none());
    }
}
