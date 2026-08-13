//! 运行时成员表持久化（gossip 准入的成员，落盘到 `<state_dir>/members.json`）。
//!
//! 与端点缓存同风格：这是**软状态**——丢了只会让 gossip 重新广播一次 member 条目，
//! 读取路径上的任何错误都降级为空表，绝不阻断 daemon 启动。文件用原子写
//! （[`crate::atomic::write_json`]），格式与 `endpoints.json` / `state.json` 一致。

use std::net::Ipv6Addr;
use std::path::Path;

use serde::{Deserialize, Serialize};
use tracing::warn;

/// 成员表文件格式版本。
const MEMBERS_VERSION: u32 = 1;

/// 一条成员记录。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberRecord {
    /// 成员名（人类可读）。
    pub name: String,
    /// 成员的 ed25519 公钥 base64。
    pub public_key: String,
    /// 成员的 overlay /128 地址。
    pub address: Ipv6Addr,
}

/// 全部 gossip 准入成员的持久化表。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MembersFile {
    /// 文件格式版本。
    pub version: u32,
    /// 成员列表（按准入顺序）。
    #[serde(default)]
    pub members: Vec<MemberRecord>,
}

impl Default for MembersFile {
    fn default() -> Self {
        Self::new()
    }
}

impl MembersFile {
    /// 新建空表。
    pub fn new() -> Self {
        Self {
            version: MEMBERS_VERSION,
            members: Vec::new(),
        }
    }

    /// 从磁盘读取；文件缺失、损坏或版本不认识时返回空表（并 warn）。
    pub fn load(path: &Path) -> Self {
        match crate::atomic::read_json::<Self>(path) {
            Ok(m) if m.version == MEMBERS_VERSION => m,
            Ok(m) => {
                warn!(
                    path = %path.display(),
                    found = m.version,
                    expected = MEMBERS_VERSION,
                    "成员表版本不认识，忽略"
                );
                Self::new()
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Self::new(),
            Err(e) => {
                warn!(path = %path.display(), error = %e, "成员表不可读，忽略");
                Self::new()
            }
        }
    }

    /// 原子写入磁盘。
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        crate::atomic::write_json(path, self)
    }

    /// 按公钥查找成员。
    pub fn get(&self, public_key: &str) -> Option<&MemberRecord> {
        self.members.iter().find(|m| m.public_key == public_key)
    }

    /// 准入（或更新）一个成员；公钥已存在则更新名字与地址，返回是否新增。
    pub fn upsert(&mut self, record: MemberRecord) -> bool {
        if let Some(existing) = self
            .members
            .iter_mut()
            .find(|m| m.public_key == record.public_key)
        {
            *existing = record;
            false
        } else {
            self.members.push(record);
            true
        }
    }

    /// 移除一个成员（幂等）。
    pub fn remove(&mut self, public_key: &str) -> bool {
        let before = self.members.len();
        self.members.retain(|m| m.public_key != public_key);
        self.members.len() != before
    }
}

/// 把 overlay /128 地址压成所属 /64 site 网络地址（AllowedIPs 用）。
pub fn site_of(address: Ipv6Addr) -> Ipv6Addr {
    let mut octets = address.octets();
    octets[8..].fill(0);
    Ipv6Addr::from(octets)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(name: &str, pk: &str) -> MemberRecord {
        MemberRecord {
            name: name.into(),
            public_key: pk.into(),
            address: "fd12:3456:78::1".parse().unwrap(),
        }
    }

    #[test]
    fn upsert_inserts_then_updates() {
        let mut m = MembersFile::new();
        assert!(m.upsert(rec("a", "K1")));
        assert!(m.upsert(rec("b", "K2")));
        assert!(!m.upsert(MemberRecord {
            name: "a-renamed".into(),
            public_key: "K1".into(),
            address: "fd12:3456:78::2".parse().unwrap(),
        }));
        assert_eq!(m.members.len(), 2);
        assert_eq!(m.get("K1").unwrap().name, "a-renamed");
        assert_eq!(
            m.get("K1").unwrap().address,
            "fd12:3456:78::2".parse::<Ipv6Addr>().unwrap()
        );
    }

    #[test]
    fn remove_is_idempotent() {
        let mut m = MembersFile::new();
        m.upsert(rec("a", "K1"));
        assert!(m.remove("K1"));
        assert!(!m.remove("K1"));
        assert!(m.members.is_empty());
    }

    #[test]
    fn roundtrip_through_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("members.json");
        let mut m = MembersFile::new();
        m.upsert(rec("nas", "K1"));
        m.save(&path).unwrap();
        let loaded = MembersFile::load(&path);
        assert_eq!(loaded.version, MEMBERS_VERSION);
        assert_eq!(loaded.members, m.members);
    }

    #[test]
    fn missing_or_corrupt_file_yields_empty() {
        let dir = tempfile::tempdir().unwrap();
        assert!(
            MembersFile::load(&dir.path().join("nope.json"))
                .members
                .is_empty()
        );
        let p = dir.path().join("bad.json");
        std::fs::write(&p, "{ not json").unwrap();
        assert!(MembersFile::load(&p).members.is_empty());
        let p2 = dir.path().join("old.json");
        std::fs::write(&p2, r#"{"version":999,"members":[]}"#).unwrap();
        assert!(MembersFile::load(&p2).members.is_empty());
    }

    #[test]
    fn site_of_masks_host_bits() {
        let addr: Ipv6Addr = "fd12:3456:78:abcd::1234".parse().unwrap();
        let site = site_of(addr);
        assert_eq!(site, "fd12:3456:78:abcd::".parse::<Ipv6Addr>().unwrap());
        assert_eq!(&addr.octets()[..8], &site.octets()[..8]);
        assert_eq!(&site.octets()[8..], &[0u8; 8]);
    }
}
