//! 隧道内 gossip 条目（协议规范：docs/protocol/gossip.md）。
//!
//! gossip（设计 spec §3 D4，落地形态见 ADR-0004）在 WG 隧道内用签名 UDP 报文交换
//! 三种**幂等的小状态声明**：某 node 当前在哪（endpoint）、谁被准入（member）、谁被
//! 吊销（revocation）。隧道外不跑 gossip——传输层只监听 overlay 地址，隧道内已由
//! WireGuard 认证加密，因此条目自身只靠 ed25519 签名 + 单调 `seq` 保证不可伪造与
//! 分区重连后确定性收敛（LWW）。
//!
//! 本模块是**纯逻辑**：条目的规范编码、签名、解析、验签，以及 [`GossipStore`] 的
//! 收敛规则。真正的收发在 `hextet-engine` 里，由 `scripts/netns-e2e-gossip.sh`
//! 端到端覆盖。

use std::cmp::Ordering;
use std::collections::HashMap;
use std::net::{Ipv6Addr, SocketAddrV6};

use crate::addr::is_usable_endpoint_addr;
use crate::error::GossipError;
use crate::identity::{NodeIdentity, NodePublicKey};

/// 条目 magic。
pub const GOSSIP_MAGIC: [u8; 4] = *b"HXTG";
/// 协议版本。
pub const GOSSIP_VERSION: u8 = 1;
/// 一条 endpoint 条目里最多带几个地址（与 LAN 公告一致）。
pub const GOSSIP_MAX_ADDRS: usize = 4;
/// 成员名最长字节数（u8 长度前缀）。
pub const GOSSIP_MAX_NAME: usize = 255;
/// ed25519 签名字节数。
const SIG_LEN: usize = 64;
/// 固定头部长度（magic + version + kind + seq + node + signer）。
const HEADER_LEN: usize = 4 + 1 + 1 + 8 + 32 + 32;
/// invite id 字节数（与 `crate::invite` 一致）。
const INVITE_ID_LEN: usize = 16;

/// 条目类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    /// 某 node 宣告自己当前的 endpoint 地址（自签名）。
    Endpoint,
    /// 管理员（或授权节点）准入某个 node（签发方 = 条目的 `issued_by`）。
    Member,
    /// 管理员（或授权节点）吊销某个 node。
    Revocation,
}

impl Kind {
    fn as_u8(self) -> u8 {
        match self {
            Self::Endpoint => 1,
            Self::Member => 2,
            Self::Revocation => 3,
        }
    }

    fn from_u8(v: u8) -> Result<Self, GossipError> {
        match v {
            1 => Ok(Self::Endpoint),
            2 => Ok(Self::Member),
            3 => Ok(Self::Revocation),
            other => Err(GossipError::BadKind(other)),
        }
    }
}

/// 一条 gossip 条目。
///
/// 三种形态共享「谁是主体（`node`）、谁签的名（`signer`）、单调序号（`seq`）、
/// 签名（`sig`）」；主体与签发方的关系是安全规则，不是可选字段：
///
/// - `Endpoint` 必须**自签名**（signer == node）：你不能替别人宣告地址，否则就是在
///   诱导别人把握手包打到任意地址。
/// - `Member` / `Revocation` 必须由**别人**签发（signer != node）：否则任何节点都能
///   自己准入自己，或自己「吊销」自己来绕过吊销。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entry {
    /// 某 node 宣告自己当前的 endpoint（地址 + WG 端口）。
    Endpoint {
        /// 宣告者。
        node: NodePublicKey,
        /// 该 node 声称可达的 IPv6 地址（未过滤，读取时用 [`Entry::endpoint_addrs`]）。
        endpoints: Vec<Ipv6Addr>,
        /// WireGuard 监听端口。
        port: u16,
        /// 单调序号。
        seq: u64,
        /// 签名（覆盖除 `sig` 外的规范编码）。
        sig: [u8; SIG_LEN],
    },
    /// 准入某个 node 为成员。
    Member {
        /// 被准入的 node。
        node: NodePublicKey,
        /// 成员名（人类可读，用于 `status`）。
        name: String,
        /// 该 node 的 site subnet id（`derive_node_addr` 派生的 16-bit id）。
        site: u16,
        /// 单调序号。
        seq: u64,
        /// 签名。
        sig: [u8; SIG_LEN],
        /// 签发方（管理员/授权节点）公钥。
        issued_by: NodePublicKey,
        /// 关联的一次性 invite id（去重与审计）。
        invite_id: [u8; INVITE_ID_LEN],
    },
    /// 吊销某个 node。
    Revocation {
        /// 被吊销的 node。
        node: NodePublicKey,
        /// 单调序号。
        seq: u64,
        /// 签名。
        sig: [u8; SIG_LEN],
        /// 签发方公钥。
        issued_by: NodePublicKey,
    },
}

impl Entry {
    /// 条目类型。
    pub fn kind(&self) -> Kind {
        match self {
            Self::Endpoint { .. } => Kind::Endpoint,
            Self::Member { .. } => Kind::Member,
            Self::Revocation { .. } => Kind::Revocation,
        }
    }

    /// 主体 node（endpoint 的宣告者 / member 的被准入者 / revocation 的被吊销者）。
    pub fn node(&self) -> &NodePublicKey {
        match self {
            Self::Endpoint { node, .. }
            | Self::Member { node, .. }
            | Self::Revocation { node, .. } => node,
        }
    }

    /// 签名者：endpoint 是 node 自己，member/revocation 是 `issued_by`。
    pub fn signer(&self) -> &NodePublicKey {
        match self {
            Self::Endpoint { node, .. } => node,
            Self::Member { issued_by, .. } | Self::Revocation { issued_by, .. } => issued_by,
        }
    }

    /// 单调序号。
    pub fn seq(&self) -> u64 {
        match self {
            Self::Endpoint { seq, .. }
            | Self::Member { seq, .. }
            | Self::Revocation { seq, .. } => *seq,
        }
    }

    /// 签名。
    pub fn sig(&self) -> &[u8; SIG_LEN] {
        match self {
            Self::Endpoint { sig, .. }
            | Self::Member { sig, .. }
            | Self::Revocation { sig, .. } => sig,
        }
    }

    /// 用 node 身份签名一条 endpoint 条目。
    pub fn sign_endpoint(
        node: &NodeIdentity,
        endpoints: Vec<Ipv6Addr>,
        port: u16,
        seq: u64,
    ) -> Result<Self, GossipError> {
        if endpoints.len() > GOSSIP_MAX_ADDRS {
            return Err(GossipError::TooManyAddrs(endpoints.len()));
        }
        let mut e = Self::Endpoint {
            node: node.public(),
            endpoints,
            port,
            seq,
            sig: [0u8; SIG_LEN],
        };
        let sig = node.sign(&e.signed_region()?);
        if let Self::Endpoint { sig: s, .. } = &mut e {
            *s = sig;
        }
        Ok(e)
    }

    /// 用签发者身份签名一条 member 条目。
    pub fn sign_member(
        issuer: &NodeIdentity,
        node: NodePublicKey,
        name: String,
        site: u16,
        seq: u64,
        invite_id: [u8; INVITE_ID_LEN],
    ) -> Result<Self, GossipError> {
        if name.len() > GOSSIP_MAX_NAME {
            return Err(GossipError::NameTooLong(name.len()));
        }
        let mut e = Self::Member {
            node,
            name,
            site,
            seq,
            sig: [0u8; SIG_LEN],
            issued_by: issuer.public(),
            invite_id,
        };
        let sig = issuer.sign(&e.signed_region()?);
        if let Self::Member { sig: s, .. } = &mut e {
            *s = sig;
        }
        Ok(e)
    }

    /// 用签发者身份签名一条 revocation 条目。
    pub fn sign_revocation(
        issuer: &NodeIdentity,
        node: NodePublicKey,
        seq: u64,
    ) -> Result<Self, GossipError> {
        let mut e = Self::Revocation {
            node,
            seq,
            sig: [0u8; SIG_LEN],
            issued_by: issuer.public(),
        };
        let sig = issuer.sign(&e.signed_region()?);
        if let Self::Revocation { sig: s, .. } = &mut e {
            *s = sig;
        }
        Ok(e)
    }

    /// 签名覆盖的规范编码（头部 + 载荷，**不含** `sig`）。
    ///
    /// 这是「签了什么」的唯一事实来源：编码是定长的、字节级的，不存在 JSON 规范化
    /// 那种键序/空白/数字表示歧义。
    fn signed_region(&self) -> Result<Vec<u8>, GossipError> {
        let mut out = Vec::with_capacity(HEADER_LEN + 64);
        out.extend_from_slice(&GOSSIP_MAGIC);
        out.push(GOSSIP_VERSION);
        out.push(self.kind().as_u8());
        out.extend_from_slice(&self.seq().to_be_bytes());
        out.extend_from_slice(self.node().as_bytes());
        out.extend_from_slice(self.signer().as_bytes());
        match self {
            Self::Endpoint {
                endpoints, port, ..
            } => {
                if endpoints.len() > GOSSIP_MAX_ADDRS {
                    return Err(GossipError::TooManyAddrs(endpoints.len()));
                }
                out.push(endpoints.len() as u8);
                out.extend_from_slice(&port.to_be_bytes());
                for a in endpoints {
                    out.extend_from_slice(&a.octets());
                }
            }
            Self::Member {
                name,
                site,
                invite_id,
                ..
            } => {
                if name.len() > GOSSIP_MAX_NAME {
                    return Err(GossipError::NameTooLong(name.len()));
                }
                out.extend_from_slice(&site.to_be_bytes());
                out.push(name.len() as u8);
                out.extend_from_slice(name.as_bytes());
                out.extend_from_slice(invite_id);
            }
            Self::Revocation { .. } => {}
        }
        Ok(out)
    }

    /// 编码为线格式（规范编码 + 签名）。
    pub fn encode(&self) -> Result<Vec<u8>, GossipError> {
        let mut out = self.signed_region()?;
        out.extend_from_slice(self.sig());
        Ok(out)
    }

    /// 解析线格式并验签。
    ///
    /// 检查顺序：长度下界 → magic → version → kind → 载荷长度自洽 → 签名 → 签名者
    /// 约束。公钥的曲线点校验在签名之前——它是解析其余字段的前提，但相对廉价。
    pub fn decode(bytes: &[u8]) -> Result<Self, GossipError> {
        if bytes.len() < HEADER_LEN + SIG_LEN {
            return Err(GossipError::TooShort);
        }
        if bytes[0..4] != GOSSIP_MAGIC {
            return Err(GossipError::BadMagic);
        }
        if bytes[4] != GOSSIP_VERSION {
            return Err(GossipError::BadVersion(bytes[4]));
        }
        let kind = Kind::from_u8(bytes[5])?;
        let seq = u64::from_be_bytes(bytes[6..14].try_into().expect("8 bytes"));
        let node_raw: [u8; 32] = bytes[14..46].try_into().expect("32 bytes");
        let signer_raw: [u8; 32] = bytes[46..78].try_into().expect("32 bytes");
        let node = NodePublicKey::from_bytes(&node_raw).map_err(|_| GossipError::BadPublicKey)?;
        let signer =
            NodePublicKey::from_bytes(&signer_raw).map_err(|_| GossipError::BadPublicKey)?;

        let entry = match kind {
            Kind::Endpoint => {
                // 载荷 = addr_count(1) + port(2) + 16*n
                let n = usize::from(bytes[78]);
                if n > GOSSIP_MAX_ADDRS {
                    return Err(GossipError::TooManyAddrs(n));
                }
                let expected = HEADER_LEN + 3 + 16 * n + SIG_LEN;
                if bytes.len() != expected {
                    return Err(GossipError::LengthMismatch {
                        expected,
                        got: bytes.len(),
                    });
                }
                let port = u16::from_be_bytes(bytes[79..81].try_into().expect("2 bytes"));
                let mut endpoints = Vec::with_capacity(n);
                for i in 0..n {
                    let off = HEADER_LEN + 3 + 16 * i;
                    let octets: [u8; 16] = bytes[off..off + 16].try_into().expect("16 bytes");
                    endpoints.push(Ipv6Addr::from(octets));
                }
                Self::Endpoint {
                    node: node.clone(),
                    endpoints,
                    port,
                    seq,
                    sig: [0u8; SIG_LEN],
                }
            }
            Kind::Member => {
                // 载荷 = site(2) + name_len(1) + name + invite_id(16)
                let site = u16::from_be_bytes(bytes[78..80].try_into().expect("2 bytes"));
                let name_len = usize::from(bytes[80]);
                let expected = HEADER_LEN + 3 + name_len + INVITE_ID_LEN + SIG_LEN;
                if bytes.len() != expected {
                    return Err(GossipError::LengthMismatch {
                        expected,
                        got: bytes.len(),
                    });
                }
                let name_start = HEADER_LEN + 3;
                let name_end = name_start + name_len;
                let name = std::str::from_utf8(&bytes[name_start..name_end])
                    .map_err(|_| GossipError::BadUtf8)?
                    .to_owned();
                let mut invite_id = [0u8; INVITE_ID_LEN];
                invite_id.copy_from_slice(&bytes[name_end..name_end + INVITE_ID_LEN]);
                Self::Member {
                    node: node.clone(),
                    name,
                    site,
                    seq,
                    sig: [0u8; SIG_LEN],
                    issued_by: signer.clone(),
                    invite_id,
                }
            }
            Kind::Revocation => {
                let expected = HEADER_LEN + SIG_LEN;
                if bytes.len() != expected {
                    return Err(GossipError::LengthMismatch {
                        expected,
                        got: bytes.len(),
                    });
                }
                Self::Revocation {
                    node: node.clone(),
                    seq,
                    sig: [0u8; SIG_LEN],
                    issued_by: signer.clone(),
                }
            }
        };

        let sig_start = bytes.len() - SIG_LEN;
        let sig: [u8; SIG_LEN] = bytes[sig_start..].try_into().expect("64 bytes");
        if !signer.verify(&bytes[..sig_start], &sig) {
            return Err(GossipError::BadSignature);
        }
        // 签名者约束（安全规则，不是可选项）
        if kind == Kind::Endpoint && signer != node {
            return Err(GossipError::EndpointNotSelfSigned);
        }
        if kind != Kind::Endpoint && signer == node {
            return Err(GossipError::SelfIssued);
        }

        Ok(match entry {
            Self::Endpoint {
                node,
                endpoints,
                port,
                seq,
                ..
            } => Self::Endpoint {
                node,
                endpoints,
                port,
                seq,
                sig,
            },
            Self::Member {
                node,
                name,
                site,
                seq,
                issued_by,
                invite_id,
                ..
            } => Self::Member {
                node,
                name,
                site,
                seq,
                sig,
                issued_by,
                invite_id,
            },
            Self::Revocation {
                node,
                seq,
                issued_by,
                ..
            } => Self::Revocation {
                node,
                seq,
                sig,
                issued_by,
            },
        })
    }

    /// 结构合法性：签名者约束 + 签名校验。
    ///
    /// `decode` 已经验过一遍；`GossipStore::merge` 对调用方传入的条目再验一次，
    /// 因为 merge 的入参可能来自手工构造，不能假设它经过了 decode。
    pub fn is_valid(&self) -> bool {
        let signer_ok = match self {
            Self::Endpoint { node, .. } => self.signer() == node,
            Self::Member { .. } | Self::Revocation { .. } => self.signer() != self.node(),
        };
        signer_ok && self.verify()
    }

    /// 验签（不检查签名者约束，那个由 [`Entry::is_valid`] 统一做）。
    pub fn verify(&self) -> bool {
        let Ok(region) = self.signed_region() else {
            return false;
        };
        self.signer().verify(&region, self.sig())
    }

    /// endpoint 条目里可用作 WireGuard endpoint 的地址（已过滤 ULA/链路本地/loopback）。
    ///
    /// 非 endpoint 条目、或 `port == 0` 时返回空。
    pub fn endpoint_addrs(&self) -> Vec<SocketAddrV6> {
        match self {
            Self::Endpoint {
                endpoints, port, ..
            } => {
                if *port == 0 {
                    return Vec::new();
                }
                endpoints
                    .iter()
                    .filter(|a| is_usable_endpoint_addr(a))
                    .map(|a| SocketAddrV6::new(*a, *port, 0, 0))
                    .collect()
            }
            _ => Vec::new(),
        }
    }
}

/// merge 的结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MergeOutcome {
    /// 该条目比表里的更新（或首次出现），已采纳。
    Applied,
    /// 该条目不比表里的新（seq 更旧，或 seq 相同但字节序不更小），忽略。
    Stale,
    /// 该条目签名/结构非法，拒绝。
    Invalid,
    /// 表已达条目上限、且这是新键（防恶意成员用无限新公钥把表撑爆），拒绝。
    Rejected,
}

/// LWW 收敛规则：同主体同类型时取 seq 大者；seq 相同时取规范编码字节序小者
/// （保证确定性，让两个分区最终收敛到同一条目）。
///
/// 返回值语义：`Greater` 表示 `a` 应替换 `b`（`a` 获胜）。
fn lww_compare(a: &Entry, b: &Entry) -> Ordering {
    match a.seq().cmp(&b.seq()) {
        Ordering::Equal => match (a.encode(), b.encode()) {
            // seq 相同：字节序**小**者获胜，所以用 b 与 a 比较——a 更小时返回 Greater
            (Ok(x), Ok(y)) => y.cmp(&x),
            // 无法编码（理论上对已校验的条目不会发生）→ 保守视为不更新
            _ => Ordering::Equal,
        },
        other => other,
    }
}

/// gossip 条目的软状态表。
///
/// key = (主体 node, 类型)：每 node 每类型只留最新一条。**没有成员资格校验**（共享
/// 密钥模型下任何成员都能自签 `Endpoint`），因此用 [`MAX_STORE_ENTRIES`] 对总条目数
/// 封顶，防止恶意成员用无限个新公钥把表与广播无界放大。
#[derive(Debug, Default)]
pub struct GossipStore {
    map: HashMap<(NodePublicKey, Kind), Entry>,
}

/// 表的总条目数上限。键结构保证每 node 每类型一条，但 node 数量本身无界——这个上限
/// 就是针对「无限新公钥」的封顶。512 ≈ 170 个 node 各 3 类条目，对 hextet 的家庭/
/// 朋友网络规模绰绰有余；达到上限后新键的条目被拒绝（已有键的更新仍放行）。
pub const MAX_STORE_ENTRIES: usize = 512;

impl GossipStore {
    /// 新建空表。
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }

    /// 表内条目数。
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// 是否为空。
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// 合并一条目（幂等）。见 [`MergeOutcome`]。
    pub fn merge(&mut self, entry: Entry) -> MergeOutcome {
        if !entry.is_valid() {
            return MergeOutcome::Invalid;
        }
        let key = (entry.node().clone(), entry.kind());
        match self.map.get(&key) {
            Some(existing) if lww_compare(&entry, existing) != Ordering::Greater => {
                MergeOutcome::Stale
            }
            // 已有同键且本条目更新：替换不占新键，不受上限约束。
            Some(_) => {
                self.map.insert(key, entry);
                MergeOutcome::Applied
            }
            // 新键：受表上限约束。
            None => {
                if self.map.len() >= MAX_STORE_ENTRIES {
                    return MergeOutcome::Rejected;
                }
                self.map.insert(key, entry);
                MergeOutcome::Applied
            }
        }
    }

    /// 某 node 最新的 endpoint 条目。
    pub fn endpoint_of(&self, node: &NodePublicKey) -> Option<&Entry> {
        self.map.get(&(node.clone(), Kind::Endpoint))
    }

    /// 某 node 最新的 member 条目。
    pub fn member_of(&self, node: &NodePublicKey) -> Option<&Entry> {
        self.map.get(&(node.clone(), Kind::Member))
    }

    /// 某 node 是否已被吊销（表里有该 node 的 revocation 条目）。
    pub fn is_revoked(&self, node: &NodePublicKey) -> bool {
        self.map.contains_key(&(node.clone(), Kind::Revocation))
    }

    /// 全部条目（广播时用）。
    pub fn entries(&self) -> impl Iterator<Item = &Entry> {
        self.map.values()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn admin() -> NodeIdentity {
        NodeIdentity::from_seed(&[1u8; 32])
    }

    fn alice() -> NodeIdentity {
        NodeIdentity::from_seed(&[2u8; 32])
    }

    fn bob() -> NodeIdentity {
        NodeIdentity::from_seed(&[3u8; 32])
    }

    fn addrs(n: usize) -> Vec<Ipv6Addr> {
        (0..n)
            .map(|i| format!("2001:db8::{i:x}").parse().unwrap())
            .collect()
    }

    fn endpoint_entry(node: &NodeIdentity, seq: u64) -> Entry {
        Entry::sign_endpoint(node, addrs(2), 4193, seq).unwrap()
    }

    fn member_entry(issuer: &NodeIdentity, node: &NodeIdentity, seq: u64) -> Entry {
        Entry::sign_member(issuer, node.public(), "nas".into(), 7, seq, [0xaa; 16]).unwrap()
    }

    #[test]
    fn roundtrip_all_kinds() {
        let endpoint = endpoint_entry(&alice(), 100);
        let back = Entry::decode(&endpoint.encode().unwrap()).unwrap();
        assert_eq!(back, endpoint);
        assert_eq!(back.kind(), Kind::Endpoint);

        let member = member_entry(&admin(), &alice(), 100);
        let back = Entry::decode(&member.encode().unwrap()).unwrap();
        assert_eq!(back, member);
        assert_eq!(back.kind(), Kind::Member);

        let rev = Entry::sign_revocation(&admin(), bob().public(), 100).unwrap();
        let back = Entry::decode(&rev.encode().unwrap()).unwrap();
        assert_eq!(back, rev);
        assert_eq!(back.kind(), Kind::Revocation);
    }

    /// endpoint 必须自签名；别人替你宣告地址是安全违规（诱导我们往任意地址打握手包）。
    ///
    /// 线格式里 endpoint 的 signer 字段恒等于 node（`signed_region` 就是这么写的），
    /// 所以通过公开 API 造不出「替别人宣告」的条目；这里手工拼一份 signer ≠ node 的
    /// 原始字节，确认 `decode` 的防御分支真的会拦。
    #[test]
    fn endpoint_must_be_self_signed() {
        let victim = bob().public();
        let forger = alice();
        // 手工构造 wire：node = victim，signer = forger，签名用 forger
        let mut region = Vec::new();
        region.extend_from_slice(&GOSSIP_MAGIC);
        region.push(GOSSIP_VERSION);
        region.push(Kind::Endpoint.as_u8());
        region.extend_from_slice(&100u64.to_be_bytes());
        region.extend_from_slice(victim.as_bytes());
        region.extend_from_slice(forger.public().as_bytes());
        region.push(1); // addr_count
        region.extend_from_slice(&4193u16.to_be_bytes());
        region.extend_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
        let sig = forger.sign(&region);
        let mut bytes = region;
        bytes.extend_from_slice(&sig);

        assert!(matches!(
            Entry::decode(&bytes).unwrap_err(),
            GossipError::EndpointNotSelfSigned
        ));
    }

    /// 成员/吊销不能自签：否则任何节点都能自己准入自己、或自己「吊销」自己。
    #[test]
    fn member_and_revocation_cannot_be_self_issued() {
        let mut m = Entry::Member {
            node: admin().public(),
            name: "me".into(),
            site: 1,
            seq: 1,
            sig: [0u8; 64],
            issued_by: admin().public(),
            invite_id: [0u8; 16],
        };
        let sig = admin().sign(&m.signed_region().unwrap());
        if let Entry::Member { sig: s, .. } = &mut m {
            *s = sig;
        }
        assert!(!m.is_valid());
        assert!(matches!(
            Entry::decode(&m.encode().unwrap()).unwrap_err(),
            GossipError::SelfIssued
        ));

        let mut r = Entry::Revocation {
            node: admin().public(),
            seq: 1,
            sig: [0u8; 64],
            issued_by: admin().public(),
        };
        let sig = admin().sign(&r.signed_region().unwrap());
        if let Entry::Revocation { sig: s, .. } = &mut r {
            *s = sig;
        }
        assert!(matches!(
            Entry::decode(&r.encode().unwrap()).unwrap_err(),
            GossipError::SelfIssued
        ));
    }

    #[test]
    fn any_flipped_bit_is_rejected() {
        let bytes = endpoint_entry(&alice(), 100).encode().unwrap();
        for i in 0..bytes.len() {
            let mut tampered = bytes.clone();
            tampered[i] ^= 0x01;
            let err = Entry::decode(&tampered).unwrap_err();
            assert!(
                matches!(
                    err,
                    GossipError::BadMagic
                        | GossipError::BadVersion(_)
                        | GossipError::BadKind(_)
                        | GossipError::TooManyAddrs(_)
                        | GossipError::LengthMismatch { .. }
                        | GossipError::BadSignature
                        | GossipError::BadPublicKey
                        | GossipError::EndpointNotSelfSigned
                ),
                "byte {i} 被改动后竟然拿到 {err:?}"
            );
        }
    }

    #[test]
    fn length_must_be_exact() {
        let bytes = endpoint_entry(&alice(), 100).encode().unwrap();
        let mut longer = bytes.clone();
        longer.push(0);
        assert!(matches!(
            Entry::decode(&longer).unwrap_err(),
            GossipError::LengthMismatch { .. }
        ));
        let shorter = &bytes[..bytes.len() - 1];
        assert!(matches!(
            Entry::decode(shorter).unwrap_err(),
            GossipError::LengthMismatch { .. }
        ));
        assert!(matches!(
            Entry::decode(&[0u8; 10]).unwrap_err(),
            GossipError::TooShort
        ));
    }

    #[test]
    fn header_fields_are_validated() {
        let good = endpoint_entry(&alice(), 100).encode().unwrap();

        let mut bad_magic = good.clone();
        bad_magic[0] = b'X';
        assert!(matches!(
            Entry::decode(&bad_magic).unwrap_err(),
            GossipError::BadMagic
        ));

        let mut bad_version = good.clone();
        bad_version[4] = 9;
        assert!(matches!(
            Entry::decode(&bad_version).unwrap_err(),
            GossipError::BadVersion(9)
        ));

        let mut bad_kind = good.clone();
        bad_kind[5] = 7;
        assert!(matches!(
            Entry::decode(&bad_kind).unwrap_err(),
            GossipError::BadKind(7)
        ));
    }

    #[test]
    fn too_many_endpoints_are_rejected() {
        let err = Entry::sign_endpoint(&alice(), addrs(GOSSIP_MAX_ADDRS + 1), 4193, 1).unwrap_err();
        assert!(matches!(err, GossipError::TooManyAddrs(5)), "got {err:?}");
    }

    #[test]
    fn too_long_name_is_rejected() {
        let long = "x".repeat(GOSSIP_MAX_NAME + 1);
        let err =
            Entry::sign_member(&admin(), alice().public(), long, 1, 1, [0u8; 16]).unwrap_err();
        assert!(matches!(err, GossipError::NameTooLong(_)), "got {err:?}");
    }

    #[test]
    fn endpoints_filter_unusable_addresses() {
        let e = Entry::sign_endpoint(
            &alice(),
            vec![
                "2001:db8::1".parse().unwrap(),
                "fd00::1".parse().unwrap(),
                "fe80::1".parse().unwrap(),
                "::1".parse().unwrap(),
            ],
            4193,
            1,
        )
        .unwrap();
        assert_eq!(
            e.endpoint_addrs(),
            vec!["[2001:db8::1]:4193".parse::<SocketAddrV6>().unwrap()]
        );
        // port == 0 不是合法 endpoint
        let zero = Entry::sign_endpoint(&alice(), addrs(1), 0, 1).unwrap();
        assert!(zero.endpoint_addrs().is_empty());
    }

    #[test]
    fn store_applies_then_rejects_stale() {
        let mut store = GossipStore::new();
        assert_eq!(
            store.merge(endpoint_entry(&alice(), 100)),
            MergeOutcome::Applied
        );
        assert_eq!(
            store.merge(endpoint_entry(&alice(), 100)),
            MergeOutcome::Stale
        );
        assert_eq!(
            store.merge(endpoint_entry(&alice(), 50)),
            MergeOutcome::Stale
        );
        assert_eq!(
            store.merge(endpoint_entry(&alice(), 200)),
            MergeOutcome::Applied
        );
        assert_eq!(store.endpoint_of(&alice().public()).unwrap().seq(), 200);
    }

    /// LWW 的确定性：seq 相同时取规范编码字节序小者，两个节点最终收敛到同一条目。
    #[test]
    fn store_prefers_smaller_bytes_on_seq_tie() {
        let mut store = GossipStore::new();
        // alice 的 endpoint 先带 2 个地址，后带 1 个地址（字节更短 → 字节序更小）
        let two = Entry::sign_endpoint(&alice(), addrs(2), 4193, 100).unwrap();
        let one = Entry::sign_endpoint(&alice(), addrs(1), 4193, 100).unwrap();
        assert!(one.encode().unwrap().len() < two.encode().unwrap().len());
        assert_eq!(store.merge(two), MergeOutcome::Applied);
        assert_eq!(store.merge(one), MergeOutcome::Applied);
        assert_eq!(
            store
                .endpoint_of(&alice().public())
                .unwrap()
                .endpoint_addrs()
                .len(),
            1
        );
    }

    #[test]
    fn store_rejects_invalid() {
        let mut store = GossipStore::new();
        // 篡改签名后 merge 必须拒绝
        let mut entry = endpoint_entry(&alice(), 100);
        if let Entry::Endpoint { sig, .. } = &mut entry {
            sig[0] ^= 0xff;
        }
        assert_eq!(store.merge(entry), MergeOutcome::Invalid);
        assert!(store.is_empty());
    }

    #[test]
    fn store_tracks_members_and_revocations() {
        let mut store = GossipStore::new();
        assert_eq!(
            store.merge(member_entry(&admin(), &alice(), 1)),
            MergeOutcome::Applied
        );
        assert!(store.member_of(&alice().public()).is_some());
        assert!(!store.is_revoked(&alice().public()));

        let rev = Entry::sign_revocation(&admin(), alice().public(), 2).unwrap();
        assert_eq!(store.merge(rev), MergeOutcome::Applied);
        assert!(store.is_revoked(&alice().public()));
        // 吊销不删 member 条目（保留审计信息），只是 is_revoked 返回真
        assert!(store.member_of(&alice().public()).is_some());
    }

    /// 表总条目数封顶：填满后新键被拒绝，已有键的更新仍放行。
    #[test]
    fn store_caps_total_entries() {
        let mut store = GossipStore::new();
        for i in 0..MAX_STORE_ENTRIES {
            // 用 i 的两个字节区分 512 个不同的 node 种子
            let mut seed = [0u8; 32];
            seed[0] = (i & 0xFF) as u8;
            seed[1] = (i >> 8) as u8;
            let id = NodeIdentity::from_seed(&seed);
            assert_eq!(store.merge(endpoint_entry(&id, 1)), MergeOutcome::Applied);
        }
        assert_eq!(store.len(), MAX_STORE_ENTRIES);

        // 新键（第 513 个 node）→ 拒绝，表不增长
        let newcomer = NodeIdentity::from_seed(&[0xEE; 32]);
        assert_eq!(
            store.merge(endpoint_entry(&newcomer, 1)),
            MergeOutcome::Rejected
        );
        assert_eq!(store.len(), MAX_STORE_ENTRIES, "拒绝后表不该增长");

        // 已有键的更新（seq 更高）仍放行，且不占新键
        let first = NodeIdentity::from_seed(&[0u8; 32]);
        assert_eq!(
            store.merge(endpoint_entry(&first, 2)),
            MergeOutcome::Applied
        );
        assert_eq!(store.len(), MAX_STORE_ENTRIES, "更新已有键不增长表");
    }

    proptest::proptest! {
        /// 任意字节输入不能让解码 panic（gossip 从网络来，输入完全不可控）。
        #[test]
        fn decode_never_panics_on_arbitrary_bytes(
            bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..400),
        ) {
            let _ = Entry::decode(&bytes);
        }

        #[test]
        fn endpoint_roundtrip(
            port in proptest::prelude::any::<u16>(),
            seq in proptest::prelude::any::<u64>(),
            n in 0usize..=GOSSIP_MAX_ADDRS,
            octets in proptest::prelude::any::<[u8; 16]>(),
        ) {
            let endpoints: Vec<Ipv6Addr> = (0..n)
                .map(|i| {
                    let mut o = octets;
                    o[15] = o[15].wrapping_add(i as u8);
                    Ipv6Addr::from(o)
                })
                .collect();
            let e = Entry::sign_endpoint(&alice(), endpoints.clone(), port, seq).unwrap();
            let back = Entry::decode(&e.encode().unwrap()).unwrap();
            proptest::prop_assert_eq!(back.kind(), Kind::Endpoint);
            proptest::prop_assert_eq!(back, e);
        }
    }
}
