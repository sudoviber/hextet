//! DHT 会合记录：密钥派生 + AEAD 编解码（协议规范：docs/protocol/dht-record.md、
//! ADR-0005）。
//!
//! 纯逻辑、无 I/O。记录被发布到 Mainline DHT（BEP44/BEP5）时，**外人既定位不到也
//! 读不懂**：定位靠「网络密钥派生的会合 ed25519 密钥对」（ADR-0005），它的公开部分
//! 决定 BEP44 的 target，不知道网络密钥就算不出这个公钥、也就找不到记录；载荷是
//! AEAD 加密的——即使碰巧拿到记录也读不出端点。这把 `dht_key` 同时 gate「定位」（经
//! HMAC 派生出会合密钥种子）与「读懂」（经 AEAD 加密）两件事，因为它们是同一个会合
//! 隐私问题（泄露都只泄露"谁在哪"），与数据面（WireGuard）无关。

use std::net::{Ipv6Addr, SocketAddrV6};

use chacha20poly1305::aead::{Aead, KeyInit, OsRng};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand_core::RngCore as _;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use hextet_core::identity::NodePublicKey;
use hextet_core::network::NetworkKey;

/// 域分隔盐——**必须与 `hextet-core` 的 HKDF 盐一致**（协议版本锚点 `hextet-v1`）。
///
/// 放在本 crate 而不是从 core 导出，是因为 core 的盐是私有的；这里是会合记录
/// 专用派生，与 core 的 network-id/doctor-probe/lan-beacon/relay 派生同源同盐，
/// 只是用途串不同（`"dht-record"`）。
const SALT: &[u8] = b"hextet-v1";

/// AEAD nonce 长度（ChaCha20-Poly1305 标准 12 字节）。
pub const NONCE_LEN: usize = 12;
/// 会合 ed25519 密钥种子长度（32 字节）。
pub const RENDEZVOUS_SEED_LEN: usize = 32;

type HmacSha256 = Hmac<Sha256>;

/// 由网络密钥派生 DHT 记录密钥（`"dht-record"` 用途串，32 字节）。
///
/// 与 `hextet-core` 的 `derive_probe_key` / `derive_lan_key` / `derive_relay_key`
/// 同一条纪律：一把密钥只干一件事。这把密钥只用于会合记录（定位 + 加密），
/// 不与数据面、中继、LAN 公告共用。
pub fn derive_dht_key(network_key: &NetworkKey) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(SALT), network_key.as_bytes());
    let mut out = [0u8; 32];
    hk.expand(b"dht-record", &mut out)
        .expect("32 bytes is a valid hkdf length");
    out
}

/// 由 `dht_key` 与节点公钥派生出会合 ed25519 密钥的种子（32 字节）。
///
/// `HMAC-SHA256(dht_key, "hextet-dht-sign" || node_pubkey)`。BEP44 可变项的 target
/// 是这个种子对应公钥的 SHA1，而公钥由网络密钥派生——不知道 `dht_key` 的人无法
/// 从节点公钥算出 target，也就定位不到记录（见 ADR-0005）。
///
/// 本函数只产出**种子字节**，不构造 ed25519 `SigningKey`：主 crate 用
/// `ed25519-dalek 2`，而 `mainline` 用的是 `ed25519-dalek 3.0.0-pre.1`，两者类型
/// 不兼容。构造 `SigningKey` 的活留给 `crate::client`（它依赖 mainline）。
pub fn rendezvous_seed(dht_key: &[u8; 32], node: &NodePublicKey) -> [u8; RENDEZVOUS_SEED_LEN] {
    let mut mac = <HmacSha256 as hmac::Mac>::new_from_slice(dht_key)
        .expect("HMAC accepts keys of any length");
    mac.update(b"hextet-dht-sign");
    mac.update(node.as_bytes());
    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; RENDEZVOUS_SEED_LEN];
    out.copy_from_slice(&tag[..RENDEZVOUS_SEED_LEN]);
    out
}

/// DHT 记录的明文载荷。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordPayload {
    /// 该节点当前可达的 endpoint（已过滤可用地址；端口已含在 `SocketAddrV6` 里）。
    pub endpoints: Vec<SocketAddrV6>,
    /// 粗粒度 epoch（`unix_secs / 3600`），保护作息隐私。
    pub epoch: u64,
}

/// 把载荷加密成可直接当 DHT value 用的自描述字节串：`nonce(12) || AEAD 密文`。
///
/// nonce 不保密但不可重复；把它前置到密文里，让「一条 DHT 记录」自包含，读取方
/// 不必从别处拿 nonce。
pub fn seal(dht_key: &[u8; 32], payload: &RecordPayload) -> Result<Vec<u8>, String> {
    let json = serde_json::to_vec(payload).map_err(|e| format!("序列化记录载荷失败: {e}"))?;
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(dht_key));
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), json.as_slice())
        .map_err(|_| "AEAD 加密失败".to_string())?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// 解 `seal` 出来的自描述字节串。
pub fn open(dht_key: &[u8; 32], sealed: &[u8]) -> Result<RecordPayload, String> {
    if sealed.len() < NONCE_LEN + 16 {
        return Err("记录过短，无法承载 nonce 与认证标签".to_string());
    }
    let (nonce_bytes, ct) = sealed.split_at(NONCE_LEN);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(dht_key));
    let plain = cipher
        .decrypt(Nonce::from_slice(nonce_bytes), ct)
        .map_err(|_| "AEAD 解密失败（密钥不对或记录被篡改）".to_string())?;
    serde_json::from_slice(&plain).map_err(|e| format!("解析记录载荷失败: {e}"))
}

/// 粗粒度 epoch：`unix_secs / 3600`。
///
/// 用 epoch 而不是精确时间戳，是为了不让 DHT 观察者从记录里推断出节点作息
/// （spec §5「粗粒度 epoch 保护作息隐私」）。
pub fn epoch_of(unix_secs: u64) -> u64 {
    unix_secs / 3600
}

/// 把裸 IPv6 地址过滤后组装成 endpoint（记录载荷里用）。
///
/// 与 LAN/gossip 的过滤同一套规则：丢掉 ULA/链路本地/loopback/multicast/unspecified。
pub fn usable_endpoints(addrs: &[Ipv6Addr], port: u16) -> Vec<SocketAddrV6> {
    if port == 0 {
        return Vec::new();
    }
    addrs
        .iter()
        .filter(|a| hextet_core::addr::is_usable_endpoint_addr(a))
        .map(|a| SocketAddrV6::new(*a, port, 0, 0))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hextet_core::identity::NodeIdentity;

    fn net_key() -> NetworkKey {
        NetworkKey::from_base64("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap()
    }

    fn node(seed: u8) -> NodePublicKey {
        NodeIdentity::from_seed(&[seed; 32]).public()
    }

    #[test]
    fn dht_key_is_deterministic_and_distinct() {
        let nk = net_key();
        let k1 = derive_dht_key(&nk);
        let k2 = derive_dht_key(&nk);
        assert_eq!(k1, k2);
        assert_ne!(k1, *nk.as_bytes());
        // 与别的用途串不同（core 的 derive 函数在本 crate 不可见，这里至少验证
        // 它不是 network key 本身；跨用途串的独立性由 core 的单测覆盖）
        assert_ne!(derive_dht_key(&NetworkKey::generate()), derive_dht_key(&nk));
    }

    #[test]
    fn rendezvous_seed_is_deterministic_and_distinct() {
        let k = derive_dht_key(&net_key());
        let a = rendezvous_seed(&k, &node(2));
        let b = rendezvous_seed(&k, &node(2));
        assert_eq!(a, b);
        assert_eq!(a.len(), RENDEZVOUS_SEED_LEN);
        // 不同节点不同种子
        assert_ne!(rendezvous_seed(&k, &node(2)), rendezvous_seed(&k, &node(3)));
        // 不同网络密钥不同种子（即使同一节点）
        assert_ne!(
            rendezvous_seed(&derive_dht_key(&net_key()), &node(2)),
            rendezvous_seed(&derive_dht_key(&NetworkKey::generate()), &node(2))
        );
    }

    #[test]
    fn seal_open_roundtrip() {
        let k = derive_dht_key(&net_key());
        let payload = RecordPayload {
            endpoints: vec!["[2001:db8::1]:4193".parse().unwrap()],
            epoch: 490_000,
        };
        let sealed = seal(&k, &payload).unwrap();
        // nonce(12) + 认证标签(16) + 一段 JSON；长度不必钉死，但要自洽
        assert!(sealed.len() > NONCE_LEN + 16, "sealed len {}", sealed.len());
        let back = open(&k, &sealed).unwrap();
        assert_eq!(back, payload);
    }

    #[test]
    fn seal_is_randomized() {
        // nonce 随机：同一载荷两次 seal 的字节串不同（否则泄露"记录没变"这一信息）
        let k = derive_dht_key(&net_key());
        let payload = RecordPayload {
            endpoints: vec![],
            epoch: 1,
        };
        let a = seal(&k, &payload).unwrap();
        let b = seal(&k, &payload).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn wrong_key_cannot_open() {
        let payload = RecordPayload {
            endpoints: vec![],
            epoch: 1,
        };
        let sealed = seal(&derive_dht_key(&net_key()), &payload).unwrap();
        assert!(open(&derive_dht_key(&NetworkKey::generate()), &sealed).is_err());
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let k = derive_dht_key(&net_key());
        let payload = RecordPayload {
            endpoints: vec!["[2001:db8::1]:4193".parse().unwrap()],
            epoch: 1,
        };
        let mut sealed = seal(&k, &payload).unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 0xff;
        assert!(open(&k, &sealed).is_err());
    }

    #[test]
    fn open_rejects_short_input() {
        let k = derive_dht_key(&net_key());
        assert!(open(&k, &[0u8; 5]).is_err());
        assert!(open(&k, &[]).is_err());
    }

    #[test]
    fn epoch_of_is_coarse() {
        assert_eq!(epoch_of(0), 0);
        assert_eq!(epoch_of(3599), 0);
        assert_eq!(epoch_of(3600), 1);
        assert_eq!(epoch_of(7200), 2);
    }

    #[test]
    fn usable_endpoints_filters() {
        let addrs: Vec<Ipv6Addr> = vec![
            "2001:db8::1".parse().unwrap(),
            "fd00::1".parse().unwrap(),
            "fe80::1".parse().unwrap(),
            "::1".parse().unwrap(),
        ];
        assert_eq!(
            usable_endpoints(&addrs, 4193),
            vec!["[2001:db8::1]:4193".parse::<SocketAddrV6>().unwrap()]
        );
        assert!(usable_endpoints(&addrs, 0).is_empty());
    }
}
