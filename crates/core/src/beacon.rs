//! LAN 组播公告报文（协议规范：docs/protocol/lan-discovery.md）。
//!
//! 同一 LAN 内的两个节点用它互相告知「我是谁、我在哪个 IPv6 上、WG 端口是几」，
//! 于是不需要任何配置、任何服务器就能连上；双方同时换前缀时也能在一个公告周期内
//! 重新找到彼此（设计 spec §3 D3 兜底链第 ① 层）。
//!
//! 报文用网络密钥派生的密钥做 HMAC 认证：LAN 上的任意设备**不能**伪造成员的地址
//! 让我们去打洞。它不加密——公钥与地址是明文，同 LAN 的观察者能看出这里在用 hextet
//! （标准 mDNS 方案同样如此，见 ADR-0002）。

use std::net::{Ipv6Addr, SocketAddrV6};

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::addr::is_usable_endpoint_addr;
use crate::error::BeaconError;
use crate::identity::NodePublicKey;

/// 报文 magic。
pub const BEACON_MAGIC: [u8; 4] = *b"HXTL";
/// 协议版本。
pub const BEACON_VERSION: u8 = 1;
/// 一条公告里最多带几个地址。
///
/// 多前缀主机（运营商 GUA + 临时地址 + 二级路由 PD）常有三四个全局地址；4 个
/// 既够用又让报文停在 130 字节，远小于任何链路的 MTU。
pub const BEACON_MAX_ADDRS: usize = 4;
/// 报文最大长度（`BEACON_MAX_ADDRS` 个地址时）。
pub const BEACON_MAX_LEN: usize = HEADER_LEN + 16 * BEACON_MAX_ADDRS + MAC_LEN;

/// 头部长度（magic..公钥，含公钥）。
const HEADER_LEN: usize = 50;
/// 截断后的 MAC 长度。
const MAC_LEN: usize = 16;
/// `kind` 字段：公告。v1 只有这一种。
const KIND_ANNOUNCE: u8 = 1;

type HmacSha256 = Hmac<Sha256>;

/// 一条 LAN 公告。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Beacon {
    /// 公告者的 ed25519 公钥。
    pub node_public_key: NodePublicKey,
    /// 公告者的 WireGuard 监听端口。
    pub listen_port: u16,
    /// 发送时的 Unix 秒，用于抗重放（收方要求单调不减且与本地时钟接近）。
    pub seq: u64,
    /// 公告者声称可达的 IPv6 地址。
    pub addresses: Vec<Ipv6Addr>,
}

impl Beacon {
    /// 编码为线格式。
    pub fn encode(&self, lan_key: &[u8; 32]) -> Result<Vec<u8>, BeaconError> {
        let n = self.addresses.len();
        if n > BEACON_MAX_ADDRS {
            return Err(BeaconError::TooManyAddrs(n));
        }
        let mut out = Vec::with_capacity(HEADER_LEN + 16 * n + MAC_LEN);
        out.extend_from_slice(&BEACON_MAGIC);
        out.push(BEACON_VERSION);
        out.push(KIND_ANNOUNCE);
        out.push(n as u8);
        out.push(0); // reserved
        out.extend_from_slice(&self.listen_port.to_be_bytes());
        out.extend_from_slice(&self.seq.to_be_bytes());
        out.extend_from_slice(self.node_public_key.as_bytes());
        for a in &self.addresses {
            out.extend_from_slice(&a.octets());
        }
        debug_assert_eq!(out.len(), HEADER_LEN + 16 * n);
        let mut mac = HmacSha256::new_from_slice(lan_key).expect("HMAC accepts keys of any length");
        mac.update(&out);
        let tag = mac.finalize().into_bytes();
        out.extend_from_slice(&tag[..MAC_LEN]);
        Ok(out)
    }

    /// 解析线格式并校验 MAC。
    ///
    /// 检查顺序：长度下界 → magic → version → kind → reserved → addr_count 上界 →
    /// **总长必须精确自洽** → MAC → 公钥合法性。变长报文不接受尾随填充：长度不自洽
    /// 时解析就有歧义，宁可拒绝。公钥的曲线点校验放在 MAC 之后——它是这里最贵的一步，
    /// 不给未认证的报文花这个钱。
    pub fn decode(bytes: &[u8], lan_key: &[u8; 32]) -> Result<Self, BeaconError> {
        if bytes.len() < HEADER_LEN + MAC_LEN {
            return Err(BeaconError::TooShort);
        }
        if bytes[0..4] != BEACON_MAGIC {
            return Err(BeaconError::BadMagic);
        }
        if bytes[4] != BEACON_VERSION {
            return Err(BeaconError::BadVersion(bytes[4]));
        }
        if bytes[5] != KIND_ANNOUNCE {
            return Err(BeaconError::BadKind(bytes[5]));
        }
        if bytes[7] != 0 {
            return Err(BeaconError::BadReserved);
        }
        let n = usize::from(bytes[6]);
        if n > BEACON_MAX_ADDRS {
            return Err(BeaconError::TooManyAddrs(n));
        }
        let expected = HEADER_LEN + 16 * n + MAC_LEN;
        if bytes.len() != expected {
            return Err(BeaconError::LengthMismatch {
                expected,
                got: bytes.len(),
            });
        }

        let body = &bytes[..expected - MAC_LEN];
        let mut mac = HmacSha256::new_from_slice(lan_key).expect("HMAC accepts keys of any length");
        mac.update(body);
        // verify_truncated_left 是常量时间比较，不要换成 == 手写比较
        mac.verify_truncated_left(&bytes[expected - MAC_LEN..])
            .map_err(|_| BeaconError::BadMac)?;

        let listen_port = u16::from_be_bytes(bytes[8..10].try_into().expect("2 bytes"));
        let seq = u64::from_be_bytes(bytes[10..18].try_into().expect("8 bytes"));
        let key_bytes: [u8; 32] = bytes[18..50].try_into().expect("32 bytes");
        let node_public_key =
            NodePublicKey::from_bytes(&key_bytes).map_err(|_| BeaconError::BadPublicKey)?;
        let mut addresses = Vec::with_capacity(n);
        for i in 0..n {
            let off = HEADER_LEN + 16 * i;
            let octets: [u8; 16] = bytes[off..off + 16].try_into().expect("16 bytes");
            addresses.push(Ipv6Addr::from(octets));
        }

        Ok(Self {
            node_public_key,
            listen_port,
            seq,
            addresses,
        })
    }

    /// 公告里可用作 endpoint 的地址（已过滤 ULA/链路本地/loopback 等）。
    ///
    /// 地址是对端**声称**的，所以这里必须过滤：否则一个成员（或知道网络密钥的人）
    /// 就能让我们把握手包打到任意地址去。
    pub fn endpoints(&self) -> Vec<SocketAddrV6> {
        if self.listen_port == 0 {
            return Vec::new();
        }
        self.addresses
            .iter()
            .filter(|a| is_usable_endpoint_addr(a))
            .map(|a| SocketAddrV6::new(*a, self.listen_port, 0, 0))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::NodeIdentity;
    use crate::network::{NetworkKey, derive_lan_key};
    use std::net::{Ipv6Addr, SocketAddrV6};

    fn key() -> [u8; 32] {
        derive_lan_key(
            &NetworkKey::from_base64("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap(),
        )
    }

    fn node() -> crate::identity::NodePublicKey {
        NodeIdentity::from_seed(&[5u8; 32]).public()
    }

    fn sample(n: usize) -> Beacon {
        Beacon {
            node_public_key: node(),
            listen_port: 4193,
            seq: 1_770_000_000,
            addresses: (0..n)
                .map(|i| {
                    format!("2001:db8::{:x}", i + 1)
                        .parse::<Ipv6Addr>()
                        .unwrap()
                })
                .collect(),
        }
    }

    #[test]
    fn roundtrip_zero_one_and_max_addresses() {
        for n in [0usize, 1, BEACON_MAX_ADDRS] {
            let b = sample(n);
            let bytes = b.encode(&key()).unwrap();
            assert_eq!(bytes.len(), 50 + 16 * n + 16);
            assert!(bytes.len() <= BEACON_MAX_LEN);
            let back = Beacon::decode(&bytes, &key()).unwrap();
            assert_eq!(back.node_public_key, b.node_public_key);
            assert_eq!(back.listen_port, b.listen_port);
            assert_eq!(back.seq, b.seq);
            assert_eq!(back.addresses, b.addresses);
        }
    }

    #[test]
    fn encode_rejects_too_many_addresses() {
        // 静默截断会让"我到底广告了哪些地址"不可预测：必须报错，由调用方显式截断
        let err = sample(BEACON_MAX_ADDRS + 1).encode(&key()).unwrap_err();
        assert!(matches!(err, BeaconError::TooManyAddrs(5)), "got {err:?}");
    }

    #[test]
    fn wrong_key_is_rejected() {
        let bytes = sample(2).encode(&key()).unwrap();
        assert!(matches!(
            Beacon::decode(&bytes, &[9u8; 32]).unwrap_err(),
            BeaconError::BadMac
        ));
    }

    #[test]
    fn any_flipped_bit_is_rejected() {
        let bytes = sample(2).encode(&key()).unwrap();
        for i in 0..bytes.len() {
            let mut tampered = bytes.clone();
            tampered[i] ^= 0x01;
            let err = Beacon::decode(&tampered, &key()).unwrap_err();
            assert!(
                matches!(
                    err,
                    BeaconError::BadMac
                        | BeaconError::BadMagic
                        | BeaconError::BadVersion(_)
                        | BeaconError::BadKind(_)
                        | BeaconError::BadReserved
                        | BeaconError::LengthMismatch { .. }
                        | BeaconError::TooManyAddrs(_)
                ),
                "byte {i} 被改动后竟然拿到 {err:?}"
            );
        }
    }

    #[test]
    fn length_must_be_exact() {
        let bytes = sample(1).encode(&key()).unwrap();
        let mut longer = bytes.clone();
        longer.push(0);
        assert!(matches!(
            Beacon::decode(&longer, &key()).unwrap_err(),
            BeaconError::LengthMismatch { .. }
        ));
        let shorter = &bytes[..bytes.len() - 1];
        assert!(matches!(
            Beacon::decode(shorter, &key()).unwrap_err(),
            BeaconError::LengthMismatch { .. }
        ));
        assert!(matches!(
            Beacon::decode(&[0u8; 10], &key()).unwrap_err(),
            BeaconError::TooShort
        ));
    }

    #[test]
    fn header_fields_are_validated() {
        let good = sample(1).encode(&key()).unwrap();

        let mut bad_magic = good.clone();
        bad_magic[0] = b'X';
        assert!(matches!(
            Beacon::decode(&bad_magic, &key()).unwrap_err(),
            BeaconError::BadMagic
        ));

        let mut bad_version = good.clone();
        bad_version[4] = 2;
        assert!(matches!(
            Beacon::decode(&bad_version, &key()).unwrap_err(),
            BeaconError::BadVersion(2)
        ));

        let mut bad_kind = good.clone();
        bad_kind[5] = 7;
        assert!(matches!(
            Beacon::decode(&bad_kind, &key()).unwrap_err(),
            BeaconError::BadKind(7)
        ));

        // reserved 必须为 0：留给未来的 flag 位，现在乱填一律拒绝
        let mut bad_reserved = good.clone();
        bad_reserved[7] = 1;
        assert!(matches!(
            Beacon::decode(&bad_reserved, &key()).unwrap_err(),
            BeaconError::BadReserved
        ));

        // addr_count 超上限：长度检查会先命中（因为报文长度与之不符）
        let mut bad_count = good.clone();
        bad_count[6] = 9;
        assert!(
            Beacon::decode(&bad_count, &key()).is_err(),
            "addr_count 越界必须被拒"
        );
    }

    /// 公告里的地址是对端**声称**的；不可用作 endpoint 的一律丢掉。
    /// 尤其是 ULA——hextet 自己的 overlay 就是 ULA，拿它当 endpoint 会形成回环。
    #[test]
    fn endpoints_filter_unusable_addresses() {
        let b = Beacon {
            node_public_key: node(),
            listen_port: 4193,
            seq: 1,
            addresses: vec![
                "2001:db8::1".parse().unwrap(),
                "fd00::1".parse().unwrap(),
                "fe80::1".parse().unwrap(),
                "::1".parse().unwrap(),
            ],
        };
        assert_eq!(
            b.endpoints(),
            vec!["[2001:db8::1]:4193".parse::<SocketAddrV6>().unwrap()]
        );
    }

    #[test]
    fn endpoints_are_empty_without_a_port() {
        let b = Beacon {
            node_public_key: node(),
            listen_port: 0,
            seq: 1,
            addresses: vec!["2001:db8::1".parse().unwrap()],
        };
        assert!(b.endpoints().is_empty());
    }

    #[test]
    fn lan_key_is_its_own_key() {
        let nk = NetworkKey::generate();
        assert_eq!(derive_lan_key(&nk), derive_lan_key(&nk));
        assert_ne!(derive_lan_key(&nk), *nk.as_bytes());
        assert_ne!(derive_lan_key(&nk), crate::network::derive_probe_key(&nk));
        assert_ne!(derive_lan_key(&nk), derive_lan_key(&NetworkKey::generate()));
    }

    /// 钉扎向量：全零 network key + 固定公钥/seq/地址 → 固定字节串。
    /// 改了线格式就会打破它——那是协议不兼容变更，必须同步
    /// docs/protocol/lan-discovery.md 与 BEACON_VERSION。
    #[test]
    fn frozen_wire_vector() {
        let bytes = sample(1).encode(&key()).unwrap();
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, FROZEN_HEX);
        let back = Beacon::decode(&bytes, &key()).unwrap();
        assert_eq!(back.addresses, sample(1).addresses);
    }

    const FROZEN_HEX: &str = concat!(
        // magic HXTL | ver 1 | kind 1 | addr_count 1 | reserved 0
        "4858544c",
        "01",
        "01",
        "01",
        "00",
        // listen_port 4193 | seq 1770000000
        "1061",
        "0000000069800e80",
        // node public key（seed = [5u8; 32]）
        "6e7a1cdd29b0b78fd13af4c5598feff4ef2a97166e3ca6f2e4fbfccd80505bf1",
        // 2001:db8::1
        "20010db8000000000000000000000001",
        // MAC（截断左 16 字节）
        "6a10bd99d41b184669605075fb47d741",
    );

    proptest::proptest! {
        #[test]
        fn encode_decode_roundtrip(
            port in proptest::prelude::any::<u16>(),
            seq in proptest::prelude::any::<u64>(),
            n in 0usize..=BEACON_MAX_ADDRS,
            octets in proptest::prelude::any::<[u8; 16]>(),
        ) {
            let addresses: Vec<Ipv6Addr> = (0..n)
                .map(|i| {
                    let mut o = octets;
                    o[15] = o[15].wrapping_add(i as u8);
                    Ipv6Addr::from(o)
                })
                .collect();
            let b = Beacon { node_public_key: node(), listen_port: port, seq, addresses: addresses.clone() };
            let bytes = b.encode(&key()).unwrap();
            let back = Beacon::decode(&bytes, &key()).unwrap();
            proptest::prop_assert_eq!(back.listen_port, port);
            proptest::prop_assert_eq!(back.seq, seq);
            proptest::prop_assert_eq!(back.addresses, addresses);
        }
    }
}
