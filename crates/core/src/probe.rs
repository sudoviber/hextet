//! doctor 探针报文（协议规范：docs/protocol/doctor-probe.md）。
//!
//! 32 字节定长、HMAC 认证、无状态。存在的唯一目的是让**对端节点**帮本机判定
//! 入站策略：先回一个"已请求"的包证明状态防火墙路径通，再从另一个源端口发一个
//! "未经请求"的包看能不能进来。没有任何项目方服务器参与。

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::error::ProbeError;

/// 探针报文固定长度。
pub const PROBE_PACKET_LEN: usize = 32;

/// 参与 MAC 计算的前缀长度（magic..reply_port）。
const MACED_LEN: usize = 16;
/// 截断后的 MAC 长度。
const MAC_LEN: usize = 16;
/// 报文 magic。
const MAGIC: [u8; 4] = *b"HXTP";
/// 协议版本。
const VERSION: u8 = 1;

type HmacSha256 = Hmac<Sha256>;

/// 报文类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeKind {
    /// 客户端 → 对端：请求回探。
    Request,
    /// 对端 → 客户端：对 Request 的直接回复（走客户端已建立的出站 state）。
    Response,
    /// 对端 → 客户端：**未经请求**的包，从另一个源端口发向 `reply_port`。
    Unsolicited,
}

impl ProbeKind {
    fn as_u8(self) -> u8 {
        match self {
            Self::Request => 1,
            Self::Response => 2,
            Self::Unsolicited => 3,
        }
    }

    fn from_u8(v: u8) -> Result<Self, ProbeError> {
        match v {
            1 => Ok(Self::Request),
            2 => Ok(Self::Response),
            3 => Ok(Self::Unsolicited),
            other => Err(ProbeError::BadKind(other)),
        }
    }
}

/// 一个探针报文。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbePacket {
    /// 报文类型。
    pub kind: ProbeKind,
    /// 本次探测的随机 nonce，回包原样带回（用来把回包与本次探测配对）。
    pub nonce: u64,
    /// `Request` 里客户端希望收 `Unsolicited` 的 UDP 端口；其余类型为 0。
    pub reply_port: u16,
}

impl ProbePacket {
    /// 编码为线格式。
    pub fn encode(&self, probe_key: &[u8; 32]) -> [u8; PROBE_PACKET_LEN] {
        let mut out = [0u8; PROBE_PACKET_LEN];
        out[0..4].copy_from_slice(&MAGIC);
        out[4] = VERSION;
        out[5] = self.kind.as_u8();
        out[6..14].copy_from_slice(&self.nonce.to_be_bytes());
        out[14..16].copy_from_slice(&self.reply_port.to_be_bytes());
        let mut mac =
            HmacSha256::new_from_slice(probe_key).expect("HMAC accepts keys of any length");
        mac.update(&out[..MACED_LEN]);
        let tag = mac.finalize().into_bytes();
        out[MACED_LEN..MACED_LEN + MAC_LEN].copy_from_slice(&tag[..MAC_LEN]);
        out
    }

    /// 解析线格式并校验 MAC。
    ///
    /// 长于 [`PROBE_PACKET_LEN`] 的数据报只看前 32 字节（尾部填充忽略）。
    pub fn decode(bytes: &[u8], probe_key: &[u8; 32]) -> Result<Self, ProbeError> {
        if bytes.len() < PROBE_PACKET_LEN {
            return Err(ProbeError::TooShort);
        }
        if bytes[0..4] != MAGIC {
            return Err(ProbeError::BadMagic);
        }
        if bytes[4] != VERSION {
            return Err(ProbeError::BadVersion(bytes[4]));
        }
        let kind = ProbeKind::from_u8(bytes[5])?;
        let mut mac =
            HmacSha256::new_from_slice(probe_key).expect("HMAC accepts keys of any length");
        mac.update(&bytes[..MACED_LEN]);
        // verify_truncated_left 是常量时间比较，不要换成 == 手写比较
        mac.verify_truncated_left(&bytes[MACED_LEN..MACED_LEN + MAC_LEN])
            .map_err(|_| ProbeError::BadMac)?;
        let nonce = u64::from_be_bytes(bytes[6..14].try_into().expect("slice is exactly 8 bytes"));
        let reply_port =
            u16::from_be_bytes(bytes[14..16].try_into().expect("slice is exactly 2 bytes"));
        Ok(Self {
            kind,
            nonce,
            reply_port,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> [u8; 32] {
        crate::network::derive_probe_key(
            &crate::network::NetworkKey::from_base64(
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            )
            .unwrap(),
        )
    }

    #[test]
    fn frozen_probe_key_vector() {
        // 全零 network key 的探针密钥。改了派生算法就会打破这个断言——
        // 那是协议不兼容变更，必须同步 docs/protocol/doctor-probe.md 与版本号。
        assert_eq!(
            key(),
            [
                0x8c, 0xe2, 0x7a, 0xff, 0xbf, 0x33, 0x6f, 0x05, 0x6d, 0x5c, 0xa3, 0x0a, 0xd6, 0x49,
                0xaa, 0x93, 0x9a, 0x1e, 0x2c, 0x35, 0xb6, 0xc2, 0x8e, 0x1d, 0xeb, 0xa6, 0xd3, 0xb1,
                0xc3, 0xb2, 0x2e, 0x47,
            ]
        );
    }

    #[test]
    fn frozen_wire_vector() {
        let pkt = ProbePacket {
            kind: ProbeKind::Request,
            nonce: 0x0102_0304_0506_0708,
            reply_port: 0x1234,
        };
        let bytes = pkt.encode(&key());
        let expected = "4858545001010102030405060708123403ac6ed7c17f6249a9daa95c76e51d18";
        let got: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(got, expected);
        assert_eq!(ProbePacket::decode(&bytes, &key()).unwrap(), pkt);
    }

    #[test]
    fn roundtrip_all_kinds() {
        for kind in [
            ProbeKind::Request,
            ProbeKind::Response,
            ProbeKind::Unsolicited,
        ] {
            let pkt = ProbePacket {
                kind,
                nonce: 0xdead_beef_cafe_0001,
                reply_port: 40000,
            };
            let bytes = pkt.encode(&key());
            assert_eq!(bytes.len(), PROBE_PACKET_LEN);
            assert_eq!(ProbePacket::decode(&bytes, &key()).unwrap(), pkt);
        }
    }

    #[test]
    fn wrong_key_is_rejected() {
        let pkt = ProbePacket {
            kind: ProbeKind::Request,
            nonce: 7,
            reply_port: 1,
        };
        let bytes = pkt.encode(&key());
        let err = ProbePacket::decode(&bytes, &[9u8; 32]).unwrap_err();
        assert!(matches!(err, ProbeError::BadMac), "got {err:?}");
    }

    #[test]
    fn any_flipped_bit_in_the_maced_region_is_rejected() {
        let pkt = ProbePacket {
            kind: ProbeKind::Response,
            nonce: 0x1122_3344_5566_7788,
            reply_port: 0,
        };
        let bytes = pkt.encode(&key());
        for i in 0..PROBE_PACKET_LEN {
            let mut tampered = bytes;
            tampered[i] ^= 0x01;
            let err = ProbePacket::decode(&tampered, &key()).unwrap_err();
            // 前 6 字节被改会先撞上 magic/version/kind 检查，其余一律 BadMac
            assert!(
                matches!(
                    err,
                    ProbeError::BadMac
                        | ProbeError::BadMagic
                        | ProbeError::BadVersion(_)
                        | ProbeError::BadKind(_)
                ),
                "byte {i} tampering slipped through: {err:?}"
            );
        }
    }

    #[test]
    fn short_packet_is_rejected() {
        assert!(matches!(
            ProbePacket::decode(&[0u8; 31], &key()).unwrap_err(),
            ProbeError::TooShort
        ));
        assert!(matches!(
            ProbePacket::decode(&[], &key()).unwrap_err(),
            ProbeError::TooShort
        ));
    }

    #[test]
    fn bad_magic_version_and_kind_are_rejected() {
        let good = ProbePacket {
            kind: ProbeKind::Request,
            nonce: 1,
            reply_port: 2,
        }
        .encode(&key());

        let mut bad_magic = good;
        bad_magic[0] = b'X';
        assert!(matches!(
            ProbePacket::decode(&bad_magic, &key()).unwrap_err(),
            ProbeError::BadMagic
        ));

        let mut bad_version = good;
        bad_version[4] = 2;
        assert!(matches!(
            ProbePacket::decode(&bad_version, &key()).unwrap_err(),
            ProbeError::BadVersion(2)
        ));

        let mut bad_kind = good;
        bad_kind[5] = 9;
        assert!(matches!(
            ProbePacket::decode(&bad_kind, &key()).unwrap_err(),
            ProbeError::BadKind(9)
        ));
    }

    #[test]
    fn longer_datagram_is_accepted_by_ignoring_the_tail() {
        // UDP 收到的包可能带填充；只要前 32 字节合法就接受
        let pkt = ProbePacket {
            kind: ProbeKind::Unsolicited,
            nonce: 5,
            reply_port: 0,
        };
        let mut buf = pkt.encode(&key()).to_vec();
        buf.extend_from_slice(b"trailing junk");
        assert_eq!(ProbePacket::decode(&buf, &key()).unwrap(), pkt);
    }

    proptest::proptest! {
        #[test]
        fn encode_decode_roundtrip(
            kind_idx in 0usize..3,
            nonce in proptest::prelude::any::<u64>(),
            reply_port in proptest::prelude::any::<u16>(),
        ) {
            let kind = [ProbeKind::Request, ProbeKind::Response, ProbeKind::Unsolicited][kind_idx];
            let pkt = ProbePacket { kind, nonce, reply_port };
            let bytes = pkt.encode(&key());
            proptest::prop_assert_eq!(ProbePacket::decode(&bytes, &key()).unwrap(), pkt);
        }
    }
}
