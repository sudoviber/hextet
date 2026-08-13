//! 中继控制帧（协议规范：docs/protocol/relay.md）。
//!
//! 中继（设计 spec §3 D5）是**逃生舱**：双端入站全阻（典型：双 CMCC 蜂窝）时，
//! 经用户自己的常电节点单跳转发加密的 WireGuard 包。中继只在 UDP 层透传，
//! 不解密、不终结会话——端到端加密不变，中继看不到流量内容。
//!
//! 本模块只有**控制帧**：注册一对会话、拿到中继为这对会话分配的端口、注销。
//! 数据平面完全没有封装：中继端口上收到的数据报**不以 `HXTR` 开头就是要转发的
//! WireGuard 包**，原样透传。这条判据成立是因为 WireGuard 报文首 4 字节是小端 u32
//! 的消息类型 1..=4（`01 00 00 00`..`04 00 00 00`），与 ASCII `HXTR` 不可能相同
//! （见 `tests::wireguard_headers_are_never_mistaken_for_relay_frames`）。
//!
//! **为什么每对会话要独占一个端口**：内核 WireGuard 自己持有 UDP socket，发出的是
//! 裸 WG 报文，中继无法要求它加上"这包发给谁"的外层封装。于是中继只能按"包从哪来"
//! 解复用；而一个节点的多条中继流共用同一个 WG socket、源地址完全相同。所以中继为
//! **每一对会话**分配一个独立端口，在该端口上按源地址二选一即可无歧义转发。

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::error::RelayError;
use crate::identity::NodePublicKey;

/// 帧 magic。
pub const RELAY_MAGIC: [u8; 4] = *b"HXTR";
/// 协议版本。
pub const RELAY_VERSION: u8 = 1;
/// 控制帧固定长度。
pub const RELAY_FRAME_LEN: usize = 96;

/// 参与 MAC 计算的前缀长度。
const MACED_LEN: usize = 80;
/// 截断后的 MAC 长度。
const MAC_LEN: usize = 16;

type HmacSha256 = Hmac<Sha256>;

/// 无序会话键：(A,B) 与 (B,A) 得到同一个值。
pub type SessionKey = [[u8; 32]; 2];

/// 控制帧类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayKind {
    /// 客户端 → 中继：注册（或续期）一对会话。
    Register,
    /// 中继 → 客户端：确认，并回带为这对会话分配的 UDP 端口。
    RegisterAck,
    /// 客户端 → 中继：主动注销（直连升级成功后调用）。
    Unregister,
}

impl RelayKind {
    fn as_u8(self) -> u8 {
        match self {
            Self::Register => 1,
            Self::RegisterAck => 2,
            Self::Unregister => 3,
        }
    }

    fn from_u8(v: u8) -> Result<Self, RelayError> {
        match v {
            1 => Ok(Self::Register),
            2 => Ok(Self::RegisterAck),
            3 => Ok(Self::Unregister),
            other => Err(RelayError::BadKind(other)),
        }
    }
}

/// 一个中继控制帧。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayFrame {
    /// 帧类型。
    pub kind: RelayKind,
    /// 端口，含义随 `kind` 变：
    ///
    /// - `Register` / `Unregister`：**发送方的 WireGuard 监听端口**。
    /// - `RegisterAck`：中继为这对会话分配的 UDP 端口。
    ///
    /// 为什么 `Register` 必须带上自己的 WG 端口：控制帧是 daemon 从**它自己的**
    /// socket 发出的（内核 WireGuard 独占 4193，用户态发不了），所以中继看到的源端口
    /// 不是 WG 的端口。中继要把 `(源地址, 帧里的 WG 端口)` 记成这一侧的数据面地址，
    /// 后续裸 WG 包的源地址才对得上、回包也才发得到正确端口。
    pub port: u16,
    /// 发送时的 Unix 秒（抗重放；窗口判定由调用方做）。
    pub seq: u64,
    /// 发送方自己的公钥。
    pub self_key: NodePublicKey,
    /// 这对会话的另一端公钥。
    pub peer_key: NodePublicKey,
}

impl RelayFrame {
    /// 编码为线格式。
    pub fn encode(&self, relay_key: &[u8; 32]) -> Vec<u8> {
        let mut out = Vec::with_capacity(RELAY_FRAME_LEN);
        out.extend_from_slice(&RELAY_MAGIC);
        out.push(RELAY_VERSION);
        out.push(self.kind.as_u8());
        out.extend_from_slice(&self.port.to_be_bytes());
        out.extend_from_slice(&self.seq.to_be_bytes());
        out.extend_from_slice(self.self_key.as_bytes());
        out.extend_from_slice(self.peer_key.as_bytes());
        debug_assert_eq!(out.len(), MACED_LEN);
        let mut mac =
            HmacSha256::new_from_slice(relay_key).expect("HMAC accepts keys of any length");
        mac.update(&out);
        let tag = mac.finalize().into_bytes();
        out.extend_from_slice(&tag[..MAC_LEN]);
        out
    }

    /// 解析线格式并校验 MAC。
    ///
    /// 长于 [`RELAY_FRAME_LEN`] 的数据报只看前 96 字节（定长帧，尾部填充忽略）。
    /// 公钥的曲线点校验放在 MAC 之后——不给未认证的报文花这个钱。
    pub fn decode(bytes: &[u8], relay_key: &[u8; 32]) -> Result<Self, RelayError> {
        if bytes.len() < RELAY_FRAME_LEN {
            return Err(RelayError::TooShort);
        }
        if bytes[0..4] != RELAY_MAGIC {
            return Err(RelayError::BadMagic);
        }
        if bytes[4] != RELAY_VERSION {
            return Err(RelayError::BadVersion(bytes[4]));
        }
        let kind = RelayKind::from_u8(bytes[5])?;
        let mut mac =
            HmacSha256::new_from_slice(relay_key).expect("HMAC accepts keys of any length");
        mac.update(&bytes[..MACED_LEN]);
        // verify_truncated_left 是常量时间比较，不要换成 == 手写比较
        mac.verify_truncated_left(&bytes[MACED_LEN..RELAY_FRAME_LEN])
            .map_err(|_| RelayError::BadMac)?;

        let port = u16::from_be_bytes(bytes[6..8].try_into().expect("2 bytes"));
        let seq = u64::from_be_bytes(bytes[8..16].try_into().expect("8 bytes"));
        let self_raw: [u8; 32] = bytes[16..48].try_into().expect("32 bytes");
        let peer_raw: [u8; 32] = bytes[48..80].try_into().expect("32 bytes");
        if self_raw == peer_raw {
            // 自己跟自己配对没有任何合法用途，但会让会话表里出现一条
            // 源地址等于目标地址的转发规则（自反射）。直接拒。
            return Err(RelayError::SelfPair);
        }
        let self_key =
            NodePublicKey::from_bytes(&self_raw).map_err(|_| RelayError::BadPublicKey)?;
        let peer_key =
            NodePublicKey::from_bytes(&peer_raw).map_err(|_| RelayError::BadPublicKey)?;

        Ok(Self {
            kind,
            port,
            seq,
            self_key,
            peer_key,
        })
    }

    /// 这对会话的无序键：两端各自算出同一个值。
    pub fn session_key(&self) -> SessionKey {
        session_key_of(self.self_key.as_bytes(), self.peer_key.as_bytes())
    }
}

/// 由两个公钥算出无序会话键（按字节序排序）。
pub fn session_key_of(a: &[u8; 32], b: &[u8; 32]) -> SessionKey {
    if a <= b { [*a, *b] } else { [*b, *a] }
}

/// 这个数据报是中继控制帧吗？
///
/// 不是的话就是要透传的 WireGuard 包。判据见模块文档。
pub fn is_relay_frame(bytes: &[u8]) -> bool {
    bytes.len() >= 4 && bytes[0..4] == RELAY_MAGIC
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::NodeIdentity;
    use crate::network::{NetworkKey, derive_relay_key};

    fn key() -> [u8; 32] {
        derive_relay_key(
            &NetworkKey::from_base64("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap(),
        )
    }

    fn a() -> crate::identity::NodePublicKey {
        NodeIdentity::from_seed(&[2u8; 32]).public()
    }

    fn b() -> crate::identity::NodePublicKey {
        NodeIdentity::from_seed(&[3u8; 32]).public()
    }

    fn sample(kind: RelayKind, port: u16) -> RelayFrame {
        RelayFrame {
            kind,
            port,
            seq: 1_770_000_000,
            self_key: a(),
            peer_key: b(),
        }
    }

    #[test]
    fn roundtrip_all_kinds() {
        for (kind, port) in [
            (RelayKind::Register, 4193),
            (RelayKind::RegisterAck, 41234),
            (RelayKind::Unregister, 4193),
        ] {
            let frame = sample(kind, port);
            let bytes = frame.encode(&key());
            assert_eq!(bytes.len(), RELAY_FRAME_LEN);
            assert_eq!(RelayFrame::decode(&bytes, &key()).unwrap(), frame);
        }
    }

    /// 中继端口上「不以 HXTR 开头就是要转发的 WireGuard 包」这条判据的地基：
    /// WireGuard 报文首 4 字节是小端 u32 的消息类型 1..=4，与 ASCII HXTR 不可能相同。
    /// 这条测试是安全断言，不是形式主义——判据错了会把 WG 包当控制帧丢掉，
    /// 或者更糟：把控制帧当数据转发出去。
    #[test]
    fn wireguard_headers_are_never_mistaken_for_relay_frames() {
        for msg_type in 1u32..=4 {
            let mut pkt = msg_type.to_le_bytes().to_vec();
            pkt.extend_from_slice(&[0u8; 60]);
            assert!(
                !is_relay_frame(&pkt),
                "WireGuard 类型 {msg_type} 的报文被误认成中继帧"
            );
        }
        // 反向：真的中继帧必须被认出来
        assert!(is_relay_frame(
            &sample(RelayKind::Register, 4193).encode(&key())
        ));
        // 太短的数据报不是中继帧（也不该 panic）
        assert!(!is_relay_frame(&[]));
        assert!(!is_relay_frame(b"HXT"));
    }

    #[test]
    fn session_key_is_order_independent() {
        let ab = sample(RelayKind::Register, 4193);
        let ba = RelayFrame {
            kind: RelayKind::Register,
            port: 4193,
            seq: 1,
            self_key: b(),
            peer_key: a(),
        };
        assert_eq!(ab.session_key(), ba.session_key());
        // 而不同的一对必须不同
        let ac = RelayFrame {
            kind: RelayKind::Register,
            port: 4193,
            seq: 1,
            self_key: a(),
            peer_key: NodeIdentity::from_seed(&[9u8; 32]).public(),
        };
        assert_ne!(ab.session_key(), ac.session_key());
    }

    #[test]
    fn self_pair_is_rejected() {
        let frame = RelayFrame {
            kind: RelayKind::Register,
            port: 4193,
            seq: 1,
            self_key: a(),
            peer_key: a(),
        };
        let bytes = frame.encode(&key());
        assert!(matches!(
            RelayFrame::decode(&bytes, &key()).unwrap_err(),
            RelayError::SelfPair
        ));
    }

    #[test]
    fn wrong_key_is_rejected() {
        let bytes = sample(RelayKind::Register, 4193).encode(&key());
        assert!(matches!(
            RelayFrame::decode(&bytes, &[9u8; 32]).unwrap_err(),
            RelayError::BadMac
        ));
    }

    #[test]
    fn any_flipped_bit_is_rejected() {
        let bytes = sample(RelayKind::RegisterAck, 4242).encode(&key());
        for i in 0..RELAY_FRAME_LEN {
            let mut tampered = bytes.clone();
            tampered[i] ^= 0x01;
            let err = RelayFrame::decode(&tampered, &key()).unwrap_err();
            assert!(
                matches!(
                    err,
                    RelayError::BadMac
                        | RelayError::BadMagic
                        | RelayError::BadVersion(_)
                        | RelayError::BadKind(_)
                ),
                "byte {i} 被改动后竟然拿到 {err:?}"
            );
        }
    }

    #[test]
    fn header_and_length_are_validated() {
        let good = sample(RelayKind::Register, 4193).encode(&key());
        assert!(matches!(
            RelayFrame::decode(&good[..95], &key()).unwrap_err(),
            RelayError::TooShort
        ));
        let mut longer = good.clone();
        longer.push(0);
        // 定长帧：多出来的尾部忽略（与探针报文一致）
        assert!(RelayFrame::decode(&longer, &key()).is_ok());

        let mut bad_magic = good.clone();
        bad_magic[0] = b'X';
        assert!(matches!(
            RelayFrame::decode(&bad_magic, &key()).unwrap_err(),
            RelayError::BadMagic
        ));
        let mut bad_version = good.clone();
        bad_version[4] = 9;
        assert!(matches!(
            RelayFrame::decode(&bad_version, &key()).unwrap_err(),
            RelayError::BadVersion(9)
        ));
        let mut bad_kind = good.clone();
        bad_kind[5] = 7;
        assert!(matches!(
            RelayFrame::decode(&bad_kind, &key()).unwrap_err(),
            RelayError::BadKind(7)
        ));
    }

    #[test]
    fn relay_key_is_its_own_key() {
        let nk = NetworkKey::generate();
        assert_eq!(derive_relay_key(&nk), derive_relay_key(&nk));
        assert_ne!(derive_relay_key(&nk), *nk.as_bytes());
        assert_ne!(derive_relay_key(&nk), crate::network::derive_lan_key(&nk));
        assert_ne!(derive_relay_key(&nk), crate::network::derive_probe_key(&nk));
    }

    /// 钉扎向量：改了线格式就会打破它——那是协议不兼容变更，必须同步
    /// docs/protocol/relay.md 与 RELAY_VERSION。
    #[test]
    fn frozen_wire_vector() {
        let bytes = sample(RelayKind::Register, 4193).encode(&key());
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, FROZEN_HEX);
    }

    const FROZEN_HEX: &str = concat!(
        // magic HXTR | ver 1 | kind 1（Register）| port 4193（发送方的 WG 监听端口）
        "4858545201011061",
        // seq 1770000000
        "0000000069800e80",
        // self_key（seed=[2u8;32]）
        "8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394",
        // peer_key（seed=[3u8;32]）
        "ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1",
        // MAC（截断左 16 字节）
        "27270216954054747fe673591633bcca",
    );

    proptest::proptest! {
        /// 任意字节输入不能让解码 panic（中继端口上的输入完全不可控）。
        #[test]
        fn decode_never_panics_on_arbitrary_bytes(
            bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..200),
        ) {
            let _ = RelayFrame::decode(&bytes, &key());
            let _ = is_relay_frame(&bytes);
        }
    }
}
