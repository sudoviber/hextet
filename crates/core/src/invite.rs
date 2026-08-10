//! invite token（协议规范：docs/protocol/invite.md）。
//!
//! 一个 token 把「网络名 + network key + 引导节点 + 签发者 + 有效期」打成一行可粘贴的
//! 字符串，让新节点一条命令就能拿到入网所需的全部参数。
//!
//! **诚实边界**：`decode` 的验签只证明「token 自签发后未被篡改」，**不**证明签发者
//! 可信——入网时还没有任何信任锚点，信任来自"你从谁手里拿到这个 token"。等到 M3-D
//! 的 gossip 准入落地，引导节点会用已知的 admin 公钥验它，那时签名才承担授权语义。
//! 同理，「一次性」目前只体现为 payload 里的 `id` 字段（供未来去重），没有任何强制。

use std::net::{SocketAddr, SocketAddrV6};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use serde::{Deserialize, Serialize};

use crate::error::InviteError;
use crate::identity::{NodeIdentity, NodePublicKey};
use crate::network::NetworkKey;

/// token 的明文前缀（第一段），兼作版本标识。
pub const INVITE_PREFIX: &str = "hxi1";
/// 载荷里的协议版本号。
pub const INVITE_VERSION: u32 = 1;
/// 一个 token 里最多允许的引导节点数。
///
/// 上限的作用是让畸形/恶意 token 的解析代价有界；实际用一两个引导节点就够了。
pub const MAX_BOOTSTRAP: usize = 8;
/// `id` 字段的字节数。
const ID_LEN: usize = 16;
/// ed25519 签名字节数。
const SIG_LEN: usize = 64;

/// token 里的一个引导节点：新节点会把它原样写成自己配置里的一个 `[[peers]]`。
#[derive(Debug, Clone)]
pub struct BootstrapPeer {
    /// peer 名（纯本地元数据，新节点可随意改）。
    pub name: String,
    /// peer 的 ed25519 公钥。
    pub public_key: NodePublicKey,
    /// peer 的 IPv6 endpoint（可为空——留给会合层去发现）。
    pub endpoints: Vec<SocketAddrV6>,
}

/// 一张邀请。
pub struct Invite {
    /// 一次性标识（16 字节随机值），供 M3-D 的准入去重。
    pub id: [u8; ID_LEN],
    /// 网络名。
    pub network_name: String,
    /// 网络共享密钥——**等同于网络准入凭证**，必须走安全信道传递。
    pub network_key: NetworkKey,
    /// 签发者公钥。
    pub issuer: NodePublicKey,
    /// 签发时刻（Unix 秒）。
    pub issued_unix: u64,
    /// 过期时刻（Unix 秒）。
    pub expires_unix: u64,
    /// 网络约定的 WireGuard 监听端口，写进新节点配置。
    pub listen_port: u16,
    /// 引导节点。
    pub bootstrap: Vec<BootstrapPeer>,
}

// 手写 Debug：`network_key` 是秘密（`NetworkKey` 刻意没有 Debug），
// 打码输出避免日志/报错路径泄露网络密钥。
impl std::fmt::Debug for Invite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Invite")
            .field("id", &self.id_string())
            .field("network_name", &self.network_name)
            .field("network_key", &"<redacted>")
            .field("issuer", &self.issuer.to_base64())
            .field("issued_unix", &self.issued_unix)
            .field("expires_unix", &self.expires_unix)
            .field("listen_port", &self.listen_port)
            .field("bootstrap", &self.bootstrap)
            .finish()
    }
}

#[derive(Serialize, Deserialize)]
struct RawInvite {
    v: u32,
    id: String,
    network_name: String,
    network_key: String,
    issuer: String,
    issued_unix: u64,
    expires_unix: u64,
    listen_port: u16,
    bootstrap: Vec<RawBootstrap>,
}

#[derive(Serialize, Deserialize)]
struct RawBootstrap {
    name: String,
    public_key: String,
    #[serde(default)]
    endpoints: Vec<String>,
}

impl Invite {
    /// 新建一张邀请（随机生成 `id`）。
    pub fn new(
        network_name: String,
        network_key: NetworkKey,
        issuer: NodePublicKey,
        issued_unix: u64,
        ttl_secs: u64,
        listen_port: u16,
        bootstrap: Vec<BootstrapPeer>,
    ) -> Self {
        let mut id = [0u8; ID_LEN];
        use rand_core::RngCore as _;
        rand_core::OsRng.fill_bytes(&mut id);
        Self {
            id,
            network_name,
            network_key,
            issuer,
            issued_unix,
            expires_unix: issued_unix.saturating_add(ttl_secs),
            listen_port,
            bootstrap,
        }
    }

    /// `id` 的 base64url 无填充表示（日志与未来去重用的键）。
    pub fn id_string(&self) -> String {
        B64URL.encode(self.id)
    }

    /// 用签发者身份签名并编码成 token 字符串。
    ///
    /// 签的是**载荷的 base64 文本本身**（不是解码后的 JSON）：验签方验的就是它在线上
    /// 看到的那串字节，于是完全不存在 JSON 规范化（键序、空白、数字表示）的问题。
    pub fn encode(&self, issuer: &NodeIdentity) -> Result<String, InviteError> {
        if issuer.public() != self.issuer {
            return Err(InviteError::IssuerMismatch);
        }
        check_bootstrap_len(self.bootstrap.len())?;

        let raw = RawInvite {
            v: INVITE_VERSION,
            id: self.id_string(),
            network_name: self.network_name.clone(),
            network_key: self.network_key.to_base64(),
            issuer: self.issuer.to_base64(),
            issued_unix: self.issued_unix,
            expires_unix: self.expires_unix,
            listen_port: self.listen_port,
            bootstrap: self
                .bootstrap
                .iter()
                .map(|b| RawBootstrap {
                    name: b.name.clone(),
                    public_key: b.public_key.to_base64(),
                    endpoints: b.endpoints.iter().map(|e| e.to_string()).collect(),
                })
                .collect(),
        };
        let json = serde_json::to_vec(&raw).map_err(|e| InviteError::BadJson(e.to_string()))?;
        let payload = B64URL.encode(&json);
        let sig = issuer.sign(payload.as_bytes());
        Ok(format!(
            "{INVITE_PREFIX}.{payload}.{}",
            B64URL.encode(sig.as_slice())
        ))
    }

    /// 解析 token 并验签。
    ///
    /// 检查顺序刻意如此：先做纯语法与长度检查（廉价），再验签，**最后**才解析
    /// 攻击者可控的地址字段——签名之后的解析工作只对已认证的载荷做。
    pub fn decode(token: &str) -> Result<Self, InviteError> {
        let mut parts = token.split('.');
        let (Some(prefix), Some(payload), Some(sig_b64), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(InviteError::Malformed);
        };
        if prefix != INVITE_PREFIX {
            return Err(InviteError::BadPrefix);
        }
        let json = B64URL.decode(payload).map_err(|_| InviteError::Malformed)?;
        let sig: [u8; SIG_LEN] = B64URL
            .decode(sig_b64)
            .map_err(|_| InviteError::Malformed)?
            .try_into()
            .map_err(|_| InviteError::Malformed)?;

        let raw: RawInvite =
            serde_json::from_slice(&json).map_err(|e| InviteError::BadJson(e.to_string()))?;
        if raw.v != INVITE_VERSION {
            return Err(InviteError::BadVersion(raw.v));
        }
        let issuer = NodePublicKey::from_base64(&raw.issuer).map_err(InviteError::BadKey)?;
        if !issuer.verify(payload.as_bytes(), &sig) {
            return Err(InviteError::BadSignature);
        }

        check_bootstrap_len(raw.bootstrap.len())?;
        let id: [u8; ID_LEN] = B64URL
            .decode(&raw.id)
            .map_err(|_| InviteError::Malformed)?
            .try_into()
            .map_err(|_| InviteError::Malformed)?;
        let network_key = NetworkKey::from_base64(&raw.network_key).map_err(InviteError::BadKey)?;

        let mut bootstrap = Vec::with_capacity(raw.bootstrap.len());
        for rb in &raw.bootstrap {
            let public_key =
                NodePublicKey::from_base64(&rb.public_key).map_err(InviteError::BadKey)?;
            let mut endpoints = Vec::with_capacity(rb.endpoints.len());
            for e in &rb.endpoints {
                match e.parse::<SocketAddr>() {
                    Ok(SocketAddr::V6(v6)) => endpoints.push(v6),
                    Ok(SocketAddr::V4(_)) => return Err(InviteError::Ipv4Endpoint(e.clone())),
                    Err(_) => return Err(InviteError::BadEndpoint(e.clone())),
                }
            }
            bootstrap.push(BootstrapPeer {
                name: rb.name.clone(),
                public_key,
                endpoints,
            });
        }

        Ok(Self {
            id,
            network_name: raw.network_name,
            network_key,
            issuer,
            issued_unix: raw.issued_unix,
            expires_unix: raw.expires_unix,
            listen_port: raw.listen_port,
            bootstrap,
        })
    }

    /// 过期检查（与 `decode` 分开，让调用方自己决定要不要放宽）。
    ///
    /// `now == expires_unix` 不算过期。
    pub fn check_not_expired(&self, now_unix: u64) -> Result<(), InviteError> {
        if now_unix > self.expires_unix {
            return Err(InviteError::Expired {
                expires_unix: self.expires_unix,
                now_unix,
            });
        }
        Ok(())
    }
}

fn check_bootstrap_len(len: usize) -> Result<(), InviteError> {
    match len {
        0 => Err(InviteError::NoBootstrap),
        n if n > MAX_BOOTSTRAP => Err(InviteError::TooManyBootstrap(n)),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::NodeIdentity;
    use crate::network::NetworkKey;
    use std::net::SocketAddrV6;

    fn ep(s: &str) -> SocketAddrV6 {
        s.parse().unwrap()
    }

    fn issuer() -> NodeIdentity {
        NodeIdentity::from_seed(&[1u8; 32])
    }

    fn zero_key() -> NetworkKey {
        NetworkKey::from_base64("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap()
    }

    fn sample(id: &NodeIdentity) -> Invite {
        Invite {
            id: [0x11; 16],
            network_name: "home".into(),
            network_key: zero_key(),
            issuer: id.public(),
            issued_unix: 1_770_000_000,
            expires_unix: 1_770_086_400,
            listen_port: 4193,
            bootstrap: vec![
                BootstrapPeer {
                    name: "router".into(),
                    public_key: NodeIdentity::from_seed(&[2u8; 32]).public(),
                    endpoints: vec![ep("[2001:db8::1]:4193"), ep("[2001:db8:2::1]:4193")],
                },
                BootstrapPeer {
                    name: "nas".into(),
                    public_key: NodeIdentity::from_seed(&[3u8; 32]).public(),
                    endpoints: vec![],
                },
            ],
        }
    }

    fn assert_same(a: &Invite, b: &Invite) {
        assert_eq!(a.id, b.id);
        assert_eq!(a.network_name, b.network_name);
        assert_eq!(a.network_key.to_base64(), b.network_key.to_base64());
        assert_eq!(a.issuer, b.issuer);
        assert_eq!(a.issued_unix, b.issued_unix);
        assert_eq!(a.expires_unix, b.expires_unix);
        assert_eq!(a.listen_port, b.listen_port);
        assert_eq!(a.bootstrap.len(), b.bootstrap.len());
        for (x, y) in a.bootstrap.iter().zip(&b.bootstrap) {
            assert_eq!(x.name, y.name);
            assert_eq!(x.public_key, y.public_key);
            assert_eq!(x.endpoints, y.endpoints);
        }
    }

    #[test]
    fn roundtrip_all_fields() {
        let id = issuer();
        let invite = sample(&id);
        let token = invite.encode(&id).unwrap();
        let back = Invite::decode(&token).unwrap();
        assert_same(&invite, &back);
    }

    #[test]
    fn token_is_single_line_and_prefixed() {
        let id = issuer();
        let token = sample(&id).encode(&id).unwrap();
        assert!(token.starts_with("hxi1."), "token = {token}");
        assert_eq!(token.matches('.').count(), 2);
        assert!(
            !token.chars().any(char::is_whitespace),
            "token 里不许有空白字符，否则粘贴时会被截断"
        );
    }

    #[test]
    fn tampering_any_byte_is_rejected() {
        let id = issuer();
        let token = sample(&id).encode(&id).unwrap();
        let bytes = token.into_bytes();
        // 每段都要覆盖到：前缀、载荷头/中/尾、签名头/中/尾
        let seg_starts: Vec<usize> = std::iter::once(0)
            .chain(
                bytes
                    .iter()
                    .enumerate()
                    .filter(|(_, b)| **b == b'.')
                    .map(|(i, _)| i + 1),
            )
            .collect();
        let mut probes: Vec<usize> = Vec::new();
        for (n, start) in seg_starts.iter().enumerate() {
            let end = seg_starts.get(n + 1).map_or(bytes.len(), |s| s - 1);
            probes.extend([*start, (start + end) / 2, end - 1]);
        }
        for i in probes {
            let mut tampered = bytes.clone();
            // 换成一个必定不同、且仍属 base64url 字母表的字符，
            // 这样错误来自签名校验而不是"不是合法 base64"
            tampered[i] = if tampered[i] == b'A' { b'B' } else { b'A' };
            let text = String::from_utf8(tampered).unwrap();
            let err = Invite::decode(&text).unwrap_err();
            assert!(
                matches!(
                    err,
                    InviteError::BadPrefix
                        | InviteError::Malformed
                        | InviteError::BadJson(_)
                        | InviteError::BadSignature
                        | InviteError::BadVersion(_)
                        | InviteError::BadKey(_)
                ),
                "byte {i} 被改动后竟然拿到 {err:?}"
            );
        }
    }

    #[test]
    fn wrong_issuer_key_cannot_sign() {
        let id = issuer();
        let other = NodeIdentity::from_seed(&[9u8; 32]);
        let err = sample(&id).encode(&other).unwrap_err();
        assert!(matches!(err, InviteError::IssuerMismatch), "got {err:?}");
    }

    #[test]
    fn foreign_signature_is_rejected() {
        let id = issuer();
        let token = sample(&id).encode(&id).unwrap();
        let payload = token.split('.').nth(1).unwrap();
        // 用另一把身份给同一段载荷签名，再拼回去
        let other = NodeIdentity::from_seed(&[9u8; 32]);
        let sig = other.sign(payload.as_bytes());
        let forged = format!(
            "{}.{}.{}",
            INVITE_PREFIX,
            payload,
            base64::Engine::encode(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                sig.as_slice()
            )
        );
        assert!(matches!(
            Invite::decode(&forged).unwrap_err(),
            InviteError::BadSignature
        ));
    }

    #[test]
    fn expiry_boundary() {
        let id = issuer();
        let invite = sample(&id);
        // 等于过期时刻不算过期，多一秒才算
        invite.check_not_expired(invite.expires_unix).unwrap();
        let err = invite
            .check_not_expired(invite.expires_unix + 1)
            .unwrap_err();
        assert!(matches!(err, InviteError::Expired { .. }), "got {err:?}");
    }

    #[test]
    fn rejects_empty_and_oversized_bootstrap() {
        let id = issuer();
        let mut invite = sample(&id);
        invite.bootstrap.clear();
        assert!(matches!(
            invite.encode(&id).unwrap_err(),
            InviteError::NoBootstrap
        ));

        let mut invite = sample(&id);
        invite.bootstrap = (0..(MAX_BOOTSTRAP as u8 + 1))
            .map(|i| BootstrapPeer {
                name: format!("n{i}"),
                public_key: NodeIdentity::from_seed(&[i + 10; 32]).public(),
                endpoints: vec![],
            })
            .collect();
        assert!(matches!(
            invite.encode(&id).unwrap_err(),
            InviteError::TooManyBootstrap(_)
        ));
    }

    /// 直接改 JSON 载荷再重签，模拟"签发者自己写了个 IPv4 endpoint"。
    fn resign_with_payload_edit(
        id: &NodeIdentity,
        edit: impl Fn(&mut serde_json::Value),
    ) -> String {
        let token = sample(id).encode(id).unwrap();
        let payload_b64 = token.split('.').nth(1).unwrap().to_owned();
        let raw = base64::Engine::decode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            &payload_b64,
        )
        .unwrap();
        let mut json: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        edit(&mut json);
        let bytes = serde_json::to_vec(&json).unwrap();
        let payload =
            base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &bytes);
        let sig = id.sign(payload.as_bytes());
        format!(
            "{}.{}.{}",
            INVITE_PREFIX,
            payload,
            base64::Engine::encode(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                sig.as_slice()
            )
        )
    }

    #[test]
    fn rejects_ipv4_endpoint() {
        let id = issuer();
        let token = resign_with_payload_edit(&id, |json| {
            json["bootstrap"][0]["endpoints"][0] = serde_json::json!("1.2.3.4:4193");
        });
        assert!(matches!(
            Invite::decode(&token).unwrap_err(),
            InviteError::Ipv4Endpoint(_)
        ));
    }

    #[test]
    fn rejects_bad_endpoint() {
        let id = issuer();
        let token = resign_with_payload_edit(&id, |json| {
            json["bootstrap"][0]["endpoints"][0] = serde_json::json!("not-an-endpoint");
        });
        assert!(matches!(
            Invite::decode(&token).unwrap_err(),
            InviteError::BadEndpoint(_)
        ));
    }

    #[test]
    fn rejects_unknown_version() {
        let id = issuer();
        let token = resign_with_payload_edit(&id, |json| {
            json["v"] = serde_json::json!(2);
        });
        assert!(matches!(
            Invite::decode(&token).unwrap_err(),
            InviteError::BadVersion(2)
        ));
    }

    #[test]
    fn unknown_json_fields_are_ignored() {
        let id = issuer();
        let token = resign_with_payload_edit(&id, |json| {
            json["future_field"] = serde_json::json!({ "whatever": 1 });
        });
        let back = Invite::decode(&token).unwrap();
        assert_eq!(back.network_name, "home");
    }

    #[test]
    fn rejects_bad_shape() {
        assert!(matches!(
            Invite::decode("nope.aaa.bbb").unwrap_err(),
            InviteError::BadPrefix
        ));
        assert!(matches!(
            Invite::decode("hxi1.aaa").unwrap_err(),
            InviteError::Malformed
        ));
        assert!(matches!(
            Invite::decode("hxi1.###.bbb").unwrap_err(),
            InviteError::Malformed
        ));
        // 签名长度不对
        assert!(matches!(
            Invite::decode("hxi1.e30.AAAA").unwrap_err(),
            InviteError::Malformed
        ));
    }

    #[test]
    fn debug_redacts_network_key() {
        let id = issuer();
        let invite = sample(&id);
        let text = format!("{invite:?}");
        assert!(text.contains("<redacted>"), "got {text}");
        assert!(
            !text.contains(&invite.network_key.to_base64()),
            "Debug 输出泄露了 network key: {text}"
        );
    }

    #[test]
    fn id_string_is_url_safe_base64() {
        let id = issuer();
        let s = sample(&id).id_string();
        assert_eq!(s.len(), 22, "16 字节 base64url 无填充 = 22 字符，got {s}");
        assert!(!s.contains('=') && !s.contains('+') && !s.contains('/'));
    }

    /// 钉扎向量：固定身份 + 全零 network key + 固定 id/时间/引导节点 → 固定 token。
    /// 改了线格式就会打破它——那是协议不兼容变更，必须同步
    /// docs/protocol/invite.md 与 INVITE_VERSION。
    #[test]
    fn frozen_token_vector() {
        let id = issuer();
        let token = sample(&id).encode(&id).unwrap();
        assert_eq!(token, FROZEN_TOKEN);
        assert_same(&sample(&id), &Invite::decode(FROZEN_TOKEN).unwrap());
    }

    const FROZEN_TOKEN: &str = concat!(
        "hxi1.eyJ2IjoxLCJpZCI6IkVSRVJFUkVSRVJFUkVSRVJFUkVSRVEiLCJuZXR3b3JrX25hbWUiOiJob21l",
        "IiwibmV0d29ya19rZXkiOiJBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB",
        "PSIsImlzc3VlciI6ImlvamozWFFKOFpYOVV0c3RQTHBkY3NwbkNiOGRsQkliODNTSUFiUVBiMXc9Iiwi",
        "aXNzdWVkX3VuaXgiOjE3NzAwMDAwMDAsImV4cGlyZXNfdW5peCI6MTc3MDA4NjQwMCwibGlzdGVuX3Bv",
        "cnQiOjQxOTMsImJvb3RzdHJhcCI6W3sibmFtZSI6InJvdXRlciIsInB1YmxpY19rZXkiOiJnVGwzRHFo",
        "OUYxOVdvMVJtdzB4K3pNdU5pcEcwN2plaVhmWVBXNC9KczVRPSIsImVuZHBvaW50cyI6WyJbMjAwMTpk",
        "Yjg6OjFdOjQxOTMiLCJbMjAwMTpkYjg6Mjo6MV06NDE5MyJdfSx7Im5hbWUiOiJuYXMiLCJwdWJsaWNf",
        "a2V5IjoiN1Vrb3hpalJ3c2JxNlFNNGtGbVZZU2xaSnpwY1kvazJOc0ZHRkt5SE45RT0iLCJlbmRwb2lu",
        "dHMiOltdfV19.68uGMDPHXlkC-RneMvOFjGBFbeKxOGsFZqK_2DEbKs2uhj0gcFc5sZXoNRD32uTRDxsS",
        "FL3seFYPf_v1IE5gBw",
    );
}
