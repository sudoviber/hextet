//! 节点身份：ed25519 签名密钥，并派生 WireGuard x25519 密钥。

use std::path::Path;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::{SigningKey, VerifyingKey};

use crate::error::IdentityError;

/// 节点身份（持有 ed25519 私钥种子）。
#[derive(Debug)]
pub struct NodeIdentity {
    signing: SigningKey,
}

impl NodeIdentity {
    /// 用系统 CSPRNG 生成新身份。
    pub fn generate() -> Self {
        let mut rng = rand_core::OsRng;
        Self {
            signing: SigningKey::generate(&mut rng),
        }
    }

    /// 从 32 字节种子恢复身份。
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            signing: SigningKey::from_bytes(seed),
        }
    }

    /// 导出 32 字节种子（谨慎处理，勿记录日志）。
    pub fn seed(&self) -> [u8; 32] {
        self.signing.to_bytes()
    }

    /// 节点公钥。
    pub fn public(&self) -> NodePublicKey {
        NodePublicKey(self.signing.verifying_key())
    }

    /// 派生 WireGuard 私钥（已 clamp 的 x25519 标量）。
    pub fn wg_secret_bytes(&self) -> [u8; 32] {
        self.signing.to_scalar_bytes()
    }

    /// 用节点身份对消息签名。
    ///
    /// ed25519 是确定性签名（RFC 8032）：同一密钥同一消息永远给出同一签名，
    /// 因此协议里的钉扎向量可以直接写死 token 字符串。
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        use ed25519_dalek::Signer as _;
        self.signing.sign(message).to_bytes()
    }

    /// 将种子以单行 base64 写入密钥文件（Unix 上 0600）。
    pub fn save(&self, path: &Path) -> Result<(), IdentityError> {
        let io = |source| IdentityError::Io {
            path: path.to_owned(),
            source,
        };
        let data = B64.encode(self.seed());
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            opts.mode(0o600);
        }
        use std::io::Write as _;
        let mut f = opts.open(path).map_err(io)?;
        writeln!(f, "{data}").map_err(io)?;
        Ok(())
    }

    /// 从密钥文件读取身份。
    pub fn load(path: &Path) -> Result<Self, IdentityError> {
        let io = |source| IdentityError::Io {
            path: path.to_owned(),
            source,
        };
        let text = std::fs::read_to_string(path).map_err(io)?;
        let bytes = B64
            .decode(text.trim())
            .map_err(|_| IdentityError::InvalidEncoding)?;
        let seed: [u8; 32] = bytes
            .try_into()
            .map_err(|_| IdentityError::InvalidEncoding)?;
        Ok(Self::from_seed(&seed))
    }
}

/// 节点公钥（ed25519）。
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct NodePublicKey(VerifyingKey);

impl NodePublicKey {
    /// 从 base64 解析。
    pub fn from_base64(s: &str) -> Result<Self, IdentityError> {
        let bytes = B64
            .decode(s.trim())
            .map_err(|_| IdentityError::InvalidEncoding)?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| IdentityError::InvalidEncoding)?;
        let vk = VerifyingKey::from_bytes(&arr).map_err(|_| IdentityError::InvalidPublicKey)?;
        Ok(Self(vk))
    }

    /// 从原始 32 字节解析（校验是合法曲线点）。
    ///
    /// 线格式里的公钥走这条路（LAN 公告、M3-D 的 gossip 条目）；base64 那条路只给
    /// 人类输入用。
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, IdentityError> {
        VerifyingKey::from_bytes(bytes)
            .map(Self)
            .map_err(|_| IdentityError::InvalidPublicKey)
    }

    /// base64 编码。
    pub fn to_base64(&self) -> String {
        B64.encode(self.0.as_bytes())
    }

    /// 原始 32 字节。
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    /// 派生 WireGuard 公钥（Montgomery 形式）。
    pub fn wg_public_bytes(&self) -> [u8; 32] {
        self.0.to_montgomery().to_bytes()
    }

    /// 校验该公钥对消息的签名。
    ///
    /// 用 `verify_strict` 而不是 `verify`：前者额外拒绝小阶公钥点，排除"同一消息
    /// 存在多个有效签名"的可延展性。签名在 hextet 里是准入凭证（invite、M3-D 的
    /// 成员/吊销条目），可延展性会让"这条记录是不是同一条"变得含糊。
    pub fn verify(&self, message: &[u8], signature: &[u8; 64]) -> bool {
        self.0
            .verify_strict(message, &ed25519_dalek::Signature::from_bytes(signature))
            .is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_seed() {
        let id = NodeIdentity::generate();
        let id2 = NodeIdentity::from_seed(&id.seed());
        assert_eq!(id.public(), id2.public());
    }

    #[test]
    fn pubkey_base64_roundtrip() {
        let pk = NodeIdentity::generate().public();
        let pk2 = NodePublicKey::from_base64(&pk.to_base64()).unwrap();
        assert_eq!(pk, pk2);
    }

    #[test]
    fn sign_verify_roundtrip() {
        let id = NodeIdentity::generate();
        let sig = id.sign(b"hextet invite payload");
        assert!(id.public().verify(b"hextet invite payload", &sig));
    }

    #[test]
    fn verify_rejects_tampered_message() {
        let id = NodeIdentity::generate();
        let sig = id.sign(b"aaaa");
        assert!(!id.public().verify(b"aaab", &sig));
    }

    #[test]
    fn verify_rejects_other_signer() {
        let a = NodeIdentity::generate();
        let b = NodeIdentity::generate();
        let sig = a.sign(b"msg");
        assert!(!b.public().verify(b"msg", &sig));
    }

    #[test]
    fn verify_rejects_tampered_signature() {
        let id = NodeIdentity::generate();
        let mut sig = id.sign(b"msg");
        sig[0] ^= 0x01;
        assert!(!id.public().verify(b"msg", &sig));
    }

    #[test]
    fn signing_is_deterministic() {
        // ed25519 是确定性签名（RFC 8032）：同一密钥同一消息必须给出同一签名。
        // 这条性质让 invite token 的钉扎向量成为可能。
        let id = NodeIdentity::from_seed(&[7u8; 32]);
        assert_eq!(id.sign(b"msg"), id.sign(b"msg"));
    }

    #[test]
    fn save_load_and_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("node.key");
        let id = NodeIdentity::generate();
        id.save(&path).unwrap();
        let loaded = NodeIdentity::load(&path).unwrap();
        assert_eq!(id.public(), loaded.public());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    proptest::proptest! {
        /// 派生的 WG 私钥经 x25519 基点乘应等于派生的 WG 公钥（两条路径一致）。
        #[test]
        fn wg_key_derivation_consistent(seed in proptest::prelude::any::<[u8; 32]>()) {
            let id = NodeIdentity::from_seed(&seed);
            let sk = x25519_dalek::StaticSecret::from(id.wg_secret_bytes());
            let pk = x25519_dalek::PublicKey::from(&sk);
            proptest::prop_assert_eq!(pk.to_bytes(), id.public().wg_public_bytes());
        }
    }

    #[test]
    fn save_fails_if_file_exists() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("node.key");
        let id = NodeIdentity::generate();

        // 第一次保存成功
        id.save(&path).unwrap();

        // 第二次保存应该失败，因为文件已存在（create_new 语义）
        let result = id.save(&path);
        assert!(result.is_err());
        match result.unwrap_err() {
            crate::error::IdentityError::Io { .. } => {
                // 预期的错误类型
            }
            _ => panic!("Expected Io error"),
        }
    }

    #[test]
    fn load_fails_on_invalid_base64() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("node.key");

        // 写入无效的 base64
        std::fs::write(&path, "!!!invalid base64!!!").unwrap();

        let result = NodeIdentity::load(&path);
        assert!(result.is_err());
        match result.unwrap_err() {
            crate::error::IdentityError::InvalidEncoding => {
                // 预期的错误类型
            }
            _ => panic!("Expected InvalidEncoding error"),
        }
    }

    #[test]
    fn load_fails_on_wrong_length() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("node.key");

        // 写入有效的 base64 但长度不对（31 字节而非 32）
        let short_seed = [0u8; 31];
        let encoded = B64.encode(short_seed);
        std::fs::write(&path, encoded).unwrap();

        let result = NodeIdentity::load(&path);
        assert!(result.is_err());
        match result.unwrap_err() {
            crate::error::IdentityError::InvalidEncoding => {
                // 预期的错误类型
            }
            _ => panic!("Expected InvalidEncoding error"),
        }
    }

    #[test]
    fn pubkey_from_base64_fails_on_invalid_base64() {
        let result = NodePublicKey::from_base64("!!!invalid base64!!!");
        assert!(result.is_err());
        match result.unwrap_err() {
            crate::error::IdentityError::InvalidEncoding => {
                // 预期的错误类型
            }
            _ => panic!("Expected InvalidEncoding error"),
        }
    }

    #[test]
    fn pubkey_from_base64_fails_on_wrong_length() {
        // 有效的 base64 但长度不对（31 字节而非 32）
        let short_bytes = [0u8; 31];
        let encoded = B64.encode(short_bytes);
        let result = NodePublicKey::from_base64(&encoded);
        assert!(result.is_err());
        match result.unwrap_err() {
            crate::error::IdentityError::InvalidEncoding => {
                // 预期的错误类型
            }
            _ => panic!("Expected InvalidEncoding error"),
        }
    }

    #[test]
    fn pubkey_from_base64_fails_on_invalid_ed25519_point() {
        // RFC 8032 ed25519 点压缩仅存储 y 坐标（32 字节）+ 符号位。
        // 并非所有 32 字节都对应有效的曲线点——当对应的 x² 无平方根时，decompress 失败。
        // 约半数 y 坐标会导致无效点。
        //
        // 方法：枚举首字节 0-255 以发现真实的无效点（deterministic fixture discovery）。
        // 数学上保证至少存在一个这样的点。

        let invalid_bytes = {
            let mut result = None;
            for n in 0u8..=255 {
                let mut candidate = [0u8; 32];
                candidate[0] = n;
                let encoded = B64.encode(candidate);
                if let Err(crate::error::IdentityError::InvalidPublicKey) =
                    NodePublicKey::from_base64(&encoded)
                {
                    result = Some(candidate);
                    break;
                }
            }
            result.expect("未找到无效的 ed25519 点（数学上不可能）")
        };

        // 用发现的无效点确认 InvalidPublicKey 错误被正确返回（不是永真的 match）
        let encoded = B64.encode(invalid_bytes);
        let result = NodePublicKey::from_base64(&encoded);
        match result {
            Err(crate::error::IdentityError::InvalidPublicKey) => {
                // 预期且必须拿到的错误
            }
            Ok(_) => panic!("发现的无效点竟然被 ed25519-dalek 接受，理论不符"),
            Err(e) => panic!("预期 InvalidPublicKey，得到 {:?}", e),
        }
    }
}
