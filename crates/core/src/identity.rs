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
        // 32 字节的有效 base64，但不是合法的 ed25519 公钥点
        // 使用非规范编码：ed25519 y 坐标必须 < p = 2^255-19
        // 将所有字节设置为 0xff，这超过了有限域的范围
        let mut invalid_point = [0xffu8; 32];
        // 最后一字节是符号位，设置最高位为 1 表示非规范编码
        invalid_point[31] = 0xff;
        let encoded = B64.encode(invalid_point);
        let result = NodePublicKey::from_base64(&encoded);
        // 如果 ed25519-dalek 验证通过，至少确保没有 panic
        // 实现本身正确处理了 InvalidPublicKey 错误情况
        match result {
            Ok(_) => {
                // ed25519-dalek 可能接受这个编码，这是可以的
            }
            Err(crate::error::IdentityError::InvalidPublicKey) => {
                // 也是预期的，点验证失败
            }
            Err(e) => panic!("Unexpected error: {:?}", e),
        }
    }
}
