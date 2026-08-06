//! 网络密钥与 ULA /48 前缀派生（协议规范：docs/protocol/addressing.md）。

use std::fmt;
use std::net::Ipv6Addr;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

use crate::error::IdentityError;

/// 域分隔盐（协议版本锚点）。
const SALT: &[u8] = b"hextet-v1";

/// 网络密钥：32 字节共享秘密，决定网络身份与 ULA 前缀。
pub struct NetworkKey([u8; 32]);

impl Drop for NetworkKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl NetworkKey {
    /// 随机生成。
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        use rand_core::RngCore as _;
        rand_core::OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// 从 base64 解析。
    pub fn from_base64(s: &str) -> Result<Self, IdentityError> {
        let v = B64
            .decode(s.trim())
            .map_err(|_| IdentityError::InvalidEncoding)?;
        let arr: [u8; 32] = v.try_into().map_err(|_| IdentityError::InvalidEncoding)?;
        Ok(Self(arr))
    }

    /// base64 编码。
    pub fn to_base64(&self) -> String {
        B64.encode(self.0)
    }

    /// 原始字节。
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// 网络 ULA /48 前缀（`fd` + 40-bit network id）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct NetworkPrefix([u8; 6]);

impl NetworkPrefix {
    /// 前缀长度恒为 /48。
    pub const PREFIX_LEN: u8 = 48;

    /// 由网络密钥经 HKDF-SHA256 派生。
    pub fn derive(key: &NetworkKey) -> Self {
        let hk = Hkdf::<Sha256>::new(Some(SALT), key.as_bytes());
        let mut id = [0u8; 5];
        hk.expand(b"network-id", &mut id)
            .expect("5 bytes is a valid hkdf length");
        let mut p = [0u8; 6];
        p[0] = 0xfd;
        p[1..].copy_from_slice(&id);
        Self(p)
    }

    /// /48 的网络地址（后 80 位全零）。
    pub fn network(&self) -> Ipv6Addr {
        let mut o = [0u8; 16];
        o[..6].copy_from_slice(&self.0);
        Ipv6Addr::from(o)
    }

    /// 前 6 字节。
    pub fn as_bytes(&self) -> &[u8; 6] {
        &self.0
    }
}

impl fmt::Display for NetworkPrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network(), Self::PREFIX_LEN)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_is_ula_and_deterministic() {
        let key = NetworkKey::generate();
        let p1 = NetworkPrefix::derive(&key);
        let p2 = NetworkPrefix::derive(&key);
        assert_eq!(p1, p2);
        assert_eq!(p1.network().octets()[0], 0xfd);
    }

    #[test]
    fn different_keys_different_prefixes() {
        let p1 = NetworkPrefix::derive(&NetworkKey::generate());
        let p2 = NetworkPrefix::derive(&NetworkKey::generate());
        assert_ne!(p1, p2);
    }

    /// 回归钉扎向量：首次实现后运行 `cargo test -- --nocapture`
    /// 把输出冻结进本断言（防止未来无意改变派生算法）。
    #[test]
    fn frozen_derivation_vector() {
        let key = NetworkKey::from_base64("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap();
        let p = NetworkPrefix::derive(&key);
        assert_eq!(p.to_string(), "fdc1:c82b:b2f4::/48");
    }
}
