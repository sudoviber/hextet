//! 自托管 DDNS 会合（会合兜底链第 ⑥ 层，协议规范：docs/protocol/ddns.md、
//! ADR-0010）。
//!
//! 把 DHT 会合记录的密文（[`crate::record`] 的 `RecordPayload` + `seal`/`open`）
//! 复用为 DDNS TXT 记录的载荷：密钥用途串换成 `"ddns-record"`，密文再做一次
//! base64url 文本包装加 `hxdd1.` 版本前缀，发布到用户自己的域名上。
//!
//! - 本模块是**纯逻辑**（无 I/O），密钥派生/渲染/解析/择优全部可单测；
//! - 真正的 DNS TXT 查询在 [`resolver`]，HTTP 更新在 [`updater`]。

use std::net::SocketAddrV6;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hkdf::Hkdf;
use sha2::Sha256;

use hextet_core::network::NetworkKey;

use crate::record::{RecordPayload, open, seal};

pub mod resolver;
pub mod updater;

/// 域分隔盐——**必须与 `hextet-core` / `crate::record` 的 HKDF 盐一致**（协议版本
/// 锚点 `hextet-v1`）。与 DHT 记录同源同盐，只是用途串不同（`"ddns-record"`）。
const SALT: &[u8] = b"hextet-v1";

/// DDNS TXT 值的版本前缀（`hx` = hextet，`dd` = ddns，`1` = 版本 1）。
pub const PREFIX: &str = "hxdd1.";

/// 由网络密钥派生 DDNS 记录密钥（`"ddns-record"` 用途串，32 字节）。
///
/// 与 `derive_dht_key` / `derive_probe_key` / `derive_lan_key` / `derive_relay_key`
/// 同一条纪律：一把密钥只干一件事。这把密钥只用于 DDNS 会合记录的 AEAD 加密，
/// 不与 DHT、数据面、中继、LAN 公告共用。
pub fn derive_ddns_key(network_key: &NetworkKey) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(SALT), network_key.as_bytes());
    let mut out = [0u8; 32];
    hk.expand(b"ddns-record", &mut out)
        .expect("32 bytes is a valid hkdf length");
    out
}

/// 把载荷加密并文本化，得到可直接当 DNS TXT 值用的字符串：
/// `hxdd1.<base64url_nopad(nonce(12) || AEAD_ChaCha20Poly1305(json(RecordPayload)))>`。
///
/// 复用 [`crate::record::seal`]：nonce 随机前置、AEAD 加密，记录自包含。base64url
/// 无填充编码让值能安全地塞进 DNS TXT 记录（单条上限 255 字节）。
pub fn render_record(ddns_key: &[u8; 32], payload: &RecordPayload) -> Result<String, String> {
    let sealed = seal(ddns_key, payload)?;
    Ok(format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(sealed)))
}

/// 反向解析 [`render_record`] 出来的 TXT 字符串。
///
/// 要求 `hxdd1.` 前缀；前缀缺失、base64url 非法、或 AEAD 解密失败（密钥不对或
/// 被篡改）都返回 `Err`。
pub fn parse_record(ddns_key: &[u8; 32], text: &str) -> Result<RecordPayload, String> {
    let rest = text
        .strip_prefix(PREFIX)
        .ok_or("not a hextet DDNS record (missing hxdd1. prefix)")?;
    let bytes = URL_SAFE_NO_PAD
        .decode(rest)
        .map_err(|e| format!("invalid base64url in DDNS record: {e}"))?;
    open(ddns_key, &bytes)
}

/// 从一批 TXT 字符串里择优取 endpoint：忽略解析失败的、取 **epoch 最大**的那条
/// 记录的 endpoints（并列取先出现的）。这是解析器的核心逻辑，纯函数、可单测。
pub fn select_endpoints(txt_strings: &[String], ddns_key: &[u8; 32]) -> Vec<SocketAddrV6> {
    let mut best: Option<(u64, Vec<SocketAddrV6>)> = None;
    for s in txt_strings {
        if let Ok(payload) = parse_record(ddns_key, s) {
            if best
                .as_ref()
                .is_none_or(|(epoch, _)| payload.epoch > *epoch)
            {
                best = Some((payload.epoch, payload.endpoints));
            }
        }
    }
    best.map(|(_, endpoints)| endpoints).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::{RecordPayload, derive_dht_key};
    use hextet_core::network::NetworkKey;

    fn net_key() -> NetworkKey {
        NetworkKey::from_base64("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap()
    }

    fn payload() -> RecordPayload {
        RecordPayload {
            endpoints: vec!["[2001:db8::1]:4193".parse().unwrap()],
            epoch: 490_000,
        }
    }

    #[test]
    fn ddns_key_is_deterministic_and_distinct_from_dht() {
        let nk = net_key();
        let k1 = derive_ddns_key(&nk);
        let k2 = derive_ddns_key(&nk);
        assert_eq!(k1, k2);
        // 与 DHT 用途串不同（一把密钥只干一件事）
        assert_ne!(k1, derive_dht_key(&nk));
        // 不同网络密钥不同
        assert_ne!(
            derive_ddns_key(&nk),
            derive_ddns_key(&NetworkKey::generate())
        );
    }

    #[test]
    fn render_parse_roundtrip() {
        let k = derive_ddns_key(&net_key());
        let text = render_record(&k, &payload()).unwrap();
        assert!(text.starts_with(PREFIX), "got {text}");
        // base64url 无填充 + 无非法字符
        assert!(!text.ends_with('='), "got {text}");
        assert_eq!(parse_record(&k, &text).unwrap(), payload());
    }

    #[test]
    fn render_is_randomized() {
        let k = derive_ddns_key(&net_key());
        let a = render_record(&k, &payload()).unwrap();
        let b = render_record(&k, &payload()).unwrap();
        assert_ne!(a, b, "nonce 随机：两次渲染的字节串不同");
    }

    #[test]
    fn wrong_key_cannot_parse() {
        let text = render_record(&derive_ddns_key(&net_key()), &payload()).unwrap();
        assert!(parse_record(&derive_ddns_key(&NetworkKey::generate()), &text).is_err());
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let k = derive_ddns_key(&net_key());
        let mut text = render_record(&k, &payload()).unwrap();
        // 翻转 base64 正文最后一个字符（把密文改掉）
        let last = text.len() - 1;
        let c = text.as_bytes()[last];
        text.replace_range(last.., if c == b'A' { "B" } else { "A" });
        assert!(parse_record(&k, &text).is_err());
    }

    #[test]
    fn parse_rejects_missing_prefix_and_bad_base64() {
        let k = derive_ddns_key(&net_key());
        let text = render_record(&k, &payload()).unwrap();
        let no_prefix = &text[PREFIX.len()..];
        assert!(parse_record(&k, no_prefix).is_err());
        assert!(parse_record(&k, "hxdd1.not!base64!").is_err());
    }

    #[test]
    fn select_endpoints_picks_max_epoch_and_ignores_garbage() {
        let k = derive_ddns_key(&net_key());
        let p_old = RecordPayload {
            endpoints: vec!["[2001:db8::1]:4193".parse().unwrap()],
            epoch: 1,
        };
        let p_new = RecordPayload {
            endpoints: vec!["[2001:db8::2]:4193".parse().unwrap()],
            epoch: 2,
        };
        let old_txt = render_record(&k, &p_old).unwrap();
        let new_txt = render_record(&k, &p_new).unwrap();
        let strings = vec![
            "garbage".to_string(),
            old_txt,
            new_txt,
            "hxdd1.also-garbage".to_string(),
        ];
        let got = select_endpoints(&strings, &k);
        assert_eq!(got, p_new.endpoints);
    }

    #[test]
    fn select_endpoints_returns_empty_when_none_valid() {
        let k = derive_ddns_key(&net_key());
        assert!(select_endpoints(&["garbage".to_string()], &k).is_empty());
        assert!(select_endpoints(&[], &k).is_empty());
    }

    // 任意字符串输入不得 panic（spec §12 fuzz 要求在 stable 工具链上的第一道防线；
    // nightly fuzz 目标 `decode_ddns_record` 是第二道）。
    proptest::proptest! {
        #[test]
        fn arbitrary_text_never_panics(s in ".*") {
            let k = derive_ddns_key(&net_key());
            let _ = parse_record(&k, &s);
        }
    }
}
