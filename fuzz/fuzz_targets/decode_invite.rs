//! Fuzz 目标：invite token（文本三段式 + base64url + ed25519），任意输入不得 panic。
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = hextet_core::invite::Invite::decode(s);
    }
});
