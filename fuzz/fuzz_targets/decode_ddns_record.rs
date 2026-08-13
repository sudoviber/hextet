//! Fuzz 目标：DDNS 会合记录（TXT 前缀 + base64url + AEAD 解密），任意字节输入不得 panic。
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // DNS TXT 值在我们的线格式里是 UTF-8 字符串（hxdd1.<base64url>）；非 UTF-8 的
    // 原始字节不属于合法输入面，直接跳过（与 beacon/gossip 的"任意字节"不同，
    // 那些是二进制帧，这里是文本记录）。
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = hextet_discovery::ddns::parse_record(&[0u8; 32], s);
    }
});
