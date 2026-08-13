//! Fuzz 目标：DHT 会合记录（AEAD 解密），任意字节输入不得 panic。
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = hextet_discovery::record::open(&[0u8; 32], data);
});
