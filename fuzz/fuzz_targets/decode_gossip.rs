//! Fuzz 目标：gossip 条目（变长签名条目），任意字节输入不得 panic。
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = hextet_core::gossip::Entry::decode(data);
});
