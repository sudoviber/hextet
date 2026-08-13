//! Fuzz 目标：doctor 探针报文（定长 + HMAC），任意字节输入不得 panic。
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = hextet_core::probe::ProbePacket::decode(data, &[0u8; 32]);
});
