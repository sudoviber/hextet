//! Fuzz 目标：中继控制帧（96 字节定长 + HMAC），任意字节输入不得 panic。
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = hextet_core::relay::RelayFrame::decode(data, &[0u8; 32]);
    // 判据函数也要压：它是中继端口解复用的第一道关
    let _ = hextet_core::relay::is_relay_frame(data);
});
