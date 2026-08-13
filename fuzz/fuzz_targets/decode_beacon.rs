//! Fuzz 目标：所有「从网络解析」的格式，任意字节输入不得 panic。
//!
//! 与 `hextet-core` / `hextet-engine` 里 stable 工具链上的 proptest 同目标，但
//! cargo-fuzz 用覆盖引导（libFuzzer）能探到 proptest 探不到的深路径。密钥固定为
//! 全零/全九（MAC 校验对绝大多数输入会失败——那正是要压的路径）。
//!
//! 运行：`cargo fuzz run <target>`（需 nightly + `cargo install cargo-fuzz`）。

#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // LAN 组播公告：全零 key
    let _ = hextet_core::beacon::Beacon::decode(data, &[0u8; 32]);
});
