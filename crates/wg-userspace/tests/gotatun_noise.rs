//! gotatun 噪声层冒烟（ADR-0012 落地 slice 2）：用 `gotatun::noise::Tunn` 在进程内
//! 完成一次 WireGuard 握手 + 一个 IPv6 数据包从 A 到 B 的完整往返。
//!
//! 这是 boringtun 时代 `noise::Tunn` 同款测试的 gotatun 版本（boringtun 后端已随
//! ADR-0012 迁移移除）——证明 gotatun 的
//! 点对点噪声隧道在本机 macOS 上**可测**：全程只碰内存缓冲，不碰真实 utun/TUN、
//! 不碰 UDP socket、不需要 root。真实 `Device`（数据面）需要 root，
//! 但其数据面核心正是这个 `Tunn`——同一份握手/加解密代码。

use std::sync::Arc;

use bytes::BytesMut;
use gotatun::noise::index_table::IndexTable;
use gotatun::noise::rate_limiter::RateLimiter;
use gotatun::noise::{Tunn, TunnResult};
use gotatun::packet::{Packet, WgKind};
use gotatun::x25519::{PublicKey, StaticSecret};

/// 构造一个最小的合法 IPv6 包：40 字节头 + payload（version=6、payload 长度、
/// 源/目的地址都填对）。
fn ipv6_packet(src: [u8; 16], dst: [u8; 16], payload: &[u8]) -> Vec<u8> {
    let mut p = vec![0u8; 40 + payload.len()];
    p[0] = 0x60; // version 6
    p[4..6].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    p[6] = 17; // next header = UDP
    p[7] = 64; // hop limit
    p[8..24].copy_from_slice(&src);
    p[24..40].copy_from_slice(&dst);
    p[40..].copy_from_slice(payload);
    p
}

#[test]
fn in_process_handshake_and_ipv6_roundtrip() {
    // 固定测试密钥（避免引入 rand 依赖；生产密钥由 config/身份派生，与这里无关）。
    let a_secret = StaticSecret::from([0x11u8; 32]);
    let b_secret = StaticSecret::from([0x22u8; 32]);
    let a_public = PublicKey::from(&a_secret);
    let b_public = PublicKey::from(&b_secret);

    let mut a = Tunn::new(
        a_secret,
        b_public,
        None,
        None,
        IndexTable::from_os_rng(),
        Arc::new(RateLimiter::new(&a_public, 100)),
    );
    let mut b = Tunn::new(
        b_secret,
        a_public,
        None,
        None,
        IndexTable::from_os_rng(),
        Arc::new(RateLimiter::new(&b_public, 100)),
    );

    // 1. 握手：init → resp → keepalive。
    let init = a
        .format_handshake_initiation(false)
        .expect("应产生握手 init");
    let resp = match b.handle_incoming_packet(WgKind::HandshakeInit(init)) {
        TunnResult::WriteToNetwork(WgKind::HandshakeResp(r)) => r,
        other => panic!("预期握手 response，得到 {other:?}"),
    };
    let keepalive = match a.handle_incoming_packet(WgKind::HandshakeResp(resp)) {
        TunnResult::WriteToNetwork(WgKind::Data(k)) => k,
        other => panic!("预期 keepalive，得到 {other:?}"),
    };
    match b.handle_incoming_packet(WgKind::Data(keepalive)) {
        TunnResult::WriteToTunnel(p) if p.is_empty() => {}
        other => panic!("预期 keepalive 收尾为空数据包，得到 {other:?}"),
    }

    // 2. 数据往返：A → B。
    let src = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let dst = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
    let bytes = ipv6_packet(src, dst, b"hello hextet overlay");

    let packet = Packet::from_bytes(BytesMut::from(&bytes[..]));
    let wg = a
        .handle_outgoing_packet(packet, None)
        .expect("已建立会话，应能封装数据包");
    let received = match b.handle_incoming_packet(wg) {
        TunnResult::WriteToTunnel(p) => p,
        other => panic!("预期 WriteToTunnel，得到 {other:?}"),
    };
    assert_eq!(
        received.as_ref(),
        &bytes[..],
        "A→B 数据包必须逐字节完整到达"
    );
}
