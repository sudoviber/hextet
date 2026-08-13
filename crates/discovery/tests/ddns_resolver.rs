//! DDNS 查询侧（resolver）的进程内闭环：本地 mock（webhook HTTP + DNS TXT）→
//! 发布一条会合记录 → `DdnsResolver::with_nameserver` 查询并解密出 endpoint。
//!
//! 这是 `[node] ddns_resolver` / `DdnsResolver::with_nameserver` 的运行时验证：
//! 走真实 HTTP POST + 真实 DNS TXT 查询（都在进程内 mock 上），证明「自定义解析器 →
//! 查询 → 解密 → endpoint」整条链路可用，而不依赖公网注册商/DNS。

use std::net::{Ipv4Addr, SocketAddrV6};

use hextet_core::network::NetworkKey;
use hextet_discovery::ddns::derive_ddns_key;
use hextet_discovery::ddns::node::LocalDdnsMock;
use hextet_discovery::ddns::render_record;
use hextet_discovery::ddns::resolver::DdnsResolver;
use hextet_discovery::ddns::updater::DdnsUpdater;
use hextet_discovery::record::RecordPayload;

fn ddns_key() -> [u8; 32] {
    derive_ddns_key(
        &NetworkKey::from_base64("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap(),
    )
}

/// 起一个用临时端口（port 0）的本地 DDNS mock，避免并行测试撞固定端口。
fn spawn_mock() -> LocalDdnsMock {
    LocalDdnsMock::spawn(Ipv4Addr::LOCALHOST, 0, 0).unwrap()
}

#[tokio::test]
async fn resolve_via_local_mock_roundtrips_endpoint() {
    let mock = spawn_mock();

    let key = ddns_key();
    let ep: SocketAddrV6 = "[2001:db8::9]:4193".parse().unwrap();
    let value = render_record(
        &key,
        &RecordPayload {
            endpoints: vec![ep],
            epoch: 42,
        },
    )
    .unwrap();

    // 发布：webhook POST 到本地 mock（与 daemon 的发布侧走同一条 updater 代码路径）。
    let updater =
        DdnsUpdater::webhook(format!("http://{}/update", mock.http_addr()), None).unwrap();
    updater.set_txt("home.example.com", &value).await.unwrap();

    // 查询：resolver 覆盖系统 DNS、指向 mock 的 DNS 端口。
    let resolver = DdnsResolver::with_nameserver(mock.dns_addr()).unwrap();
    let got = resolver
        .lookup_peer("home.example.com", &key)
        .await
        .unwrap();

    assert_eq!(got, vec![ep], "经本地 mock 查询应解密回原 endpoint");
}

#[tokio::test]
async fn unknown_fqdn_returns_empty_not_error() {
    let mock = spawn_mock();

    let key = ddns_key();
    let resolver = DdnsResolver::with_nameserver(mock.dns_addr()).unwrap();
    // 没发布过的 FQDN：mock 回 NOERROR 空应答 → 空，不是 Err
    let got = resolver.lookup_peer("nope.example.com", &key).await;
    match got {
        Ok(eps) => assert!(eps.is_empty(), "未发布的 FQDN 应返回空, got {eps:?}"),
        Err(e) => panic!("未发布的 FQDN 不应是错误: {e}"),
    }
}
