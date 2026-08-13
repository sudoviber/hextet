//! DHT 会合恢复 E2E：双端同时换前缀后经 DHT 自动恢复（计划阶段 E 验收）。
//!
//! 用 `mainline` 的**本地 Testnet**（进程内 BEP5/BEP44，loopback IPv4）而不是真实 DHT——
//! 这是计划阶段 E 明确要求的「不打真实 DHT」。两个独立的 [`DhtClient`] 各自扮演一个
//! 节点在生产里的 daemon DHT 任务：各自发布**自己的**会合记录（按自己的公钥寻址），
//! 各自查询**对端**的公钥拿到对端的地址。
//!
//! 关键场景（M3 验收第 1 条）：A、B **同时**换前缀——双方都先发布新地址，谁也不先
//! 通知谁——然后各自重新查询，必须拿到对方的**新**地址（证明更新确实传播，而非拿到
//! 陈旧地址）。这正是「双方都不知道对方现在在哪」时经 DHT 重新找到彼此的最小闭环。

use std::net::{Ipv4Addr, SocketAddrV6};

use hextet_core::identity::{NodeIdentity, NodePublicKey};
use hextet_core::network::NetworkKey;
use hextet_discovery::client::DhtClient;
use hextet_discovery::record::derive_dht_key;

fn dht_key() -> [u8; 32] {
    derive_dht_key(
        &NetworkKey::from_base64("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap(),
    )
}

fn node(seed: u8) -> NodePublicKey {
    NodeIdentity::from_seed(&[seed; 32]).public()
}

fn ep(s: &str) -> SocketAddrV6 {
    s.parse().unwrap()
}

#[tokio::test]
async fn two_nodes_change_prefix_and_recover_via_dht() {
    let testnet = mainline::Testnet::builder(3)
        .bind_address(Ipv4Addr::LOCALHOST)
        .build()
        .expect("本地 testnet 应能构建");

    let key = dht_key();
    let a = node(2);
    let b = node(3);

    // 两个节点各自的会合客户端（生产里是两个 daemon 的 DHT 任务）
    let a_client = DhtClient::new(key, testnet.bootstrap.clone(), Ipv4Addr::LOCALHOST).unwrap();
    let b_client = DhtClient::new(key, testnet.bootstrap.clone(), Ipv4Addr::LOCALHOST).unwrap();

    // 阶段 1：初始地址
    let a_old = vec![ep("[2001:db8:1::a]:4193")];
    let b_old = vec![ep("[2001:db8:1::b]:4193")];
    a_client.publish(&a, &a_old, 490_000).await.unwrap();
    b_client.publish(&b, &b_old, 490_000).await.unwrap();

    // 阶段 2：确认能互相找到（初始）
    assert_eq!(b_client.lookup(&a).await.unwrap(), a_old);
    assert_eq!(a_client.lookup(&b).await.unwrap(), b_old);

    // 阶段 3：双端**同时**换前缀——都先发新地址，谁也不先通知谁
    let a_new = vec![ep("[2001:db8:2::a]:4193")];
    let b_new = vec![ep("[2001:db8:2::b]:4193")];
    a_client.publish(&a, &a_new, 490_001).await.unwrap();
    b_client.publish(&b, &b_new, 490_001).await.unwrap();

    // 阶段 4：各自重新查询，必须拿到**新**地址（证明更新传播，不是陈旧缓存）
    assert_eq!(b_client.lookup(&a).await.unwrap(), a_new);
    assert_eq!(a_client.lookup(&b).await.unwrap(), b_new);
}
