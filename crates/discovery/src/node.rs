//! 本地（离线）Mainline DHT 会合节点——netns E2E 用。
//!
//! 生产 daemon 的 DHT 会合面向真实 Mainline DHT（IPv4 公网出站），但 netns E2E
//! 要求确定性、离线、秒级收敛：于是起一个 server-mode、no_bootstrap 的单节点 DHT，
//! 让测试里的两个 daemon 都 bootstrap 到它、经它发布/查询会合记录。这与 spec
//! 「测试：本地 mainline testnet 而非真实 DHT」（M3 阶段 E）是同一纪律，只是把
//! 进程内 `mainline::Testnet` 拉出来做成一个可由脚本独立启动的进程。

use std::net::Ipv4Addr;

use mainline::Dht;

/// 一个只服务本地测试网络的单节点 Mainline DHT。
///
/// 持有 mainline 的 actor 线程；`Drop` 时整个节点随进程关闭。进程退出即整个测试
/// 网络消失——这正是 E2E 想要的：一次测试一套干净的 DHT，不与真实 DHT 或其它测试
/// 交叉污染。
pub struct LocalDhtNode {
    // 以下划线开头：只用于「保活」，不读取。actor 线程的存续绑定在这个 `Dht` 上，
    // drop 即关闭整条 UDP 监听。
    _inner: Dht,
}

impl LocalDhtNode {
    /// 起一个 server-mode、no_bootstrap 的本地 DHT 节点，监听 `bind:port`。
    ///
    /// `port` 必须非零：调用方（脚本）要用它构造 bootstrap 地址。`bind` 应是测试
    /// 拓扑里可达的具体 IPv4（如网桥地址 `172.18.0.1`），不能用 `0.0.0.0`，否则
    /// 对端无从构造 bootstrap 地址。
    pub fn spawn(bind: Ipv4Addr, port: u16) -> Result<Self, String> {
        assert!(port != 0, "本地 DHT 节点需要显式端口");
        let inner = Dht::builder()
            .server_mode()
            .no_bootstrap()
            .port(port)
            .bind_address(bind)
            .build()
            .map_err(|e| format!("本地 DHT 节点启动失败: {e}"))?;
        Ok(Self { _inner: inner })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV6};

    use hextet_core::identity::NodeIdentity;
    use hextet_core::network::NetworkKey;

    use crate::client::DhtClient;
    use crate::record::derive_dht_key;

    fn dht_key() -> [u8; 32] {
        derive_dht_key(
            &NetworkKey::from_base64("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap(),
        )
    }

    fn node(seed: u8) -> hextet_core::identity::NodePublicKey {
        NodeIdentity::from_seed(&[seed; 32]).public()
    }

    /// 单节点本地 DHT 上做发布→查询闭环。
    ///
    /// 这是 `scripts/netns-e2e-dht.sh` 依赖的核心不变量：**一个** server-mode 节点就
    /// 足以让两个客户端 bootstrap 到它、经它互相发布/查询会合记录——不需要像
    /// `mainline::Testnet` 那样起多个节点。
    #[tokio::test]
    async fn single_node_publish_then_lookup() {
        let server = LocalDhtNode::spawn(Ipv4Addr::LOCALHOST, 48_831).unwrap();
        let bootstrap = vec!["127.0.0.1:48831".to_string()];

        let key = dht_key();
        let a = node(2);
        let a_eps: Vec<SocketAddrV6> = vec!["[2001:db8::a]:4193".parse().unwrap()];

        // 发布者与查询者都只 bootstrap 到这一个节点。
        let publisher = DhtClient::new(dht_key(), bootstrap.clone(), Ipv4Addr::LOCALHOST).unwrap();
        publisher.publish(&a, &a_eps, 490_000).await.unwrap();

        let looker = DhtClient::new(key, bootstrap.clone(), Ipv4Addr::LOCALHOST).unwrap();
        let got = looker.lookup(&a).await.unwrap();
        assert_eq!(got, a_eps);

        drop(server);
    }
}
