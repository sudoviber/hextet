//! Mainline DHT 传输层（协议规范：docs/protocol/dht-record.md、ADR-0005）。
//!
//! 把 [`crate::record`] 加密好的会合记录经 Mainline DHT（BEP5/BEP44）发布与查询。
//! `mainline` 类型**不出本模块**——调用方只见 [`DhtClient`]，这样 `mainline` 的 API
//! 一旦 break（它依赖 `ed25519-dalek 3.0.0-pre.1`，spec §13 已列风险）只需改这里。

use std::net::{Ipv4Addr, SocketAddrV6};

use mainline::{Dht, MutableItem, SigningKey};

use hextet_core::identity::NodePublicKey;

use crate::record::{open, rendezvous_seed, seal};

/// 一次 DHT 会合发布/查询的客户端。
///
/// 持有 `mainline` 的 async 节点与网络密钥派生的 `dht_key`。
pub struct DhtClient {
    dht: mainline::async_dht::AsyncDht,
    dht_key: [u8; 32],
}

impl DhtClient {
    /// 由 `dht_key` 与 bootstrap 节点列表构建客户端。
    ///
    /// `bootstrap` 为空时走 `mainline` 内置的公开 bootstrap 节点（首次冷启动）；
    /// 非空时用持久化的 `<state_dir>/dht-nodes.json`（见 [`crate::nodes`]）。
    /// `bind` 是本机出站 IPv4 地址（控制面弱依赖 IPv4，见 spec §5）。
    pub fn new(dht_key: [u8; 32], bootstrap: Vec<String>, bind: Ipv4Addr) -> Result<Self, String> {
        let mut builder = Dht::builder();
        if !bootstrap.is_empty() {
            builder.bootstrap(&bootstrap);
        }
        builder.bind_address(bind);
        let dht = builder.build().map_err(|e| e.to_string())?;
        Ok(Self {
            dht: dht.as_async(),
            dht_key,
        })
    }

    /// 本节点当前路由表里的 bootstrap 地址（持久化到 `dht-nodes.json`）。
    pub async fn bootstrap_nodes(&self) -> Vec<String> {
        self.dht.to_bootstrap().await
    }

    /// 发布某节点的会合记录。
    ///
    /// 读-改-写（mainline 推荐的防丢失更新模式）：先读最近 `seq`，`new_seq = old + 1`，
    /// `cas = Some(old)`；没有旧记录则 `seq = 1`、`cas = None`。
    pub async fn publish(
        &self,
        node: &NodePublicKey,
        endpoints: &[SocketAddrV6],
        epoch: u64,
    ) -> Result<(), String> {
        let signer = rendezvous_signer(&self.dht_key, node);
        let public = signer.verifying_key().to_bytes();
        let value = seal(
            &self.dht_key,
            &crate::record::RecordPayload {
                endpoints: endpoints.to_vec(),
                epoch,
            },
        )?;

        let (seq, cas) = match self.dht.get_mutable_most_recent(&public, None).await {
            Some(recent) => {
                // seq 来自 DHT、攻击者成员可控：直接 +1 在 seq==i64::MAX 时会 debug panic、
                // release 回绕成 i64::MIN（服务端拒收 seq 更小 → 记录永久卡死）。饱和加 + 到顶报错。
                let next = recent
                    .seq()
                    .checked_add(1)
                    .ok_or_else(|| "DHT 记录 seq 已达上限，无法发布".to_string())?;
                (next, Some(recent.seq()))
            }
            None => (1, None),
        };
        let item = MutableItem::new(signer, &value, seq, None);
        self.dht
            .put_mutable(item, cas)
            .await
            .map_err(|e| format!("DHT 发布失败: {e}"))?;
        Ok(())
    }

    /// 查询某节点的会合记录，返回其解密后的 endpoint 列表（未找到返回空）。
    pub async fn lookup(&self, node: &NodePublicKey) -> Result<Vec<SocketAddrV6>, String> {
        let signer = rendezvous_signer(&self.dht_key, node);
        let public = signer.verifying_key().to_bytes();
        match self.dht.get_mutable_most_recent(&public, None).await {
            Some(item) => {
                let payload = open(&self.dht_key, item.value())?;
                // 读取路径同样要过滤：AEAD 只保证「记录是成员写的」，不保证地址合法——
                // 恶意成员可塞 loopback/ULA/链路本地等地址。与 publish 侧同一套规则。
                Ok(payload
                    .endpoints
                    .into_iter()
                    .filter(|e| e.port() != 0 && hextet_core::addr::is_usable_endpoint_addr(e.ip()))
                    .collect())
            }
            None => Ok(Vec::new()),
        }
    }
}

/// 由 `dht_key` 与节点公钥派生会合签名密钥（32 字节种子 → `SigningKey`）。
fn rendezvous_signer(dht_key: &[u8; 32], node: &NodePublicKey) -> SigningKey {
    let seed = rendezvous_seed(dht_key, node);
    SigningKey::from_bytes(&seed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::derive_dht_key;
    use hextet_core::identity::NodeIdentity;
    use hextet_core::network::NetworkKey;

    fn dht_key() -> [u8; 32] {
        derive_dht_key(
            &NetworkKey::from_base64("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap(),
        )
    }

    fn node(seed: u8) -> NodePublicKey {
        NodeIdentity::from_seed(&[seed; 32]).public()
    }

    /// 本地的 `mainline` testnet（loopback IPv4，不打真实 DHT）验证发布/查询闭环：
    /// 两端用同一网络密钥、同一 DHT，A 发布自己的端点，B 能查回来且内容一致。
    #[tokio::test]
    async fn publish_then_lookup_on_local_testnet() {
        let testnet = mainline::Testnet::builder(3)
            .bind_address(Ipv4Addr::LOCALHOST)
            .build()
            .expect("本地 testnet 应能构建");

        let key = dht_key();
        let a = node(2);
        let a_eps: Vec<SocketAddrV6> = vec!["[2001:db8::a]:4193".parse().unwrap()];

        // 发布者：一个独立客户端（模拟节点 A）
        let publisher =
            DhtClient::new(dht_key(), testnet.bootstrap.clone(), Ipv4Addr::LOCALHOST).unwrap();
        publisher.publish(&a, &a_eps, 490_000).await.unwrap();

        // 查询者：另一个独立客户端（模拟节点 B）——同一网络密钥，从同一 testnet bootstrap
        let looker = DhtClient::new(key, testnet.bootstrap.clone(), Ipv4Addr::LOCALHOST).unwrap();
        let got = looker.lookup(&a).await.unwrap();
        assert_eq!(got, a_eps);
    }

    /// 网络密钥不同 → 会合密钥不同 → 查到的记录解不开（密钥不对），表现为查不到/解密失败。
    #[tokio::test]
    async fn wrong_network_key_cannot_read() {
        let testnet = mainline::Testnet::builder(3)
            .bind_address(Ipv4Addr::LOCALHOST)
            .build()
            .expect("本地 testnet 应能构建");

        let a = node(2);
        let a_eps: Vec<SocketAddrV6> = vec!["[2001:db8::a]:4193".parse().unwrap()];

        let publisher =
            DhtClient::new(dht_key(), testnet.bootstrap.clone(), Ipv4Addr::LOCALHOST).unwrap();
        publisher.publish(&a, &a_eps, 490_000).await.unwrap();

        // 另一把网络密钥派生出的 dht_key：会合公钥不同，连 target 都不同，查不到
        let other_key = derive_dht_key(&NetworkKey::generate());
        let looker =
            DhtClient::new(other_key, testnet.bootstrap.clone(), Ipv4Addr::LOCALHOST).unwrap();
        let got = looker.lookup(&a).await.unwrap();
        assert!(got.is_empty());
    }
}
