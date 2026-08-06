//! 节点地址派生：公钥 → site /64 与节点地址（协议规范：docs/protocol/addressing.md）。

use std::net::Ipv6Addr;

use sha2::{Digest, Sha256};

use crate::error::AddrError;
use crate::identity::NodePublicKey;
use crate::network::NetworkPrefix;

/// 一个节点在 overlay 中的地址簇。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeAddr {
    /// 16-bit site subnet id（网络内须唯一，配置加载时校验）。
    pub subnet_id: u16,
    /// 节点的 site /64 网络地址（供 M4 子网路由使用）。
    pub site: Ipv6Addr,
    /// 节点自身 /128 地址。
    pub address: Ipv6Addr,
}

/// 从网络前缀与节点公钥派生地址。
pub fn derive_node_addr(
    prefix: NetworkPrefix,
    pubkey: &NodePublicKey,
) -> Result<NodeAddr, AddrError> {
    let subnet_id = {
        let d = Sha256::new_with_prefix(b"hextet-v1 subnet-id")
            .chain_update(pubkey.as_bytes())
            .finalize();
        u16::from_be_bytes([d[0], d[1]])
    };
    let iid: [u8; 8] = {
        let d = Sha256::new_with_prefix(b"hextet-v1 iid")
            .chain_update(pubkey.as_bytes())
            .finalize();
        d[..8].try_into().expect("sha256 output >= 8 bytes")
    };
    if iid == [0u8; 8] {
        return Err(AddrError::DegenerateIid);
    }

    let mut site = [0u8; 16];
    site[..6].copy_from_slice(prefix.as_bytes());
    site[6..8].copy_from_slice(&subnet_id.to_be_bytes());

    let mut addr = site;
    addr[8..].copy_from_slice(&iid);

    Ok(NodeAddr {
        subnet_id,
        site: Ipv6Addr::from(site),
        address: Ipv6Addr::from(addr),
    })
}

/// 校验一组（节点名, 地址）无 subnet id 冲突。
pub fn check_subnet_collisions(nodes: &[(String, NodeAddr)]) -> Result<(), AddrError> {
    let mut seen: std::collections::HashMap<u16, &str> = std::collections::HashMap::new();
    for (name, addr) in nodes {
        if let Some(prev) = seen.insert(addr.subnet_id, name) {
            return Err(AddrError::SubnetCollision {
                a: prev.to_owned(),
                b: name.clone(),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::NodeIdentity;

    #[test]
    fn same_network_same_prefix_different_nodes() {
        let key = crate::network::NetworkKey::generate();
        let prefix = NetworkPrefix::derive(&key);
        let a = derive_node_addr(prefix, &NodeIdentity::generate().public()).unwrap();
        let b = derive_node_addr(prefix, &NodeIdentity::generate().public()).unwrap();
        // 同网 /48
        assert_eq!(a.address.octets()[..6], b.address.octets()[..6]);
        // 不同节点几乎必然不同 /64
        assert_ne!(a.address, b.address);
        // site 是 /64 网络地址（后 64 位全零）
        assert_eq!(a.site.octets()[8..], [0u8; 8]);
        // 节点地址落在自己的 site /64 内
        assert_eq!(a.address.octets()[..8], a.site.octets()[..8]);
    }

    #[test]
    fn deterministic_node_addr() {
        let key = crate::network::NetworkKey::generate();
        let prefix = NetworkPrefix::derive(&key);
        let pk = NodeIdentity::generate().public();
        assert_eq!(
            derive_node_addr(prefix, &pk).unwrap().address,
            derive_node_addr(prefix, &pk).unwrap().address
        );
    }

    #[test]
    fn collision_detection() {
        let key = crate::network::NetworkKey::generate();
        let prefix = NetworkPrefix::derive(&key);
        let a = derive_node_addr(prefix, &NodeIdentity::generate().public()).unwrap();
        let dup = a.clone();
        let err = check_subnet_collisions(&[("a".into(), a), ("b".into(), dup)]).unwrap_err();
        assert!(matches!(err, AddrError::SubnetCollision { .. }));
    }
}
