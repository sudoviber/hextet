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

/// 是否 ULA（RFC 4193 `fc00::/7`）。
pub fn is_ula(addr: &Ipv6Addr) -> bool {
    (addr.segments()[0] & 0xfe00) == 0xfc00
}

/// 是否链路本地单播（RFC 4291 `fe80::/10`）。
pub fn is_link_local(addr: &Ipv6Addr) -> bool {
    (addr.segments()[0] & 0xffc0) == 0xfe80
}

/// 这个地址能不能拿来当 WireGuard endpoint。
///
/// 排除四类地址，每一类都有具体的坑：
/// - **ULA**：hextet 自己的 overlay 地址就是 ULA。把它当 endpoint 会让隧道套隧道，
///   直接形成回环。LAN 上别的设备的 ULA 同理不可路由到公网。
/// - **链路本地**：需要 scope id 才有意义，而 scope id 是**本机**的接口编号，
///   跨节点传过去没有任何意义。
/// - **loopback / unspecified**：不是对端能到达的地址。
/// - **组播**：endpoint 必须是单播。
///
/// 注意 `2001:db8::/32`（文档前缀）刻意**不排除**——netns E2E 与文档示例全用它。
pub fn is_usable_endpoint_addr(addr: &Ipv6Addr) -> bool {
    !is_ula(addr)
        && !is_link_local(addr)
        && !addr.is_loopback()
        && !addr.is_multicast()
        && !addr.is_unspecified()
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
    fn ula_and_link_local_boundaries() {
        // ULA = fc00::/7 → 首段高 7 位为 1111110
        assert!(is_ula(&"fc00::1".parse().unwrap()));
        assert!(is_ula(&"fd00::1".parse().unwrap()));
        assert!(is_ula(&"fdff:ffff::1".parse().unwrap()));
        assert!(!is_ula(&"fe00::1".parse().unwrap()));
        assert!(!is_ula(&"fbff::1".parse().unwrap()));
        assert!(!is_ula(&"2001:db8::1".parse().unwrap()));

        // link-local = fe80::/10 → fe80..febf
        assert!(is_link_local(&"fe80::1".parse().unwrap()));
        assert!(is_link_local(&"febf:ffff::1".parse().unwrap()));
        assert!(!is_link_local(&"fec0::1".parse().unwrap()));
        assert!(!is_link_local(&"fe7f::1".parse().unwrap()));
    }

    #[test]
    fn usable_endpoint_addresses() {
        // 可用：全局单播，含文档前缀（E2E 与文档示例都用它）
        for good in ["2001:db8::1", "2606:4700::1111", "fec0::1"] {
            assert!(
                is_usable_endpoint_addr(&good.parse().unwrap()),
                "{good} 应可用作 endpoint"
            );
        }
        // 不可用
        for bad in ["fd00::1", "fc00::1", "fe80::1", "::1", "::", "ff02::1"] {
            assert!(
                !is_usable_endpoint_addr(&bad.parse().unwrap()),
                "{bad} 不该被当作 endpoint"
            );
        }
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
