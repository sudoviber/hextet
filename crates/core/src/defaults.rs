//! 全局默认值（见设计 spec §5）。

/// 默认 WireGuard UDP 监听端口（致敬 RFC 4193）。
pub const DEFAULT_PORT: u16 = 4193;
/// 默认隧道 MTU（中国家宽 PPPoE 1492 − IPv6 WG 开销 80，留余量）。
pub const DEFAULT_MTU: u32 = 1400;
/// 默认接口名。
pub const DEFAULT_INTERFACE: &str = "hextet0";
/// 默认 doctor 探针 UDP 端口（4193 + 1；内核 WireGuard 独占 4193，探针必须换端口）。
pub const DEFAULT_PROBE_PORT: u16 = 4194;
/// 默认状态目录：daemon 在此存放端点缓存与运行时状态文件。
pub const DEFAULT_STATE_DIR: &str = "/var/lib/hextet";
/// 默认 LAN 组播公告 UDP 端口（4193 + 2）。
pub const DEFAULT_LAN_PORT: u16 = 4195;
/// 默认中继控制端口（4193 + 3）。
///
/// 每一对中继会话另有一个内核分配的临时端口（见 docs/protocol/relay.md），
/// 这个端口只跑控制帧。
pub const DEFAULT_RELAY_PORT: u16 = 4196;
/// 默认隧道内 gossip UDP 端口（4193 + 4）。
///
/// gossip 只在 WG 隧道内跑（源地址必须在网络 /48 内，见 docs/protocol/gossip.md），
/// 所以这个端口绑定在 overlay 地址上，隧道外不可达。
pub const DEFAULT_GOSSIP_PORT: u16 = 4197;
/// 默认 WireGuard 常驻 keepalive 秒数（`[node] keepalive`，设计 spec §5「常电节点 25s」）。
///
/// 设为 `0` 表示**不发送**常驻 keepalive（`persistent_keepalive = None`）——移动端
/// 按需连接模式用它在空闲时彻底静默以省电，代价是 NAT/防火墙映射可能被回收、被动可达
/// 变差。见 `docs/adr/ADR-0015-on-demand-keepalive.md`。
pub const DEFAULT_KEEPALIVE: u16 = 25;
/// LAN 公告的链路本地组播组：`ff02::4193`。
///
/// 选链路本地 scope（`ff02::/16`）是刻意的——公告只应该在本链路上传播，
/// 组播 hop limit 默认为 1，路由器不会转发它，天然不会泄漏到 LAN 之外。
/// 组 ID 用 `0x4193` 与 WireGuard 端口呼应，且不在 IANA 已分配的低号段里。
pub const LAN_MULTICAST_GROUP: std::net::Ipv6Addr =
    std::net::Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x4193);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_stable() {
        assert_eq!(DEFAULT_PORT, 4193);
        assert_eq!(DEFAULT_MTU, 1400);
        assert_eq!(DEFAULT_INTERFACE, "hextet0");
        assert_eq!(DEFAULT_PROBE_PORT, 4194);
        assert_eq!(DEFAULT_STATE_DIR, "/var/lib/hextet");
        assert_eq!(DEFAULT_LAN_PORT, 4195);
        assert_eq!(DEFAULT_RELAY_PORT, 4196);
        assert_eq!(DEFAULT_GOSSIP_PORT, 4197);
        assert_eq!(DEFAULT_KEEPALIVE, 25);
        assert_eq!(LAN_MULTICAST_GROUP.to_string(), "ff02::4193");
        // 组播组必须是链路本地 scope：公告不该被路由器转发出本链路
        assert!(LAN_MULTICAST_GROUP.is_multicast());
        assert_eq!(LAN_MULTICAST_GROUP.segments()[0] & 0x000f, 0x0002);
    }
}
