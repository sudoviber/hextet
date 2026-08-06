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
    }
}
