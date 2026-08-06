//! 全局默认值（见设计 spec §5）。

/// 默认 WireGuard UDP 监听端口（致敬 RFC 4193）。
pub const DEFAULT_PORT: u16 = 4193;
/// 默认隧道 MTU（中国家宽 PPPoE 1492 − IPv6 WG 开销 80，留余量）。
pub const DEFAULT_MTU: u32 = 1400;
/// 默认接口名。
pub const DEFAULT_INTERFACE: &str = "hextet0";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_stable() {
        assert_eq!(DEFAULT_PORT, 4193);
        assert_eq!(DEFAULT_MTU, 1400);
        assert_eq!(DEFAULT_INTERFACE, "hextet0");
    }
}
