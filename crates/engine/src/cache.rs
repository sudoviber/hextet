//! 端点缓存：把"上次能连上的 endpoint"持久化，重启后直接复用。

use std::net::SocketAddrV6;

use serde::{Deserialize, Serialize};

/// 一个曾经见到过的 endpoint 及其最后一次被证实可用的时间。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CachedEndpoint {
    /// endpoint 本体（存储前已 [`crate::candidates::normalize`]）。
    pub endpoint: SocketAddrV6,
    /// 最后一次被证实可用的 Unix 时间戳（秒）。
    pub last_seen_unix: u64,
}
