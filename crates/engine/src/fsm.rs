//! 单个 peer 的打洞/连接状态机（纯逻辑，无 I/O）。
//!
//! 机制（设计 spec §4「关键设计」）：打洞不需要独立信令协议——会合层只负责
//! "知道对方当前 `[addr]:port`"，然后两端同时发 WireGuard 握手包，防火墙 state
//! 相互命中即通。本状态机做的就是「在候选 endpoint 之间轮换，并持续制造出站
//! 握手」，以及在握手成功后跟随内核的 roaming 结果。

use std::net::SocketAddrV6;
use std::time::{Duration, SystemTime};

use crate::candidates::normalize;

/// 候选 endpoint 轮换间隔。
///
/// 内核 WireGuard 的握手重试间隔是 5s（REKEY_TIMEOUT），2.5s 轮换保证每个候选
/// 在被换掉之前至少收到一次我们主动触发的握手初始化。
pub const ROTATE_INTERVAL: Duration = Duration::from_millis(2500);

/// 握手新鲜度阈值：超过它视为连接已断。
///
/// 与 `hextet status` 的 `connected` 判定阈值保持一致（180s）——两处如果不一致，
/// 会出现 status 说 connected 而 daemon 正在打洞这种自相矛盾的输出。
pub const HANDSHAKE_FRESH: Duration = Duration::from_secs(180);

/// 状态机对外可见状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PunchState {
    /// 正在轮换候选 endpoint 打洞。
    Probing {
        /// 当前候选下标。
        candidate_index: usize,
        /// 已走完的完整轮次数（仅用于可观测性，不参与决策）。
        rounds: u32,
    },
    /// 已有新鲜握手。
    Connected {
        /// 内核当前记录的 endpoint（已归一化）。
        endpoint: SocketAddrV6,
    },
}

/// 每 tick 从内核读到的观测值。
#[derive(Debug, Clone, Copy)]
pub struct Observation {
    /// 最近一次握手时间（内核 WireGuard 报告）。
    pub last_handshake: Option<SystemTime>,
    /// 内核当前记录的 endpoint。调用方必须先 [`normalize`]。
    pub kernel_endpoint: Option<SocketAddrV6>,
}

/// 状态机要求外部执行的副作用。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// 把内核里该 peer 的 endpoint 设成给定值。
    SetEndpoint(SocketAddrV6),
    /// 向该 peer 的 overlay 地址发一个包：触发 WireGuard 握手，
    /// 或用本机**新的**源地址发一个已认证的包让对端 roaming。
    Nudge,
    /// 该 endpoint 已被证实可用，记入端点缓存。
    MarkGood(SocketAddrV6),
}

/// 单个 peer 的打洞状态机。
#[derive(Debug)]
pub struct PeerFsm {
    candidates: Vec<SocketAddrV6>,
    state: PunchState,
    last_transition: SystemTime,
}

fn handshake_is_fresh(last_handshake: Option<SystemTime>, now: SystemTime) -> bool {
    match last_handshake {
        // duration_since 在 t > now 时报错（时钟回拨）：保守视为新鲜。
        Some(t) => now
            .duration_since(t)
            .map(|d| d < HANDSHAKE_FRESH)
            .unwrap_or(true),
        None => false,
    }
}

impl PeerFsm {
    /// 用候选列表新建状态机，初始状态为 `Probing { candidate_index: 0, rounds: 0 }`。
    pub fn new(candidates: Vec<SocketAddrV6>, now: SystemTime) -> Self {
        Self {
            candidates: candidates.into_iter().map(normalize).collect(),
            state: PunchState::Probing {
                candidate_index: 0,
                rounds: 0,
            },
            last_transition: now,
        }
    }

    /// 当前状态。
    pub fn state(&self) -> PunchState {
        self.state
    }

    /// 候选数量。
    pub fn candidates_len(&self) -> usize {
        self.candidates.len()
    }

    /// 当前候选（`Connected` 状态下返回已连上的 endpoint）。
    pub fn current_candidate(&self) -> Option<SocketAddrV6> {
        match self.state {
            PunchState::Connected { endpoint } => Some(endpoint),
            PunchState::Probing {
                candidate_index, ..
            } => self.candidates.get(candidate_index).copied(),
        }
    }

    /// 立刻重试当前候选：daemon 启动时调用一次，本机地址变化后再调用。
    ///
    /// `Connected` 状态下只发 `Nudge`——本机地址变了不需要改对端 endpoint，
    /// 只需要让对端收到一个来自新源地址的已认证包（WireGuard roaming）。
    pub fn kick(&mut self, now: SystemTime) -> Vec<Action> {
        self.last_transition = now;
        match self.state {
            PunchState::Connected { .. } => vec![Action::Nudge],
            PunchState::Probing {
                candidate_index, ..
            } => match self.candidates.get(candidate_index) {
                Some(&ep) => vec![Action::SetEndpoint(ep), Action::Nudge],
                None => vec![],
            },
        }
    }

    /// 推进一个 tick。
    pub fn tick(&mut self, now: SystemTime, obs: Observation) -> Vec<Action> {
        let fresh = handshake_is_fresh(obs.last_handshake, now);
        let kernel_endpoint = obs.kernel_endpoint.map(normalize);

        match self.state {
            PunchState::Probing {
                candidate_index,
                rounds,
            } => {
                if fresh {
                    let Some(endpoint) =
                        kernel_endpoint.or_else(|| self.candidates.get(candidate_index).copied())
                    else {
                        return vec![];
                    };
                    self.state = PunchState::Connected { endpoint };
                    self.last_transition = now;
                    return vec![Action::MarkGood(endpoint)];
                }
                if self.candidates.is_empty() {
                    return vec![];
                }
                let elapsed = now
                    .duration_since(self.last_transition)
                    .unwrap_or(Duration::ZERO);
                if elapsed < ROTATE_INTERVAL {
                    return vec![];
                }
                let next = (candidate_index + 1) % self.candidates.len();
                let rounds = if next == 0 {
                    rounds.saturating_add(1)
                } else {
                    rounds
                };
                self.state = PunchState::Probing {
                    candidate_index: next,
                    rounds,
                };
                self.last_transition = now;
                vec![Action::SetEndpoint(self.candidates[next]), Action::Nudge]
            }
            PunchState::Connected { endpoint } => {
                if !fresh {
                    self.state = PunchState::Probing {
                        candidate_index: 0,
                        rounds: 0,
                    };
                    self.last_transition = now;
                    return match self.candidates.first() {
                        Some(&ep) => vec![Action::SetEndpoint(ep), Action::Nudge],
                        None => vec![],
                    };
                }
                match kernel_endpoint {
                    // 对端换了地址，内核已据已认证包 roaming：跟随并记入缓存
                    Some(ke) if ke != endpoint => {
                        self.state = PunchState::Connected { endpoint: ke };
                        self.last_transition = now;
                        vec![Action::MarkGood(ke)]
                    }
                    _ => vec![],
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ep(s: &str) -> SocketAddrV6 {
        s.parse().unwrap()
    }

    fn t0() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000)
    }

    fn three() -> Vec<SocketAddrV6> {
        vec![
            ep("[2001:db8::1]:4193"),
            ep("[2001:db8::2]:4193"),
            ep("[2001:db8::3]:4193"),
        ]
    }

    /// 没有握手时的观测。
    fn cold() -> Observation {
        Observation {
            last_handshake: None,
            kernel_endpoint: None,
        }
    }

    #[test]
    fn starts_in_probing_at_first_candidate() {
        let fsm = PeerFsm::new(three(), t0());
        assert_eq!(
            fsm.state(),
            PunchState::Probing {
                candidate_index: 0,
                rounds: 0
            }
        );
        assert_eq!(fsm.current_candidate(), Some(ep("[2001:db8::1]:4193")));
        assert_eq!(fsm.candidates_len(), 3);
    }

    #[test]
    fn kick_sets_current_candidate_and_nudges() {
        let mut fsm = PeerFsm::new(three(), t0());
        let actions = fsm.kick(t0());
        assert_eq!(
            actions,
            vec![Action::SetEndpoint(ep("[2001:db8::1]:4193")), Action::Nudge]
        );
    }

    #[test]
    fn probing_does_nothing_before_rotate_interval() {
        let mut fsm = PeerFsm::new(three(), t0());
        let _ = fsm.kick(t0());
        let actions = fsm.tick(t0() + Duration::from_millis(2_400), cold());
        assert!(actions.is_empty(), "got {actions:?}");
        assert_eq!(
            fsm.state(),
            PunchState::Probing {
                candidate_index: 0,
                rounds: 0
            }
        );
    }

    #[test]
    fn probing_rotates_to_next_candidate_after_interval() {
        let mut fsm = PeerFsm::new(three(), t0());
        let _ = fsm.kick(t0());
        let actions = fsm.tick(t0() + Duration::from_millis(2_600), cold());
        assert_eq!(
            actions,
            vec![Action::SetEndpoint(ep("[2001:db8::2]:4193")), Action::Nudge]
        );
        assert_eq!(
            fsm.state(),
            PunchState::Probing {
                candidate_index: 1,
                rounds: 0
            }
        );
    }

    #[test]
    fn rotation_wraps_and_counts_rounds() {
        let mut fsm = PeerFsm::new(three(), t0());
        let _ = fsm.kick(t0());
        let mut now = t0();
        // 0 -> 1 -> 2 -> 0（回到 0 时算走完一轮）
        for expected in [1usize, 2, 0] {
            now += Duration::from_millis(2_600);
            let _ = fsm.tick(now, cold());
            match fsm.state() {
                PunchState::Probing {
                    candidate_index, ..
                } => assert_eq!(candidate_index, expected),
                other => panic!("expected Probing, got {other:?}"),
            }
        }
        assert_eq!(
            fsm.state(),
            PunchState::Probing {
                candidate_index: 0,
                rounds: 1
            }
        );
    }

    #[test]
    fn single_candidate_keeps_re_nudging_same_endpoint() {
        let mut fsm = PeerFsm::new(vec![ep("[2001:db8::1]:4193")], t0());
        let _ = fsm.kick(t0());
        let actions = fsm.tick(t0() + Duration::from_millis(2_600), cold());
        // 只有一个候选时"轮换"回到自己：仍然要重发 nudge，
        // 否则内核 WireGuard 放弃握手后（约 90s）就再也不会重试。
        assert_eq!(
            actions,
            vec![Action::SetEndpoint(ep("[2001:db8::1]:4193")), Action::Nudge]
        );
    }

    #[test]
    fn fresh_handshake_transitions_to_connected_and_marks_good() {
        let mut fsm = PeerFsm::new(three(), t0());
        let _ = fsm.kick(t0());
        let now = t0() + Duration::from_secs(3);
        let actions = fsm.tick(
            now,
            Observation {
                last_handshake: Some(now - Duration::from_secs(1)),
                kernel_endpoint: Some(ep("[2001:db8::2]:4193")),
            },
        );
        assert_eq!(actions, vec![Action::MarkGood(ep("[2001:db8::2]:4193"))]);
        assert_eq!(
            fsm.state(),
            PunchState::Connected {
                endpoint: ep("[2001:db8::2]:4193")
            }
        );
    }

    #[test]
    fn connected_is_quiet_while_handshake_stays_fresh() {
        let mut fsm = PeerFsm::new(three(), t0());
        let now = t0() + Duration::from_secs(3);
        let _ = fsm.tick(
            now,
            Observation {
                last_handshake: Some(now),
                kernel_endpoint: Some(ep("[2001:db8::1]:4193")),
            },
        );
        let actions = fsm.tick(
            now + Duration::from_secs(30),
            Observation {
                last_handshake: Some(now),
                kernel_endpoint: Some(ep("[2001:db8::1]:4193")),
            },
        );
        assert!(actions.is_empty(), "got {actions:?}");
    }

    #[test]
    fn connected_follows_peer_roaming() {
        let mut fsm = PeerFsm::new(three(), t0());
        let now = t0() + Duration::from_secs(3);
        let _ = fsm.tick(
            now,
            Observation {
                last_handshake: Some(now),
                kernel_endpoint: Some(ep("[2001:db8::1]:4193")),
            },
        );
        // 对端换了前缀，内核根据已认证的包更新了 endpoint
        let actions = fsm.tick(
            now + Duration::from_secs(1),
            Observation {
                last_handshake: Some(now + Duration::from_secs(1)),
                kernel_endpoint: Some(ep("[2001:db8:2::1]:4193")),
            },
        );
        assert_eq!(actions, vec![Action::MarkGood(ep("[2001:db8:2::1]:4193"))]);
        assert_eq!(
            fsm.state(),
            PunchState::Connected {
                endpoint: ep("[2001:db8:2::1]:4193")
            }
        );
    }

    #[test]
    fn connected_falls_back_to_probing_when_handshake_goes_stale() {
        let mut fsm = PeerFsm::new(three(), t0());
        let now = t0() + Duration::from_secs(3);
        let _ = fsm.tick(
            now,
            Observation {
                last_handshake: Some(now),
                kernel_endpoint: Some(ep("[2001:db8::2]:4193")),
            },
        );
        let actions = fsm.tick(
            now + Duration::from_secs(300),
            Observation {
                last_handshake: Some(now),
                kernel_endpoint: Some(ep("[2001:db8::2]:4193")),
            },
        );
        assert_eq!(
            actions,
            vec![Action::SetEndpoint(ep("[2001:db8::1]:4193")), Action::Nudge]
        );
        assert_eq!(
            fsm.state(),
            PunchState::Probing {
                candidate_index: 0,
                rounds: 0
            }
        );
    }

    #[test]
    fn kick_while_connected_only_nudges() {
        let mut fsm = PeerFsm::new(three(), t0());
        let now = t0() + Duration::from_secs(3);
        let _ = fsm.tick(
            now,
            Observation {
                last_handshake: Some(now),
                kernel_endpoint: Some(ep("[2001:db8::1]:4193")),
            },
        );
        // 本机换了前缀：不要动对端 endpoint，只需发一个包让对端 roaming 到我们的新源地址
        assert_eq!(fsm.kick(now + Duration::from_secs(1)), vec![Action::Nudge]);
    }

    #[test]
    fn empty_candidates_never_panic_and_emit_nothing() {
        let mut fsm = PeerFsm::new(vec![], t0());
        assert!(fsm.kick(t0()).is_empty());
        assert!(fsm.tick(t0() + Duration::from_secs(10), cold()).is_empty());
        assert_eq!(fsm.current_candidate(), None);
        assert_eq!(fsm.candidates_len(), 0);
    }

    #[test]
    fn handshake_in_the_future_is_treated_as_fresh() {
        // 时钟回拨 / 内核时间比 SystemTime::now() 新时 duration_since 会 Err，
        // 保守当作"新鲜"，不要把一条正常连接打回打洞状态。
        let mut fsm = PeerFsm::new(three(), t0());
        let now = t0() + Duration::from_secs(3);
        let actions = fsm.tick(
            now,
            Observation {
                last_handshake: Some(now + Duration::from_secs(60)),
                kernel_endpoint: Some(ep("[2001:db8::1]:4193")),
            },
        );
        assert_eq!(actions, vec![Action::MarkGood(ep("[2001:db8::1]:4193"))]);
    }

    #[test]
    fn connected_without_kernel_endpoint_falls_back_to_candidate() {
        // 极端情况：握手新鲜但内核没报 endpoint —— 用当前候选顶上，不要 panic。
        let mut fsm = PeerFsm::new(three(), t0());
        let now = t0() + Duration::from_secs(3);
        let actions = fsm.tick(
            now,
            Observation {
                last_handshake: Some(now),
                kernel_endpoint: None,
            },
        );
        assert_eq!(actions, vec![Action::MarkGood(ep("[2001:db8::1]:4193"))]);
    }
}
