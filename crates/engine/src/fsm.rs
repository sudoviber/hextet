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

    /// 换掉候选列表：会合层（LAN 公告 / gossip 转介 / DHT）发现新 endpoint 时调用。
    ///
    /// 契约：
    /// 1. 入参先归一化去重后存下（顺序与截断由调用方的
    ///    [`build_candidates`](crate::candidates::build_candidates) 负责）。
    /// 2. 列表内容没变化 → 什么都不做。
    /// 3. `Connected` 状态 → 只换列表，**不产生任何 Action**：一条正常工作的连接
    ///    绝不因为"听到了新地址"而被打扰。新列表会在将来握手失效时才起作用。
    /// 4. `Probing` 状态 → 若列表里出现了旧列表没有的 endpoint，**立刻指向第一个新的
    ///    并重试**（新发现的地址是活证据，比继续磨完剩下的陈旧候选更值得先试）；
    ///    否则尽量继续指向原来那个（跟随它的新下标），它也不在了才回到下标 0。
    ///    指向变了就发 `SetEndpoint + Nudge` 并重置轮换计时（给新候选完整的一轮）。
    /// 5. 新列表为空 → 状态回到 `Probing { 0, 0 }`，不 panic。
    pub fn set_candidates(
        &mut self,
        candidates: Vec<SocketAddrV6>,
        now: SystemTime,
    ) -> Vec<Action> {
        let mut next: Vec<SocketAddrV6> = Vec::with_capacity(candidates.len());
        for ep in candidates.into_iter().map(normalize) {
            if !next.contains(&ep) {
                next.push(ep);
            }
        }
        let old = std::mem::replace(&mut self.candidates, next);
        if old == self.candidates {
            return vec![];
        }

        match self.state {
            PunchState::Connected { .. } => vec![],
            PunchState::Probing {
                candidate_index,
                rounds,
            } => {
                if self.candidates.is_empty() {
                    self.state = PunchState::Probing {
                        candidate_index: 0,
                        rounds: 0,
                    };
                    return vec![];
                }
                let previous = old.get(candidate_index).copied();
                let index = match self.candidates.iter().position(|ep| !old.contains(ep)) {
                    Some(fresh) => fresh,
                    None => previous
                        .and_then(|ep| self.candidates.iter().position(|c| *c == ep))
                        .unwrap_or(0),
                };
                self.state = PunchState::Probing {
                    candidate_index: index,
                    rounds,
                };
                let pointed = self.candidates[index];
                if Some(pointed) == previous {
                    return vec![];
                }
                self.last_transition = now;
                vec![Action::SetEndpoint(pointed), Action::Nudge]
            }
        }
    }

    /// 从 `Connected` 退回 Probing，从第一个不等于 `avoid` 的候选开始重试。
    ///
    /// 中继期间"升级回直连"必须用它：内核 WireGuard 一个 peer 只有一个 endpoint，
    /// 想试直连就得先离开当前（中继）endpoint——[`set_candidates`](Self::set_candidates)
    /// 刻意不打扰 `Connected` 的连接，所以光有新候选并不会触发重试。
    ///
    /// 已经在 Probing、或者除了 `avoid` 之外没有别的候选时什么都不做。
    pub fn retry_from(&mut self, avoid: Option<SocketAddrV6>, now: SystemTime) -> Vec<Action> {
        if !matches!(self.state, PunchState::Connected { .. }) {
            return vec![];
        }
        let avoid = avoid.map(normalize);
        let Some(index) = self.candidates.iter().position(|c| Some(*c) != avoid) else {
            return vec![];
        };
        self.state = PunchState::Probing {
            candidate_index: index,
            rounds: 0,
        };
        self.last_transition = now;
        vec![Action::SetEndpoint(self.candidates[index]), Action::Nudge]
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
    fn set_candidates_jumps_to_a_newly_discovered_endpoint() {
        let mut fsm = PeerFsm::new(three(), t0());
        let _ = fsm.kick(t0());
        // 轮换到第二个候选
        let _ = fsm.tick(t0() + Duration::from_millis(2_600), cold());

        let discovered = ep("[2001:db8:9::9]:4193");
        let mut next = vec![discovered];
        next.extend(three());
        let actions = fsm.set_candidates(next, t0() + Duration::from_secs(3));
        assert_eq!(
            actions,
            vec![Action::SetEndpoint(discovered), Action::Nudge],
            "新发现的 endpoint 应该被立刻试"
        );
        assert_eq!(fsm.current_candidate(), Some(discovered));
        assert_eq!(fsm.candidates_len(), 4);
    }

    #[test]
    fn set_candidates_keeps_pointing_at_the_same_endpoint_when_only_order_changes() {
        let mut fsm = PeerFsm::new(three(), t0());
        let _ = fsm.kick(t0());
        let _ = fsm.tick(t0() + Duration::from_millis(2_600), cold());
        assert_eq!(fsm.current_candidate(), Some(ep("[2001:db8::2]:4193")));

        // 同一批地址换了顺序（没有任何新地址）：不该打断当前尝试
        let reordered = vec![
            ep("[2001:db8::3]:4193"),
            ep("[2001:db8::2]:4193"),
            ep("[2001:db8::1]:4193"),
        ];
        let actions = fsm.set_candidates(reordered, t0() + Duration::from_secs(3));
        assert!(actions.is_empty(), "got {actions:?}");
        assert_eq!(fsm.current_candidate(), Some(ep("[2001:db8::2]:4193")));
    }

    #[test]
    fn set_candidates_falls_back_to_first_when_current_disappears() {
        let mut fsm = PeerFsm::new(three(), t0());
        let _ = fsm.kick(t0());
        let _ = fsm.tick(t0() + Duration::from_millis(2_600), cold());
        assert_eq!(fsm.current_candidate(), Some(ep("[2001:db8::2]:4193")));

        // 当前候选被移出列表，且没有"新"地址（都是旧列表里有的）
        let shrunk = vec![ep("[2001:db8::1]:4193"), ep("[2001:db8::3]:4193")];
        let actions = fsm.set_candidates(shrunk, t0() + Duration::from_secs(3));
        assert_eq!(
            actions,
            vec![Action::SetEndpoint(ep("[2001:db8::1]:4193")), Action::Nudge]
        );
        assert_eq!(fsm.current_candidate(), Some(ep("[2001:db8::1]:4193")));
    }

    /// 已连上时绝不因为"听到新地址"而动手：那会把一条好连接打断。
    #[test]
    fn set_candidates_never_disturbs_a_connected_peer() {
        let mut fsm = PeerFsm::new(three(), t0());
        let now = t0() + Duration::from_secs(3);
        let _ = fsm.tick(
            now,
            Observation {
                last_handshake: Some(now),
                kernel_endpoint: Some(ep("[2001:db8::1]:4193")),
            },
        );
        let mut next = vec![ep("[2001:db8:9::9]:4193")];
        next.extend(three());
        let actions = fsm.set_candidates(next, now + Duration::from_secs(1));
        assert!(actions.is_empty(), "got {actions:?}");
        assert_eq!(
            fsm.state(),
            PunchState::Connected {
                endpoint: ep("[2001:db8::1]:4193")
            }
        );
        // 但新列表已经就位：握手失效后会用上它
        assert_eq!(fsm.candidates_len(), 4);
    }

    #[test]
    fn retry_from_leaves_connected_and_skips_the_avoided_candidate() {
        let mut fsm = PeerFsm::new(three(), t0());
        let now = t0() + Duration::from_secs(3);
        // 连在第三个候选上（模拟"连在中继上"）
        let _ = fsm.tick(
            now,
            Observation {
                last_handshake: Some(now),
                kernel_endpoint: Some(ep("[2001:db8::3]:4193")),
            },
        );
        let actions = fsm.retry_from(Some(ep("[2001:db8::3]:4193")), now);
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
    fn retry_from_is_a_noop_without_alternatives_or_while_probing() {
        // 只有被 avoid 的那一个候选：无处可试，保持 Connected
        let only = vec![ep("[2001:db8::1]:4193")];
        let mut fsm = PeerFsm::new(only.clone(), t0());
        let now = t0() + Duration::from_secs(3);
        let _ = fsm.tick(
            now,
            Observation {
                last_handshake: Some(now),
                kernel_endpoint: Some(ep("[2001:db8::1]:4193")),
            },
        );
        assert!(
            fsm.retry_from(Some(ep("[2001:db8::1]:4193")), now)
                .is_empty()
        );
        assert_eq!(
            fsm.state(),
            PunchState::Connected {
                endpoint: ep("[2001:db8::1]:4193")
            }
        );

        // 已经在 Probing：不重置进度
        let mut fsm = PeerFsm::new(three(), t0());
        let _ = fsm.kick(t0());
        let _ = fsm.tick(t0() + Duration::from_millis(2_600), cold());
        assert!(
            fsm.retry_from(None, t0() + Duration::from_secs(3))
                .is_empty()
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
    fn set_candidates_with_identical_list_is_a_noop() {
        let mut fsm = PeerFsm::new(three(), t0());
        let _ = fsm.kick(t0());
        let _ = fsm.tick(t0() + Duration::from_millis(2_600), cold());
        let actions = fsm.set_candidates(three(), t0() + Duration::from_secs(3));
        assert!(actions.is_empty(), "got {actions:?}");
        assert_eq!(fsm.current_candidate(), Some(ep("[2001:db8::2]:4193")));
    }

    #[test]
    fn set_candidates_handles_empty_and_from_empty() {
        // 从空列表变成有候选：立刻试第一个
        let mut fsm = PeerFsm::new(vec![], t0());
        let actions = fsm.set_candidates(three(), t0());
        assert_eq!(
            actions,
            vec![Action::SetEndpoint(ep("[2001:db8::1]:4193")), Action::Nudge]
        );

        // 变成空列表：不 panic，状态回到起点
        let actions = fsm.set_candidates(vec![], t0() + Duration::from_secs(1));
        assert!(actions.is_empty(), "got {actions:?}");
        assert_eq!(
            fsm.state(),
            PunchState::Probing {
                candidate_index: 0,
                rounds: 0
            }
        );
        assert_eq!(fsm.current_candidate(), None);
    }

    #[test]
    fn set_candidates_normalizes_and_dedupes() {
        let mut fsm = PeerFsm::new(vec![], t0());
        let with_scope = SocketAddrV6::new("2001:db8::1".parse().unwrap(), 4193, 4, 9);
        let _ = fsm.set_candidates(vec![with_scope, ep("[2001:db8::1]:4193")], t0());
        assert_eq!(fsm.candidates_len(), 1);
        assert_eq!(fsm.current_candidate(), Some(ep("[2001:db8::1]:4193")));
    }

    /// 换候选后轮换计时要重置：新候选应拿到完整的一个 ROTATE_INTERVAL。
    #[test]
    fn set_candidates_resets_the_rotation_timer() {
        let mut fsm = PeerFsm::new(three(), t0());
        let _ = fsm.kick(t0());
        // 距上次切换已过 2.4s，正常再过 0.1s 就该轮换
        let at = t0() + Duration::from_millis(2_400);
        let mut next = vec![ep("[2001:db8:9::9]:4193")];
        next.extend(three());
        let _ = fsm.set_candidates(next, at);
        let actions = fsm.tick(at + Duration::from_millis(200), cold());
        assert!(
            actions.is_empty(),
            "刚换上的候选不该在 200ms 后就被轮换掉: {actions:?}"
        );
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
