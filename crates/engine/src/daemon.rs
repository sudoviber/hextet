//! 守护进程主循环：把 wg 后端、地址监听、打洞状态机、端点缓存、状态文件接起来。
//!
//! 本文件是 M2 唯一"必须真跑网络才能验证"的部分，由 `scripts/netns-e2e-dynamic.sh`
//! 端到端覆盖；所有判断逻辑都在 `crate::{fsm, candidates, cache, state}` 里且已被单测覆盖。

use std::collections::HashMap;
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use anyhow::Context as _;
use hextet_core::addr::derive_node_addr;
use hextet_core::config::load_config_and_identity;
use hextet_core::network::NetworkPrefix;
use hextet_platform::{AddrEvent, setup_interface, watch_ipv6_addresses};
use hextet_wg::WgBackend as _;
use hextet_wg::kernel::KernelBackend;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::cache::EndpointCache;
use crate::candidates::{MAX_CANDIDATES, build_candidates, normalize};
use crate::fsm::{Action, Observation, PeerFsm, PunchState};
use crate::spec::build_device_spec;
use crate::state::{EngineState, PeerState, STATE_VERSION, endpoint_source, unix_secs};

/// 主循环 tick 周期。
const TICK: Duration = Duration::from_secs(1);

/// 本机地址变化事件的去抖窗口。
///
/// PPPoE 重拨换前缀时内核会连发多条 `RTM_NEWADDR`/`RTM_DELADDR`；等 200ms 把这一
/// 串事件吞掉再统一重试，避免对每条事件都发一遍 nudge。
const ADDR_DEBOUNCE: Duration = Duration::from_millis(200);

/// nudge 包的目标端口（RFC 863 discard）。
///
/// nudge 的唯一目的是"让内核 WireGuard 有东西可发"：包本身会被对端丢弃，
/// 但它触发的握手/已认证数据包会让对端学到我们当前的源地址（roaming）。
const NUDGE_PORT: u16 = 9;

/// 每个 peer 的运行时上下文。
struct PeerRuntime {
    name: String,
    key_b64: String,
    wg_public: [u8; 32],
    overlay: Ipv6Addr,
    configured: Vec<SocketAddrV6>,
    fsm: PeerFsm,
}

/// 循环期间不变的上下文。
struct Ctx {
    interface: String,
    node_address: Ipv6Addr,
    node_public_key: String,
    cache_path: PathBuf,
    state_path: PathBuf,
}

/// 启动守护进程，阻塞直到收到 SIGINT/SIGTERM。
pub fn run(config_path: &Path) -> anyhow::Result<()> {
    let rt = tokio::runtime::Runtime::new().context("创建 tokio runtime")?;
    rt.block_on(run_async(config_path))
}

fn ensure_state_dir(dir: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("创建状态目录 {}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("设置状态目录权限 {}", dir.display()))?;
    }
    Ok(())
}

/// 内核报告的 endpoint → 归一化后的 `SocketAddrV6`（IPv4 endpoint 直接丢弃）。
fn kernel_endpoint(endpoint: Option<SocketAddr>) -> Option<SocketAddrV6> {
    match endpoint {
        Some(SocketAddr::V6(v6)) => Some(normalize(v6)),
        // hextet 是 IPv6-only 的；内核不该报出 IPv4 endpoint，报了就当没有
        Some(SocketAddr::V4(_)) | None => None,
    }
}

async fn run_async(config_path: &Path) -> anyhow::Result<()> {
    let (cfg, id) = load_config_and_identity(config_path)?;
    let own = derive_node_addr(cfg.prefix, &id.public())?;

    ensure_state_dir(&cfg.node.state_dir)?;
    let ctx = Ctx {
        interface: cfg.node.interface.clone(),
        node_address: own.address,
        node_public_key: id.public().to_base64(),
        cache_path: cfg.node.state_dir.join("endpoints.json"),
        state_path: cfg.node.state_dir.join("state.json"),
    };

    // 1) 数据面就位（与 `hextet up` 同一条路径，两步都幂等）
    let backend = KernelBackend;
    let spec = build_device_spec(&cfg, &id);
    backend
        .apply(&spec)
        .context("配置 WireGuard 设备（需要 root/CAP_NET_ADMIN）")?;
    setup_interface(
        &ctx.interface,
        own.address,
        NetworkPrefix::PREFIX_LEN,
        cfg.node.mtu,
    )
    .await
    .context("配置接口地址/MTU")?;
    info!(
        interface = %ctx.interface,
        address = %own.address,
        peers = cfg.peers.len(),
        "daemon 启动"
    );

    // 2) 端点缓存 + 每 peer 运行时
    let mut cache = EndpointCache::load(&ctx.cache_path);
    let start = SystemTime::now();
    let mut peers: Vec<PeerRuntime> = cfg
        .peers
        .iter()
        .map(|p| {
            let key_b64 = p.public_key.to_base64();
            let entry = cache.entry(&key_b64);
            let cached = entry.map(|e| e.seen.as_slice()).unwrap_or(&[]);
            let candidates =
                build_candidates(&p.endpoints, cached, entry.and_then(|e| e.last_good));
            let total = p.endpoints.len() + cached.len();
            if total > candidates.len() {
                debug!(
                    peer = %p.name,
                    kept = candidates.len(),
                    limit = MAX_CANDIDATES,
                    "候选 endpoint 去重/截断后减少"
                );
            }
            info!(peer = %p.name, candidates = candidates.len(), "候选 endpoint 就绪");
            PeerRuntime {
                name: p.name.clone(),
                key_b64,
                wg_public: p.public_key.wg_public_bytes(),
                overlay: p.addr.address,
                configured: p.endpoints.clone(),
                fsm: PeerFsm::new(candidates, start),
            }
        })
        .collect();

    // 3) nudge socket：往 overlay 地址发包，逼内核 WireGuard 发握手/已认证包
    let nudge = UdpSocket::bind("[::]:0")
        .await
        .context("绑定 nudge socket")?;

    // 4) 本机地址变化监听（失败只降级，不致命：tick 仍会在 180s 内发现连接失效）
    let (tx, mut addr_rx) = mpsc::channel::<AddrEvent>(64);
    tokio::spawn(async move {
        match watch_ipv6_addresses(tx).await {
            Ok(()) => debug!("IPv6 地址监听正常结束"),
            Err(e) => warn!(error = %e, "IPv6 地址监听退出：换前缀后将退化为 tick 驱动恢复"),
        }
    });

    // 5) 首次触发：让每个 peer 立刻开始握手，而不是等第一次轮换
    let now = SystemTime::now();
    for peer in peers.iter_mut() {
        let actions = peer.fsm.kick(now);
        apply_actions(&backend, &ctx, &nudge, &mut cache, &*peer, &actions).await;
    }

    let mut ticker = tokio::time::interval(TICK);
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("注册 SIGTERM handler")?;

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                tick_once(&backend, &ctx, &nudge, &mut cache, &mut peers).await;
            }
            Some(event) = addr_rx.recv() => {
                debug!(?event, "本机 IPv6 地址变化");
                tokio::time::sleep(ADDR_DEBOUNCE).await;
                let mut extra = 0usize;
                while addr_rx.try_recv().is_ok() {
                    extra += 1;
                }
                let now = SystemTime::now();
                for peer in peers.iter_mut() {
                    let actions = peer.fsm.kick(now);
                    apply_actions(&backend, &ctx, &nudge, &mut cache, &*peer, &actions).await;
                }
                info!(coalesced = extra, "地址变化：已对所有 peer 重新握手/nudge");
            }
            _ = tokio::signal::ctrl_c() => {
                info!("收到 SIGINT");
                break;
            }
            _ = sigterm.recv() => {
                info!("收到 SIGTERM");
                break;
            }
        }
    }

    info!(
        interface = %ctx.interface,
        "daemon 退出（接口保留，用 `hextet down` 拆除）"
    );
    Ok(())
}

async fn tick_once(
    backend: &KernelBackend,
    ctx: &Ctx,
    nudge: &UdpSocket,
    cache: &mut EndpointCache,
    peers: &mut [PeerRuntime],
) {
    let statuses = match backend.status(&ctx.interface) {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, "读取 WireGuard 状态失败，跳过本 tick");
            return;
        }
    };
    let by_key: HashMap<[u8; 32], &hextet_wg::types::PeerStatus> =
        statuses.iter().map(|s| (s.wg_public, s)).collect();

    let now = SystemTime::now();
    let mut peer_states = Vec::with_capacity(peers.len());
    for peer in peers.iter_mut() {
        let observed = by_key.get(&peer.wg_public);
        let obs = Observation {
            last_handshake: observed.and_then(|s| s.last_handshake),
            kernel_endpoint: observed.and_then(|s| kernel_endpoint(s.endpoint)),
        };
        let actions = peer.fsm.tick(now, obs);
        apply_actions(backend, ctx, nudge, cache, &*peer, &actions).await;
        peer_states.push(peer_state_of(&*peer, cache));
    }

    let state = EngineState {
        version: STATE_VERSION,
        updated_unix: unix_secs(now),
        interface: ctx.interface.clone(),
        node_address: ctx.node_address,
        node_public_key: ctx.node_public_key.clone(),
        peers: peer_states,
    };
    if let Err(e) = crate::state::write(&ctx.state_path, &state) {
        warn!(path = %ctx.state_path.display(), error = %e, "写状态文件失败");
    }
}

fn peer_state_of(peer: &PeerRuntime, cache: &EndpointCache) -> PeerState {
    let (punch_state, candidate_index, rounds) = match peer.fsm.state() {
        PunchState::Connected { .. } => ("connected", 0usize, 0u32),
        PunchState::Probing {
            candidate_index,
            rounds,
        } => ("probing", candidate_index, rounds),
    };
    let endpoint = peer.fsm.current_candidate();
    let empty: Vec<crate::cache::CachedEndpoint> = Vec::new();
    let cached = cache
        .entry(&peer.key_b64)
        .map(|e| e.seen.as_slice())
        .unwrap_or(&empty);
    PeerState {
        name: peer.name.clone(),
        public_key: peer.key_b64.clone(),
        address: peer.overlay,
        punch_state: punch_state.to_owned(),
        endpoint,
        endpoint_source: endpoint_source(endpoint, &peer.configured, cached).to_owned(),
        candidates: peer.fsm.candidates_len(),
        candidate_index,
        rounds,
    }
}

async fn apply_actions(
    backend: &KernelBackend,
    ctx: &Ctx,
    nudge: &UdpSocket,
    cache: &mut EndpointCache,
    peer: &PeerRuntime,
    actions: &[Action],
) {
    for action in actions {
        match *action {
            Action::SetEndpoint(ep) => {
                match backend.set_peer_endpoint(&ctx.interface, &peer.wg_public, ep) {
                    Ok(()) => debug!(peer = %peer.name, endpoint = %ep, "设置 endpoint"),
                    Err(e) => {
                        warn!(peer = %peer.name, endpoint = %ep, error = %e, "设置 endpoint 失败")
                    }
                }
            }
            Action::Nudge => {
                let target = SocketAddrV6::new(peer.overlay, NUDGE_PORT, 0, 0);
                match nudge.send_to(&[0u8], SocketAddr::V6(target)).await {
                    Ok(_) => debug!(peer = %peer.name, "nudge 已发出"),
                    // 对端还没连通时内核可能返回 ENETUNREACH/EHOSTUNREACH/EPERM，
                    // 这在打洞过程中是常态，不是错误
                    Err(e) => {
                        debug!(peer = %peer.name, error = %e, "nudge 发送失败（打洞中属正常）")
                    }
                }
            }
            Action::MarkGood(ep) => {
                cache.record_good(&peer.key_b64, ep, unix_secs(SystemTime::now()));
                if let Err(e) = cache.save(&ctx.cache_path) {
                    warn!(path = %ctx.cache_path.display(), error = %e, "写端点缓存失败");
                }
                info!(peer = %peer.name, endpoint = %ep, "连接就绪（已记入端点缓存）");
            }
        }
    }
}
