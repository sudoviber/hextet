//! 守护进程主循环：把 wg 后端、地址监听、打洞状态机、端点缓存、状态文件接起来。
//!
//! 本文件是 M2 唯一"必须真跑网络才能验证"的部分，由 `scripts/netns-e2e-dynamic.sh`
//! 端到端覆盖；所有判断逻辑都在 `crate::{fsm, candidates, cache, state}` 里且已被单测覆盖。

use std::collections::HashMap;
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use anyhow::Context as _;
use hextet_core::addr::derive_node_addr;
use hextet_core::config::load_config_and_identity;
use hextet_core::defaults::LAN_MULTICAST_GROUP;
use hextet_core::identity::NodePublicKey;
use hextet_core::network::NetworkPrefix;
use hextet_core::network::{derive_lan_key, derive_probe_key, derive_relay_key};
use hextet_platform::{
    AddrEvent, list_multicast_interfaces, setup_interface, watch_ipv6_addresses,
};
use hextet_wg::WgBackend as _;
use hextet_wg::kernel::KernelBackend;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::cache::EndpointCache;
use crate::candidates::{CandidateSources, MAX_CANDIDATES, build_candidates, normalize};
use crate::fsm::{Action, Observation, PeerFsm, PunchState};
use crate::lan::{LanConfig, LanUpdate};
use crate::relay_client::{self, RelaySession};
use crate::relay_server::RelayPolicy;
use crate::spec::build_device_spec;
use crate::state::{EngineState, PeerState, STATE_VERSION, endpoint_source, unix_secs};

/// 主循环 tick 周期。
const TICK: Duration = Duration::from_secs(1);

/// 本机地址变化事件的去抖窗口。
///
/// PPPoE 重拨换前缀时内核会连发多条 `RTM_NEWADDR`/`RTM_DELADDR`；等 200ms 把这一
/// 串事件吞掉再统一重试，避免对每条事件都发一遍 nudge。
const ADDR_DEBOUNCE: Duration = Duration::from_millis(200);

/// 直连候选整整轮换几轮仍无握手才启用中继逃生舱。
///
/// 2 轮 ≈ 每个候选被试过两次（≤8 个候选、2.5s 轮换 → 最多 40s）。给足直连机会，
/// 又不至于让"确实连不上"的场景干等太久。
const RELAY_AFTER_ROUNDS: u32 = 2;

/// 中继注册失败后多久才重试。
///
/// 没有它的话，`rounds` 每轮增长都会触发一次 5s 超时的注册尝试，
/// 在中继本身不可达时变成持续刷日志。
const RELAY_RETRY_COOLDOWN: Duration = Duration::from_secs(60);

/// nudge 包的目标端口（RFC 863 discard）。
///
/// nudge 的唯一目的是"让内核 WireGuard 有东西可发"：包本身会被对端丢弃，
/// 但它触发的握手/已认证数据包会让对端学到我们当前的源地址（roaming）。
const NUDGE_PORT: u16 = 9;

/// 该 peer 的中继逃生舱状态（没有可用中继时为 `None`）。
struct RelayLink {
    /// 中继节点在配置里的名字（`status` 展示用）。
    via_name: String,
    /// 中继的控制地址（可能多个，注册时全试）。
    control: Vec<SocketAddrV6>,
    /// 对端公钥（注册帧里的 peer_key）。
    peer_public: NodePublicKey,
    /// 已建立的会话。
    session: Option<RelaySession>,
    /// 正在注册（避免并发重复注册）。
    pending: bool,
    /// 有新的直连证据，正在尝试升级回直连（此时候选列表放开直连候选）。
    upgrade_pending: bool,
    /// 上次注册/续期成功的时刻。
    last_register: Option<Instant>,
    /// 注册失败后的冷却截止时刻。
    retry_after: Option<Instant>,
}

/// 中继注册任务的结果。
struct RelayRegistered {
    peer_key: String,
    session: Option<RelaySession>,
}

/// 每个 peer 的运行时上下文。
struct PeerRuntime {
    name: String,
    key_b64: String,
    wg_public: [u8; 32],
    overlay: Ipv6Addr,
    configured: Vec<SocketAddrV6>,
    /// 会合层当下发现的 endpoint（阶段 B：LAN 公告）。
    discovered: Vec<SocketAddrV6>,
    /// 中继逃生舱（spec D5）。
    relay: Option<RelayLink>,
    fsm: PeerFsm,
}

/// 循环期间不变的上下文。
struct Ctx {
    interface: String,
    node_address: Ipv6Addr,
    node_public_key: String,
    /// 本节点公钥（中继注册帧要用）。
    own_public: NodePublicKey,
    /// 本节点 WireGuard 监听端口（中继注册帧要用，见 docs/protocol/relay.md C-0）。
    listen_port: u16,
    /// 中继控制帧的认证密钥。
    relay_key: [u8; 32],
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
        own_public: id.public(),
        listen_port: cfg.node.listen_port,
        relay_key: derive_relay_key(&cfg.network_key),
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
    // 哪些 peer 可以当中继（spec D5：显式配置，不自动选）
    let relay_peers: Vec<&hextet_core::config::Peer> =
        cfg.peers.iter().filter(|p| p.relay).collect();
    if !relay_peers.is_empty() {
        info!(
            relays = ?relay_peers.iter().map(|p| p.name.as_str()).collect::<Vec<_>>(),
            "配置了中继逃生舱：直连轮换 {RELAY_AFTER_ROUNDS} 轮无果后启用"
        );
    }
    let mut peers: Vec<PeerRuntime> = cfg
        .peers
        .iter()
        .map(|p| {
            let key_b64 = p.public_key.to_base64();
            let entry = cache.entry(&key_b64);
            let cached = entry.map(|e| e.seen.as_slice()).unwrap_or(&[]);
            let candidates = build_candidates(&CandidateSources {
                last_good: entry.and_then(|e| e.last_good),
                discovered: &[],
                configured: &p.endpoints,
                cached,
                // 启动时还没有中继会话；建立后经 set_candidates 加入
                relay: None,
            });
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
            // 自己不能当自己的中继；有多个中继时用第一个（顺序即配置顺序）
            let relay = relay_peers
                .iter()
                .find(|r| r.public_key != p.public_key)
                .map(|r| RelayLink {
                    via_name: r.name.clone(),
                    control: r.relay_control_endpoints(),
                    peer_public: p.public_key.clone(),
                    session: None,
                    pending: false,
                    upgrade_pending: false,
                    last_register: None,
                    retry_after: None,
                });
            PeerRuntime {
                name: p.name.clone(),
                key_b64,
                wg_public: p.public_key.wg_public_bytes(),
                overlay: p.addr.address,
                configured: p.endpoints.clone(),
                discovered: Vec::new(),
                relay,
                fsm: PeerFsm::new(candidates, start),
            }
        })
        .collect();

    // 3) nudge socket：往 overlay 地址发包，逼内核 WireGuard 发握手/已认证包
    let nudge = UdpSocket::bind("[::]:0")
        .await
        .context("绑定 nudge socket")?;

    // 3.5) 探针响应器：让网络内其他节点能请本机回探（hextet doctor 的对端侧）
    let probe_bind = SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, cfg.node.probe_port, 0, 0);
    match UdpSocket::bind(probe_bind).await {
        Ok(socket) => {
            let probe_key = derive_probe_key(&cfg.network_key);
            info!(port = cfg.node.probe_port, "探针响应器已启动");
            tokio::spawn(async move {
                if let Err(e) = crate::probe_responder::serve(socket, probe_key).await {
                    warn!(error = %e, "探针响应器退出：对端将无法用 hextet doctor 探测本机");
                }
            });
        }
        // 端口被占（例如同时跑着 `hextet doctor --serve`）只影响 doctor，
        // 数据面完全不受影响，因此不致命
        Err(e) => warn!(
            port = cfg.node.probe_port,
            error = %e,
            "绑定探针端口失败，跳过探针响应器"
        ),
    }

    // 3.6) 中继服务端：只有显式打开才提供（spec D5）
    if cfg.node.relay {
        let bind = SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, cfg.node.relay_port, 0, 0);
        match UdpSocket::bind(bind).await {
            Ok(socket) => {
                let policy = if cfg.node.relay_allow.is_empty() {
                    RelayPolicy::AnyMember
                } else {
                    RelayPolicy::Allowlist(
                        cfg.node.relay_allow.iter().map(|k| *k.as_bytes()).collect(),
                    )
                };
                info!(
                    port = cfg.node.relay_port,
                    allow = cfg.node.relay_allow.len(),
                    "中继服务已启用（只转发加密的 WireGuard 包，不解密）"
                );
                let relay_key = ctx.relay_key;
                tokio::spawn(async move {
                    match crate::relay_server::serve(socket, relay_key, policy).await {
                        Ok(()) => debug!("中继服务正常结束"),
                        Err(e) => warn!(error = %e, "中继服务退出：其他节点将无法经本机中继"),
                    }
                });
            }
            // 端口被占只影响"给别人当中继"，本机数据面不受影响
            Err(e) => warn!(
                port = cfg.node.relay_port,
                error = %e,
                "绑定中继端口失败，跳过中继服务"
            ),
        }
    }

    // 3.75) LAN 组播发现（会合兜底链第 ① 层）：让同 LAN 的同网节点无需配置就能互相发现
    let (lan_tx, mut lan_rx) = mpsc::channel::<LanUpdate>(64);
    let (lan_kick_tx, lan_kick_rx) = mpsc::channel::<()>(4);
    if cfg.node.lan_discovery {
        match list_multicast_interfaces(Some(&ctx.interface)).await {
            Ok(interfaces) if !interfaces.is_empty() => {
                let names: Vec<&str> = interfaces.iter().map(|(_, n)| n.as_str()).collect();
                info!(interfaces = ?names, "LAN 发现：将在这些接口上收发公告");
                let lan_cfg = LanConfig {
                    port: cfg.node.lan_port,
                    group: LAN_MULTICAST_GROUP,
                    interfaces: interfaces.iter().map(|(i, _)| *i).collect(),
                    own_public_key: id.public(),
                    lan_key: derive_lan_key(&cfg.network_key),
                    listen_port: cfg.node.listen_port,
                    exclude_interface: ctx.interface.clone(),
                };
                tokio::spawn(async move {
                    match crate::lan::serve(lan_cfg, lan_tx, lan_kick_rx).await {
                        Ok(()) => debug!("LAN 发现正常结束"),
                        Err(e) => warn!(error = %e, "LAN 发现退出：同 LAN 自动发现不可用"),
                    }
                });
            }
            // 没有可组播的接口 / 枚举失败：只丢掉 LAN 这一路会合，数据面不受影响
            Ok(_) => {
                warn!("没有可用于组播的接口，跳过 LAN 发现");
                drop(lan_tx);
                drop(lan_kick_rx);
            }
            Err(e) => {
                warn!(error = %e, "枚举组播接口失败，跳过 LAN 发现");
                drop(lan_tx);
                drop(lan_kick_rx);
            }
        }
    } else {
        info!("LAN 组播发现已关闭（[node] lan_discovery = false）");
        drop(lan_tx);
        drop(lan_kick_rx);
    }

    // 3.9) 中继注册结果回传通道（注册要等应答，不能阻塞主循环）
    let (relay_tx, mut relay_rx) = mpsc::channel::<RelayRegistered>(16);

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
                tick_once(&backend, &ctx, &nudge, &mut cache, &mut peers, &relay_tx).await;
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
                // 本机换了地址 → 立刻补发一条 LAN 公告，别让同 LAN 的对端等一个周期。
                // 通道满或已关闭都无所谓：周期公告本身就是兜底。
                let _ = lan_kick_tx.try_send(());
                info!(coalesced = extra, "地址变化：已对所有 peer 重新握手/nudge");
            }
            Some(update) = lan_rx.recv() => {
                on_lan_update(&backend, &ctx, &nudge, &mut cache, &mut peers, update).await;
            }
            Some(done) = relay_rx.recv() => {
                on_relay_registered(&backend, &ctx, &nudge, &mut cache, &mut peers, done).await;
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
    relay_tx: &mpsc::Sender<RelayRegistered>,
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
        drive_relay(peer, ctx, cache, relay_tx, Instant::now());
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

/// 组装某个 peer 当前的各路候选来源。
fn sources_for<'a>(peer: &'a PeerRuntime, cache: &'a EndpointCache) -> CandidateSources<'a> {
    let entry = cache.entry(&peer.key_b64);
    CandidateSources {
        last_good: entry.and_then(|e| e.last_good),
        discovered: &peer.discovered,
        configured: &peer.configured,
        cached: entry.map(|e| e.seen.as_slice()).unwrap_or(&[]),
        relay: peer
            .relay
            .as_ref()
            .and_then(|l| l.session.map(|s| s.endpoint)),
    }
}

/// 用当前的各路来源重算某个 peer 的候选列表。
///
/// 中继会话已建立、且没有"该升级回直连"的新证据时，候选列表里**只留中继**：
/// 两端各自按 2.5s 轮换，必须同时落在中继候选上才握得上手——继续掺着直连候选轮换
/// 会让两端反复错开（CI 里实测把收敛时间从 ~7s 拖到 ~28s，且概率性更久）。
/// 直连候选此刻已经整整试过 [`RELAY_AFTER_ROUNDS`] 轮全都失败，留着没有价值。
fn candidates_for(peer: &PeerRuntime, cache: &EndpointCache) -> Vec<SocketAddrV6> {
    if let Some(link) = peer.relay.as_ref()
        && let Some(session) = link.session
        && !link.upgrade_pending
    {
        return vec![session.endpoint];
    }
    build_candidates(&sources_for(peer, cache))
}

/// 推进中继逃生舱：该注册就注册，直连活了就注销，会话该续期就续期。
///
/// 只在这里做**决策**，实际的注册/注销扔到后台任务里跑——注册要等应答（最多 5s），
/// 绝不能阻塞每秒一次的主循环。
fn drive_relay(
    peer: &mut PeerRuntime,
    ctx: &Ctx,
    cache: &EndpointCache,
    relay_tx: &mpsc::Sender<RelayRegistered>,
    now: Instant,
) {
    let state = peer.fsm.state();
    let peer_name = peer.name.clone();
    if peer
        .relay
        .as_ref()
        .is_none_or(|link| link.control.is_empty())
    {
        return;
    }

    // 候选列表在下面这段里可能需要重算；重算要借 &peer，所以先结束对 link 的可变借用
    let mut recompute = false;
    {
        let Some(link) = peer.relay.as_mut() else {
            return;
        };
        match state {
            PunchState::Connected { endpoint } => {
                let Some(session) = link.session else { return };
                if endpoint != session.endpoint {
                    // 直连活了：立刻放掉中继会话（spec D5「直连恢复即退出中继」）
                    info!(
                        peer = %peer_name,
                        via = %link.via_name,
                        endpoint = %endpoint,
                        "已升级为直连，注销中继会话"
                    );
                    spawn_unregister(ctx, link, session);
                    link.session = None;
                    link.upgrade_pending = false;
                    link.last_register = None;
                    link.retry_after = None;
                    recompute = true;
                } else {
                    // 稳定在中继上：结束升级尝试，候选收回到只剩中继
                    if link.upgrade_pending {
                        debug!(peer = %peer_name, "升级直连未成功，继续走中继");
                        link.upgrade_pending = false;
                        recompute = true;
                    }
                    // 按节奏续期（服务端会话 TTL 180s）
                    let due = link
                        .last_register
                        .is_none_or(|t| now.duration_since(t) >= relay_client::REGISTER_INTERVAL);
                    if due && !link.pending {
                        link.pending = true;
                        spawn_register(ctx, link, &peer_name, relay_tx.clone());
                    }
                }
            }
            PunchState::Probing { rounds, .. } => {
                if link.session.is_some() || link.pending || rounds < RELAY_AFTER_ROUNDS {
                    return;
                }
                if link.retry_after.is_some_and(|t| now < t) {
                    return;
                }
                // 绝不静默降级：进中继一定伴随一条说明原因的日志
                info!(
                    peer = %peer_name,
                    via = %link.via_name,
                    rounds,
                    "直连候选已轮换 {rounds} 轮仍无握手，尝试经中继连接"
                );
                link.pending = true;
                spawn_register(ctx, link, &peer_name, relay_tx.clone());
            }
        }
    }
    if recompute {
        let candidates = candidates_for(&*peer, cache);
        // `Connected` 状态下 `set_candidates` 契约上只换列表、不产生动作
        let _ = peer.fsm.set_candidates(candidates, SystemTime::now());
    }
}

fn spawn_register(ctx: &Ctx, link: &RelayLink, peer_name: &str, tx: mpsc::Sender<RelayRegistered>) {
    let control = link.control.clone();
    let own = ctx.own_public.clone();
    let peer_public = link.peer_public.clone();
    let listen_port = ctx.listen_port;
    let relay_key = ctx.relay_key;
    let peer_key = peer_public.to_base64();
    let name = peer_name.to_owned();
    tokio::spawn(async move {
        let session =
            relay_client::register(&control, &own, &peer_public, listen_port, &relay_key).await;
        if session.is_none() {
            debug!(peer = %name, "中继注册未得到应答");
        }
        let _ = tx.send(RelayRegistered { peer_key, session }).await;
    });
}

fn spawn_unregister(ctx: &Ctx, link: &RelayLink, session: RelaySession) {
    let own = ctx.own_public.clone();
    let peer_public = link.peer_public.clone();
    let listen_port = ctx.listen_port;
    let relay_key = ctx.relay_key;
    tokio::spawn(async move {
        relay_client::unregister(session.control, &own, &peer_public, listen_port, &relay_key)
            .await;
    });
}

/// 中继注册任务回来了：更新会话并把中继 endpoint 交给候选列表。
async fn on_relay_registered(
    backend: &KernelBackend,
    ctx: &Ctx,
    nudge: &UdpSocket,
    cache: &mut EndpointCache,
    peers: &mut [PeerRuntime],
    done: RelayRegistered,
) {
    let Some(peer) = peers.iter_mut().find(|p| p.key_b64 == done.peer_key) else {
        return;
    };
    let peer_name = peer.name.clone();
    let Some(link) = peer.relay.as_mut() else {
        return;
    };
    link.pending = false;
    match done.session {
        Some(session) => {
            link.last_register = Some(Instant::now());
            link.retry_after = None;
            if link.session == Some(session) {
                return; // 续期成功，端口没变，无需重算候选
            }
            info!(
                peer = %peer_name,
                via = %link.via_name,
                endpoint = %session.endpoint,
                "中继会话就绪（数据仍是端到端加密，中继读不到内容）"
            );
            link.session = Some(session);
            let candidates = candidates_for(&*peer, cache);
            let actions = peer.fsm.set_candidates(candidates, SystemTime::now());
            apply_actions(backend, ctx, nudge, cache, &*peer, &actions).await;
        }
        None => {
            link.retry_after = Some(Instant::now() + RELAY_RETRY_COOLDOWN);
            warn!(
                peer = %peer_name,
                via = %link.via_name,
                cooldown_secs = RELAY_RETRY_COOLDOWN.as_secs(),
                "中继注册失败（超时或被拒绝），稍后重试；这条连接目前不通"
            );
        }
    }
}

/// LAN 上听到某节点的新地址：更新它的候选并按 FSM 的判断决定要不要立刻重试。
async fn on_lan_update(
    backend: &KernelBackend,
    ctx: &Ctx,
    nudge: &UdpSocket,
    cache: &mut EndpointCache,
    peers: &mut [PeerRuntime],
    update: LanUpdate,
) {
    let Some(peer) = peers.iter_mut().find(|p| p.key_b64 == update.peer_key) else {
        // 同网但不在本机配置里：这是给用户的可操作提示，不是错误
        debug!(
            peer = %update.peer_key,
            "LAN 上发现未配置的同网节点；`hextet peer add --public-key <它> 即可连上"
        );
        return;
    };
    if peer.discovered == update.endpoints {
        return;
    }
    info!(
        peer = %peer.name,
        endpoints = ?update.endpoints.iter().map(|e| e.to_string()).collect::<Vec<_>>(),
        "LAN 发现更新了该 peer 的地址"
    );
    peer.discovered = update.endpoints;

    // 正走在中继上时，光换候选列表不会有任何动作（`set_candidates` 刻意不打扰
    // `Connected` 的连接）。而 LAN 上出现新地址正是"该试试直连了"的证据，
    // 所以这里显式放开直连候选并让状态机离开中继 endpoint 去试一轮
    // ——这就是 docs/adr/ADR-0003 里说的事件驱动升级。
    let relayed_endpoint = relayed_via_endpoint(peer);
    if let Some(relay_ep) = relayed_endpoint
        && let Some(link) = peer.relay.as_mut()
    {
        link.upgrade_pending = true;
        info!(
            peer = %peer.name,
            "有了新的直连线索，尝试从中继升级回直连"
        );
        let candidates = candidates_for(&*peer, cache);
        let mut actions = peer.fsm.set_candidates(candidates, SystemTime::now());
        actions.extend(peer.fsm.retry_from(Some(relay_ep), SystemTime::now()));
        apply_actions(backend, ctx, nudge, cache, &*peer, &actions).await;
        return;
    }

    let candidates = candidates_for(&*peer, cache);
    let actions = peer.fsm.set_candidates(candidates, SystemTime::now());
    apply_actions(backend, ctx, nudge, cache, &*peer, &actions).await;
}

/// 该 peer 此刻是不是正连在中继会话 endpoint 上（是则返回那个 endpoint）。
fn relayed_via_endpoint(peer: &PeerRuntime) -> Option<SocketAddrV6> {
    let session = peer.relay.as_ref().and_then(|l| l.session)?;
    match peer.fsm.state() {
        PunchState::Connected { endpoint } if endpoint == session.endpoint => Some(endpoint),
        _ => None,
    }
}

fn peer_state_of(peer: &PeerRuntime, cache: &EndpointCache) -> PeerState {
    let sources = sources_for(peer, cache);
    let relay_session = peer.relay.as_ref().and_then(|l| l.session);
    let (punch_state, candidate_index, rounds) = match peer.fsm.state() {
        // 走在中继上就如实说 relayed，绝不显示成普通的 connected
        PunchState::Connected { endpoint }
            if relay_session.is_some_and(|s| s.endpoint == endpoint) =>
        {
            ("relayed", 0usize, 0u32)
        }
        PunchState::Connected { .. } => ("connected", 0usize, 0u32),
        PunchState::Probing {
            candidate_index,
            rounds,
        } => ("probing", candidate_index, rounds),
    };
    let endpoint = peer.fsm.current_candidate();
    PeerState {
        name: peer.name.clone(),
        public_key: peer.key_b64.clone(),
        address: peer.overlay,
        punch_state: punch_state.to_owned(),
        endpoint,
        endpoint_source: endpoint_source(endpoint, &sources).to_owned(),
        lan_endpoints: peer.discovered.len(),
        relay_via: if punch_state == "relayed" {
            peer.relay.as_ref().map(|l| l.via_name.clone())
        } else {
            None
        },
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
                // 中继会话 endpoint 不进缓存：那个端口是中继临时分配的，
                // 会话一结束就失效。把它记成 last_good 只会让下次启动先去试一个
                // 死地址，还会污染"上次直连成功在哪"这个真正有用的信息。
                if peer
                    .relay
                    .as_ref()
                    .and_then(|l| l.session)
                    .is_some_and(|s| s.endpoint == ep)
                {
                    info!(peer = %peer.name, endpoint = %ep, "经中继连通（不记入端点缓存）");
                    continue;
                }
                cache.record_good(&peer.key_b64, ep, unix_secs(SystemTime::now()));
                if let Err(e) = cache.save(&ctx.cache_path) {
                    warn!(path = %ctx.cache_path.display(), error = %e, "写端点缓存失败");
                }
                info!(peer = %peer.name, endpoint = %ep, "连接就绪（已记入端点缓存）");
            }
        }
    }
}
