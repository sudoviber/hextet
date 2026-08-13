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
#[cfg(not(target_os = "android"))]
use hextet_core::network::NetworkPrefix;
use hextet_core::network::{derive_lan_key, derive_probe_key, derive_relay_key};
use hextet_core::route::Ipv6Route;
#[cfg(not(target_os = "android"))]
use hextet_platform::setup_interface;
use hextet_platform::{AddrEvent, PlatformError, list_multicast_interfaces, watch_ipv6_addresses};
use hextet_wg::types::PeerSpec;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch};
use tracing::{debug, error, info, warn};

use crate::cache::EndpointCache;
use crate::candidates::{
    CandidateSources, DiscoveredEndpoints, MAX_CANDIDATES, Source, build_candidates, normalize,
};
use crate::ddns::{DdnsConfig, DdnsEvent};
use crate::dht::{DhtConfig, DhtControl, DhtEvent};
use crate::fsm::{Action, Observation, PeerFsm, PunchState};
use crate::gossip::{GossipConfig, GossipControl, GossipEvent};
use crate::lan::LanConfig;
use crate::members::{MemberRecord, MembersFile, site_of};
use crate::relay_client::{self, RelaySession};
use crate::relay_server::RelayPolicy;
use crate::route_manager::{RouteBackend, RouteManager};
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
    /// 这个 peer 通告的、在其背后可达的子网路由（配置静态声明）。
    routes: Vec<Ipv6Route>,
    /// 会合层当下发现的 endpoint（阶段 B：LAN 公告；阶段 D：gossip 转介），
    /// 每项带来源标签，按来源优先级排好序。
    discovered: Vec<(Source, SocketAddrV6)>,
    /// 中继逃生舱（spec D5）。
    relay: Option<RelayLink>,
    fsm: PeerFsm,
}

/// 平台路由后端的适配器：把 [`hextet_platform::add_route`]/`remove_route` 接进
/// [`RouteBackend`]，让 [`RouteManager`] 可以走同一条抽象、同时被 mock 覆盖。
struct PlatformRoutes;

impl RouteBackend for PlatformRoutes {
    async fn add_route(&self, interface: &str, route: Ipv6Route) -> Result<(), PlatformError> {
        hextet_platform::add_route(interface, route.prefix(), route.prefix_len()).await
    }

    async fn remove_route(&self, interface: &str, route: Ipv6Route) -> Result<(), PlatformError> {
        hextet_platform::remove_route(interface, route.prefix(), route.prefix_len()).await
    }
}

/// 循环期间不变的上下文。
struct Ctx {
    /// 用户/配置文件里的接口名（`hextet0`），用于人类可读的身份展示（日志、
    /// `state.json` 的 `interface` 字段）。
    interface: String,
    /// OS 层真实设备名（`WgBackend::apply` 返回值，ADR-0009 决策 3）。
    ///
    /// Linux 恒等于 [`Ctx::interface`]（内核 WG 设备名即配置名）；macOS 上是读回的
    /// `utunN`（配置名经 hextet0→utun 映射）。所有「按名操作设备」的调用
    /// （`status`/`set_peer_endpoint`/`add_peer`/`remove_peer`、路由增删、接口排除）
    /// 都必须用这个名字；`interface` 只用于展示/配置身份。
    device_name: String,
    node_address: Ipv6Addr,
    node_public_key: String,
    /// 本节点公钥（中继注册帧要用）。
    own_public: NodePublicKey,
    /// 本节点 WireGuard 监听端口（中继注册帧要用，见 docs/protocol/relay.md C-0）。
    listen_port: u16,
    /// 常驻 keepalive 秒数（`[node] keepalive`，`0` = 关闭）。gossip 准入成员时用同一个
    /// 值（与配置 peer 一致），不硬编码 25。见 ADR-0015。
    keepalive: u16,
    /// 中继控制帧的认证密钥。
    relay_key: [u8; 32],
    cache_path: PathBuf,
    state_path: PathBuf,
    /// gossip 准入成员表的持久化路径。
    members_path: PathBuf,
}

/// 启动守护进程，阻塞直到收到 SIGINT/SIGTERM。
///
/// 便捷入口（CLI / 系统服务走这条路径）：**自己创建并拥有** tokio runtime，然后
/// `block_on` 跑完整段 [`run_async`]。可嵌入场景（宿主已经持有 runtime，例如 Android
/// VpnService 线程）不要走这里——改用 [`spawn_on`] 把主循环挂到外部 runtime 上，
/// 避免在宿主线程里再 `Runtime::new()` + `block_on`（ADR-0012 决策 6）。
///
/// 内部用 [`tokio::sync::watch`] 做停机信号：在 runtime 上 spawn 一个小任务把
/// SIGINT/SIGTERM 映射成 `shutdown.send(true)`，主循环据此退出并清理。对外行为与
/// 旧实现（`ctrl_c`/`sigterm` 直接驱动 `select!`）完全一致——收到信号 → 干净退出 +
/// 移除通告路由。SIGTERM handler 注册失败仍像旧实现一样是致命错误（沿调用栈返回）。
pub fn run(config_path: &Path) -> anyhow::Result<()> {
    let rt = tokio::runtime::Runtime::new().context("创建 tokio runtime")?;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("注册 SIGTERM handler")?;
    rt.spawn(async move {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = sigterm.recv() => {}
        }
        let _ = shutdown_tx.send(true);
    });
    rt.block_on(run_async(
        config_path,
        shutdown_rx,
        std::sync::Arc::new(crate::backend::platform_default()),
    ))
}

/// 守护进程的控制句柄：宿主（例如 Android `VpnService`）通过它请求停机并等待主循环
/// 收尾。
///
/// 由 [`spawn_on`] 返回。宿主在 `onDestroy` 里先调 [`DaemonHandle::stop`] 触发停机
/// （主循环退出前会移除已装的通告路由），再 `await` [`DaemonHandle::wait`] 等它真正
/// 结束。停机信号走 [`tokio::sync::watch`]，非阻塞、幂等。
pub struct DaemonHandle {
    /// 停机信号发送端：`stop` 向它发 `true`，主循环在 `select!` 里观察到变化即退出。
    shutdown: watch::Sender<bool>,
    /// 主循环任务的句柄：`wait` 通过它等待任务（含退出清理）真正完成。
    join: tokio::task::JoinHandle<()>,
}

impl DaemonHandle {
    /// 非阻塞地请求停机。
    ///
    /// 向停机信号发 `true`，主循环会在下一轮 `select!` 里退出并执行退出清理（移除
    /// 已装的通告路由）。重复调用无害（`watch::Sender::send` 在值未变化时只是空操作）。
    pub fn stop(&self) {
        let _ = self.shutdown.send(true);
    }

    /// 等待主循环任务真正结束（含退出清理）。
    ///
    /// 消耗掉 `self`；返回时说明任务已退出、路由已清理完毕。任务内部已自行记录启动
    /// 期错误（`run_async` 的 `Err` 只会 `error!` 日志，不会 panic），故这里无需再处理
    /// `JoinError`。
    pub async fn wait(self) {
        let _ = self.join.await;
    }
}

/// 在**外部提供的** tokio runtime 上启动守护进程主循环，立即返回一个 [`DaemonHandle`]。
///
/// 与 [`run`] 相反：本函数不创建、不 `block_on`、也不接管 runtime。它把
/// [`run_async`] 作为任务 spawn 到调用方传入的 [`tokio::runtime::Handle`] 上，随即
/// 返回控制句柄；runtime 的创建、存活与回收都由宿主负责（ADR-0012 决策 6）。这正是
/// Android VpnService 的形态——`establish()` 跑在宿主自有线程上，engine 不能在这里
/// 新建 `Runtime` 或 `block_on`。
///
/// spawn 出去的任务**不再**自行注册 SIGINT/SIGTERM——停机改由 [`tokio::sync::watch`]
/// 信号驱动，宿主通过 [`DaemonHandle::stop`] 触发、[`DaemonHandle::wait`] 收尾
/// （Android 上即 `VpnService.onDestroy` 里 stop + wait）。启动期的致命错误（读配置、
/// 建后端、配接口等失败）仍会在任务内以 `error!` 记日志（而不是静默吞掉，`run` 则
/// 把同样的错误沿调用栈返回给 CLI）。真正的 start/status 同步控制面由 M7 后续片
/// （engine-FFI）在这一层之上补齐，本函数只交付「runtime 可注入 + 可停机」这一环。
///
/// 本函数是 [`spawn_with_backend`] 的薄封装：后端取
/// [`crate::backend::platform_default`]（`cfg(target_os)` 按平台选后端）。
pub fn spawn_on(
    handle: tokio::runtime::Handle,
    config_path: &Path,
) -> anyhow::Result<DaemonHandle> {
    spawn_with_backend(
        handle,
        config_path,
        std::sync::Arc::new(crate::backend::platform_default()),
    )
}

/// 在**外部提供的** tokio runtime 上、用**外部提供的**后端实例启动主循环，返回句柄。
///
/// 与 [`spawn_on`] 的差异只在后端来源：本函数把 `backend`（可能是已 `set_tun_fd`
/// 注入 fd 的**同一实例**，ADR-0014 D3/D4）原样交给 [`run_async`]，而不是在内部
/// `new()` 一个新后端。这是 Android engine-FFI 的 `spawn_daemon` 路径——fd 必须预
/// 注入到 `apply()` 实际使用的那个实例上，不能让 daemon 内部自建后端再期望外部注入 fd。
/// 其余语义（停机信号、错误日志、`DaemonHandle` 生命周期）与 [`spawn_on`] 完全一致。
pub fn spawn_with_backend(
    handle: tokio::runtime::Handle,
    config_path: &Path,
    backend: std::sync::Arc<dyn hextet_wg::WgBackend + Send + Sync>,
) -> anyhow::Result<DaemonHandle> {
    let config_path = config_path.to_path_buf();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let join = handle.spawn(async move {
        if let Err(e) = run_async(&config_path, shutdown_rx, backend).await {
            error!(error = %e, "daemon 任务退出并返回错误");
        }
    });
    Ok(DaemonHandle {
        shutdown: shutdown_tx,
        join,
    })
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

async fn run_async(
    config_path: &Path,
    mut shutdown: watch::Receiver<bool>,
    backend: std::sync::Arc<dyn hextet_wg::WgBackend + Send + Sync>,
) -> anyhow::Result<()> {
    let (cfg, id) = load_config_and_identity(config_path)?;
    let own = derive_node_addr(cfg.prefix, &id.public())?;

    ensure_state_dir(&cfg.node.state_dir)?;

    // 1) 数据面就位（与 `hextet up` 同一条路径，两步都幂等）。
    // 后端由调用方注入（`run`/`spawn_on` 走 `platform_default()`；Android engine-FFI 走
    // `spawn_with_backend` 传入已 `set_tun_fd` 的同一实例，ADR-0014 D3/D4）。`Arc<dyn
    // WgBackend + Send + Sync>` 供打洞主循环与 HTTP 状态服务共享**同一实例**——用户态
    // 后端持有内部注册表 + 设备句柄，不 `Clone`。
    let spec = build_device_spec(&cfg, &id);
    // `apply` 返回 OS 层真实设备名（ADR-0009 决策 3）。Linux 恒等于配置名；macOS 是读回的
    // 真实 `utunN`。真实名只用于「按名操作设备」；配置名 `ctx.interface` 保留为人类/配置身份。
    let real_name = backend
        .apply(&spec)
        .context("配置 WireGuard 设备（需要 root/CAP_NET_ADMIN）")?;
    // Linux-only 断言：内核后端恒返回配置名。macOS 返回 `utunN`（≠ `hextet0`），此断言不成立。
    #[cfg(target_os = "linux")]
    debug_assert_eq!(real_name, cfg.node.interface, "Linux 内核后端恒返回配置名");
    // Android：`VpnService.Builder` 已 addAddress/addRoute，daemon 不再经 platform 配一遍
    // （ADR-0014 D1）；其余平台经 platform 配 overlay 地址与 MTU。
    #[cfg(not(target_os = "android"))]
    {
        setup_interface(
            &real_name,
            own.address,
            NetworkPrefix::PREFIX_LEN,
            cfg.node.mtu,
        )
        .await
        .context("配置接口地址/MTU")?;
    }
    // macOS：显式加 overlay /48 路由，与 Linux「内核配地址即自动下直连 /48 路由」语义对齐
    // （ADR-0009 决策 4，与 `hextet up` 同路径）。设备随 daemon 进程存活，退出即随 backend
    // drop 自动销毁，无需显式移除。
    #[cfg(target_os = "macos")]
    hextet_platform::add_route(&real_name, cfg.prefix.network(), NetworkPrefix::PREFIX_LEN)
        .await
        .context("添加 overlay /48 路由")?;

    let ctx = Ctx {
        interface: cfg.node.interface.clone(),
        device_name: real_name,
        node_address: own.address,
        node_public_key: id.public().to_base64(),
        own_public: id.public(),
        listen_port: cfg.node.listen_port,
        keepalive: cfg.node.keepalive,
        relay_key: derive_relay_key(&cfg.network_key),
        cache_path: cfg.node.state_dir.join("endpoints.json"),
        state_path: cfg.node.state_dir.join("state.json"),
        members_path: cfg.node.state_dir.join("members.json"),
    };

    info!(
        interface = %ctx.interface,
        device = %ctx.device_name,
        address = %own.address,
        peers = cfg.peers.len(),
        "daemon 启动"
    );

    // 2) 端点缓存 + 成员表 + 每 peer 运行时
    let mut cache = EndpointCache::load(&ctx.cache_path);
    let mut members = MembersFile::load(&ctx.members_path);
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
                routes: p.routes.clone(),
                discovered: Vec::new(),
                relay,
                fsm: PeerFsm::new(candidates, start),
            }
        })
        .collect();

    // 2.5) 把 gossip 准入的成员（不在配置文件里的）补进运行时 peer 列表：
    // 它们靠 gossip 转介发现地址，不占配置里的 [[peers]]，也不需要显式 relay。
    let known: std::collections::HashSet<String> =
        peers.iter().map(|p| p.key_b64.clone()).collect();
    for m in &members.members {
        if known.contains(&m.public_key) {
            continue;
        }
        let Ok(node_key) = hextet_core::identity::NodePublicKey::from_base64(&m.public_key) else {
            warn!(key = %m.public_key, "成员表里的公钥非法，跳过");
            continue;
        };
        let key_b64 = m.public_key.clone();
        let entry = cache.entry(&key_b64);
        let cached = entry.map(|e| e.seen.as_slice()).unwrap_or(&[]);
        let candidates = build_candidates(&CandidateSources {
            last_good: entry.and_then(|e| e.last_good),
            discovered: &[],
            configured: &[],
            cached,
            relay: None,
        });
        peers.push(PeerRuntime {
            name: m.name.clone(),
            key_b64,
            wg_public: node_key.wg_public_bytes(),
            overlay: m.address,
            configured: Vec::new(),
            routes: Vec::new(),
            discovered: Vec::new(),
            relay: None,
            fsm: PeerFsm::new(candidates, start),
        });
    }

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
    let (lan_tx, mut lan_rx) = mpsc::channel::<DiscoveredEndpoints>(64);
    let (lan_kick_tx, lan_kick_rx) = mpsc::channel::<()>(4);
    if cfg.node.lan_discovery {
        match list_multicast_interfaces(Some(&ctx.device_name)).await {
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
                    exclude_interface: ctx.device_name.clone(),
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

    // 3.95) 隧道内 gossip（会合兜底链第 ④ 层）：端点广播 + peer 转介 + 成员/吊销
    let (gossip_tx, mut gossip_rx) = mpsc::channel::<GossipEvent>(64);
    let (gossip_ctl_tx, gossip_ctl_rx) = mpsc::channel::<GossipControl>(4);
    let (gossip_kick_tx, gossip_kick_rx) = mpsc::channel::<()>(4);
    {
        let gossip_targets: Vec<Ipv6Addr> = peers.iter().map(|p| p.overlay).collect();
        let gossip_cfg = GossipConfig {
            port: cfg.node.gossip_port,
            own_address: own.address,
            prefix: cfg.prefix,
            own_identity: id,
            listen_port: cfg.node.listen_port,
            exclude_interface: ctx.device_name.clone(),
            targets: gossip_targets,
        };
        info!(
            port = cfg.node.gossip_port,
            "隧道内 gossip 已接线（端点广播 + peer 转介 + 成员）"
        );
        tokio::spawn(async move {
            match crate::gossip::serve(gossip_cfg, gossip_tx, gossip_ctl_rx, gossip_kick_rx).await {
                Ok(()) => debug!("gossip 正常结束"),
                Err(e) => warn!(error = %e, "gossip 退出：会合第 ④ 层不可用"),
            }
        });
    }

    // 3.98) DHT 会合（会合兜底链第 ⑤ 层）：控制面弱依赖 IPv4 出站，尽力而为
    let (dht_tx, mut dht_rx) = mpsc::channel::<DhtEvent>(64);
    let (dht_ctl_tx, dht_ctl_rx) = mpsc::channel::<DhtControl>(4);
    let (dht_kick_tx, dht_kick_rx) = mpsc::channel::<()>(4);
    if cfg.node.dht {
        let dht_peers: Vec<String> = peers.iter().map(|p| p.key_b64.clone()).collect();
        let dht_cfg = DhtConfig {
            dht_key: hextet_discovery::record::derive_dht_key(&cfg.network_key),
            own_public: ctx.own_public.clone(),
            listen_port: cfg.node.listen_port,
            exclude_interface: ctx.device_name.clone(),
            nodes_path: ctx.state_path.with_file_name("dht-nodes.json"),
            peers: dht_peers,
        };
        info!("DHT 会合已接线（发布 + 查询，控制面弱依赖 IPv4）");
        tokio::spawn(async move {
            match crate::dht::serve(dht_cfg, dht_tx, dht_ctl_rx, dht_kick_rx).await {
                Ok(()) => debug!("DHT 会合正常结束"),
                Err(e) => warn!(error = %e, "DHT 会合不可用：会合第 ⑤ 层降级（不影响数据面）"),
            }
        });
    } else {
        info!("DHT 会合已关闭（[node] dht = false）");
        drop(dht_tx);
        drop(dht_ctl_rx);
        drop(dht_kick_rx);
    }

    // 3.985) DDNS 会合（会合兜底链第 ⑥ 层）：自托管 DDNS，尽力而为
    let (ddns_tx, mut ddns_rx) = mpsc::channel::<DdnsEvent>(64);
    let (ddns_kick_tx, ddns_kick_rx) = mpsc::channel::<()>(4);
    if let Some(ddns_settings) = &cfg.ddns {
        if ddns_settings.enabled {
            let ddns_cfg = DdnsConfig {
                update_url: ddns_settings.update_url.clone(),
                port: ddns_settings.port,
                exclude_interface: ctx.device_name.clone(),
                peers: crate::ddns::ddns_peers(&cfg.peers),
            };
            info!("DDNS 会合已接线（发布 + 查询，自托管兜底）");
            tokio::spawn(async move {
                match crate::ddns::serve(ddns_cfg, ddns_tx, ddns_kick_rx).await {
                    Ok(()) => debug!("DDNS 会合正常结束"),
                    Err(e) => warn!(error = %e, "DDNS 会合不可用：会合第 ⑥ 层降级（不影响数据面）"),
                }
            });
        } else {
            info!("DDNS 会合已关闭（[ddns] enabled = false）");
            drop(ddns_tx);
            drop(ddns_kick_rx);
        }
    } else {
        debug!("未配置 [ddns] 段，跳过 DDNS 会合");
        drop(ddns_tx);
        drop(ddns_kick_rx);
    }

    // 3.99) HTTP 状态服务（切片 B2）：把 axum 状态服务器接进常驻循环，一边打洞一边
    // serve `/healthz` + `/api/status`。仅当 [node] http_addr 与 http_port 成对配置时启用。
    // cfg 在此处被 move 进 router（这是它最后一次被读；此后主循环只用 Ctx，不再读 cfg）。
    let http_addr = cfg.node.http_addr;
    let http_port = cfg.node.http_port;
    if let (Some(addr), Some(port)) = (http_addr, http_port) {
        let router = crate::http::router(std::sync::Arc::clone(&backend), cfg);
        let bind = SocketAddrV6::new(addr, port, 0, 0);
        tokio::spawn(async move {
            match tokio::net::TcpListener::bind(bind).await {
                Ok(listener) => {
                    info!(addr = %addr, port = port, "HTTP 状态服务已启动");
                    // axum::serve 常驻（listener 出错才返回）；失败只 warn，数据面不受影响
                    if let Err(e) = axum::serve(listener, router).await {
                        warn!(addr = %addr, port = port, error = %e, "HTTP 状态服务退出");
                    }
                }
                Err(e) => warn!(
                    addr = %addr,
                    port = port,
                    error = %e,
                    "绑定 HTTP 端口失败，跳过状态服务（数据面不受影响）"
                ),
            }
        });
    }

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
        apply_actions(&*backend, &ctx, &nudge, &mut cache, &*peer, &actions).await;
    }

    let mut ticker = tokio::time::interval(TICK);

    // site-to-site：跟踪并精确增删每个 peer 的通告路由（后端恒为平台实现，见
    // `PlatformRoutes`；接口名用 OS 层真实设备名，见 `Ctx::device_name`）
    let mut route_mgr = RouteManager::new();

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                // 新连上一个 peer：立刻补发一轮 gossip 广播。转介的常见竞态是「R 收到 B 的
                // 条目时 A↔R 隧道还没起来，R 转给 A 的那包因 Destination address required
                // 被丢掉，要等 30s 周期才重发」。连接就绪正是隧道刚打通的时刻，踢一脚让
                // 学到的条目立刻重发，把首次转介从「最长 30s」压回「连接后即达」。
                if tick_once(&*backend, &ctx, &nudge, &mut cache, &mut peers, &relay_tx, &mut route_mgr).await {
                    let _ = gossip_kick_tx.try_send(());
                }
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
                    apply_actions(&*backend, &ctx, &nudge, &mut cache, &*peer, &actions).await;
                }
                // 本机换了地址 → 立刻补发一条 LAN 公告 + 一条 gossip 广播 + 一条 DHT 重发 +
                // 一条 DDNS 更新，别让同 LAN / 已连的对端等一个周期。通道满或已关闭都无所谓：
                // 周期兜底。
                let _ = lan_kick_tx.try_send(());
                let _ = gossip_kick_tx.try_send(());
                let _ = dht_kick_tx.try_send(());
                let _ = ddns_kick_tx.try_send(());
                info!(coalesced = extra, "地址变化：已对所有 peer 重新握手/nudge");
            }
            Some(update) = lan_rx.recv() => {
                on_discovered(&*backend, &ctx, &nudge, &mut cache, &mut peers, update).await;
            }
            Some(event) = gossip_rx.recv() => {
                match event {
                    GossipEvent::Discovered(d) => {
                        on_discovered(&*backend, &ctx, &nudge, &mut cache, &mut peers, d).await;
                    }
                    other => {
                        on_membership_event(&*backend, &ctx, &mut peers, &mut members, other, &gossip_ctl_tx, &dht_ctl_tx).await;
                    }
                }
            }
            Some(event) = dht_rx.recv() => {
                match event {
                    DhtEvent::Discovered(d) => {
                        on_discovered(&*backend, &ctx, &nudge, &mut cache, &mut peers, d).await;
                    }
                }
            }
            Some(event) = ddns_rx.recv() => {
                match event {
                    DdnsEvent::Discovered(d) => {
                        on_discovered(&*backend, &ctx, &nudge, &mut cache, &mut peers, d).await;
                    }
                }
            }
            Some(done) = relay_rx.recv() => {
                on_relay_registered(&*backend, &ctx, &nudge, &mut cache, &mut peers, done).await;
            }
            _ = shutdown.changed() => {
                info!("收到停机信号，准备退出");
                break;
            }
        }
    }

    // 退出前把已装的通告路由全部移除（接口保留，但路由不该指向一个已停止的守护进程）
    if let Err(e) = route_mgr
        .remove_all(&PlatformRoutes, &ctx.device_name)
        .await
    {
        warn!(interface = %ctx.device_name, error = %e, "退出时移除通告路由失败");
    }
    info!(
        interface = %ctx.interface,
        "daemon 退出（接口保留，用 `hextet down` 拆除）"
    );
    Ok(())
}

async fn tick_once(
    backend: &(dyn hextet_wg::WgBackend + Send + Sync),
    ctx: &Ctx,
    nudge: &UdpSocket,
    cache: &mut EndpointCache,
    peers: &mut [PeerRuntime],
    relay_tx: &mpsc::Sender<RelayRegistered>,
    route_mgr: &mut RouteManager,
) -> bool {
    let statuses = match backend.status(&ctx.device_name) {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, "读取 WireGuard 状态失败，跳过本 tick");
            return false;
        }
    };
    let by_key: HashMap<[u8; 32], &hextet_wg::types::PeerStatus> =
        statuses.iter().map(|s| (s.wg_public, s)).collect();

    let now = SystemTime::now();
    let mut any_connected = false;
    let mut peer_states = Vec::with_capacity(peers.len());
    for peer in peers.iter_mut() {
        let observed = by_key.get(&peer.wg_public);
        let obs = Observation {
            last_handshake: observed.and_then(|s| s.last_handshake),
            kernel_endpoint: observed.and_then(|s| kernel_endpoint(s.endpoint)),
        };
        let actions = peer.fsm.tick(now, obs);
        any_connected |= actions.iter().any(|a| matches!(a, Action::MarkGood(_)));
        apply_actions(backend, ctx, nudge, cache, &*peer, &actions).await;
        drive_relay(peer, ctx, cache, relay_tx, Instant::now());
        // site-to-site：只有连上才装路由，断开/重连期间清掉，避免流量黑洞
        sync_peer_routes(route_mgr, ctx, peer).await;
        peer_states.push(peer_state_of(&*peer, cache, route_mgr));
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
    any_connected
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
    backend: &(dyn hextet_wg::WgBackend + Send + Sync),
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
            let mut actions = peer.fsm.set_candidates(candidates, SystemTime::now());
            // 已连但会合层刚听到一个与当前连接**不同**的地址：对端可能已换址（PPPoE 重拨 /
            // 双端同时换前缀）。事件驱动地切过去试，而不是等 180s 握手失效才回头用新列表
            // ——与中继"升级回直连"是同一个道理（ADR-0003）。
            if actions.is_empty()
                && let Some(current) = peer.fsm.current_candidate()
                && peer
                    .discovered
                    .iter()
                    .any(|(_, ep)| normalize(*ep) != current)
            {
                actions = peer.fsm.retry_from(Some(current), SystemTime::now());
            }
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

/// 会合层听到某节点的新地址（LAN 或 gossip 转介）：更新它的候选并按 FSM 判断
/// 要不要立刻重试。
async fn on_discovered(
    backend: &(dyn hextet_wg::WgBackend + Send + Sync),
    ctx: &Ctx,
    nudge: &UdpSocket,
    cache: &mut EndpointCache,
    peers: &mut [PeerRuntime],
    update: DiscoveredEndpoints,
) {
    let Some(peer) = peers.iter_mut().find(|p| p.key_b64 == update.peer_key) else {
        // 同网/转介但不在本机配置、也不是 gossip 准入的成员：可操作提示，不是错误
        debug!(
            peer = %update.peer_key,
            source = update.source.as_str(),
            "会合层发现未配置的同网节点；`hextet peer add --public-key <它> 即可连上"
        );
        return;
    };
    // 用该来源的新集合替换旧集合，其余来源保留，再按来源优先级排序
    let new_source = update.source;
    let new_eps = update.endpoints;
    info!(
        peer = %peer.name,
        source = new_source.as_str(),
        endpoints = ?new_eps.iter().map(|e| e.to_string()).collect::<Vec<_>>(),
        "会合层更新了该 peer 的地址"
    );
    // 先记下这次刚听到的地址集合再合并进 discovered：漫游判定要拿它和当前
    // connected endpoint 比（见下面非中继分支）。
    let fresh_eps = new_eps.clone();
    peer.discovered.retain(|(s, _)| *s != new_source);
    peer.discovered
        .extend(new_eps.into_iter().map(|e| (new_source, e)));
    peer.discovered.sort_by_key(|(s, _)| s.priority());

    // 正走在中继上时，光换候选列表不会有任何动作（`set_candidates` 刻意不打扰
    // `Connected` 的连接）。而会合层出现新地址正是"该试试直连了"的证据，
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
    let mut actions = peer.fsm.set_candidates(candidates, SystemTime::now());
    // 漫游跟随（会合层版）：直连的 peer 收到一条不再包含当前 endpoint 的新公告，
    // 说明对端已经搬到新地址。两侧同时换前缀时，靠"发已认证包让对方内核 roaming"
    // 的那条路径够不到对方（双方都往对方的旧地址发包），这条是唯一恢复通道。
    if let PunchState::Connected { endpoint } = peer.fsm.state()
        && !fresh_eps.is_empty()
        && !fresh_eps.iter().any(|e| normalize(*e) == endpoint)
    {
        actions.extend(peer.fsm.retry_from(Some(endpoint), SystemTime::now()));
    }
    apply_actions(backend, ctx, nudge, cache, &*peer, &actions).await;
}

/// gossip 成员/吊销事件：运行时增删 peer + 落盘 + 更新 gossip 广播目标。
///
/// （端点转介走 [`on_discovered`]，在 select 循环里单独分支。）
async fn on_membership_event(
    backend: &(dyn hextet_wg::WgBackend + Send + Sync),
    ctx: &Ctx,
    peers: &mut Vec<PeerRuntime>,
    members: &mut MembersFile,
    event: GossipEvent,
    gossip_ctl_tx: &mpsc::Sender<GossipControl>,
    dht_ctl_tx: &mpsc::Sender<DhtControl>,
) {
    match event {
        GossipEvent::MemberAdmitted {
            node,
            name,
            address,
        } => {
            let key_b64 = node.to_base64();
            // 已吊销的 node 不要再准入（handle_datagram 已拦一层，这里兜底）
            if let Some(existing) = peers.iter().find(|p| p.key_b64 == key_b64) {
                debug!(peer = %existing.name, "member 条目对应的节点已在运行时表中，忽略");
                return;
            }
            let wg_public = node.wg_public_bytes();
            let candidates = build_candidates(&CandidateSources {
                last_good: None,
                discovered: &[],
                configured: &[],
                cached: &[],
                relay: None,
            });
            info!(peer = %name, address = %address, "gossip 准入新成员");
            // 数据面先加 peer（AllowedIPs = 其 /64 site），再进运行时表
            let _ = backend.add_peer(
                &ctx.device_name,
                &PeerSpec {
                    wg_public,
                    endpoint: None,
                    allowed_ips: vec![(site_of(address), 64)],
                    persistent_keepalive: (ctx.keepalive != 0).then_some(ctx.keepalive),
                },
            );
            peers.push(PeerRuntime {
                name: name.clone(),
                key_b64: key_b64.clone(),
                wg_public,
                overlay: address,
                configured: Vec::new(),
                routes: Vec::new(),
                discovered: Vec::new(),
                relay: None,
                fsm: PeerFsm::new(candidates, SystemTime::now()),
            });
            members.upsert(MemberRecord {
                name,
                public_key: key_b64,
                address,
            });
            if let Err(e) = members.save(&ctx.members_path) {
                warn!(path = %ctx.members_path.display(), error = %e, "写成员表失败");
            }
            // 新成员要成为 gossip 的广播目标 + DHT 的查询目标
            let targets: Vec<Ipv6Addr> = peers.iter().map(|p| p.overlay).collect();
            let _ = gossip_ctl_tx
                .send(GossipControl::UpdateTargets(targets))
                .await;
            let _ = dht_ctl_tx
                .send(DhtControl::UpdatePeers(
                    peers.iter().map(|p| p.key_b64.clone()).collect(),
                ))
                .await;
        }
        GossipEvent::Revoked { node } => {
            let key_b64 = node.to_base64();
            let wg_public = node.wg_public_bytes();
            // 数据面立即移除（拒绝后续流量）
            let _ = backend.remove_peer(&ctx.device_name, &wg_public);
            if let Some(idx) = peers.iter().position(|p| p.key_b64 == key_b64) {
                info!(peer = %peers[idx].name, "gossip 吊销：已从数据面移除该 peer");
                peers.remove(idx);
            }
            if members.remove(&key_b64) {
                if let Err(e) = members.save(&ctx.members_path) {
                    warn!(path = %ctx.members_path.display(), error = %e, "写成员表失败");
                }
            }
            let targets: Vec<Ipv6Addr> = peers.iter().map(|p| p.overlay).collect();
            let _ = gossip_ctl_tx
                .send(GossipControl::UpdateTargets(targets))
                .await;
            let _ = dht_ctl_tx
                .send(DhtControl::UpdatePeers(
                    peers.iter().map(|p| p.key_b64.clone()).collect(),
                ))
                .await;
        }
        GossipEvent::Discovered(_) => unreachable!("端点转介在 select 循环里单独处理"),
    }
}

/// 该 peer 此刻是不是正连在中继会话 endpoint 上（是则返回那个 endpoint）。
fn relayed_via_endpoint(peer: &PeerRuntime) -> Option<SocketAddrV6> {
    let session = peer.relay.as_ref().and_then(|l| l.session)?;
    match peer.fsm.state() {
        PunchState::Connected { endpoint } if endpoint == session.endpoint => Some(endpoint),
        _ => None,
    }
}

/// 按 peer 当前连接状态同步它的通告路由：`Connected` 时装上，否则清掉。
///
/// 路由只有在"数据面真能把这个前缀送进隧道"时才有意义——打洞中/断连时装着
/// 等于把一个黑洞写进路由表。失败只 warn（下一 tick 会重试，不打断主循环）。
async fn sync_peer_routes(route_mgr: &mut RouteManager, ctx: &Ctx, peer: &PeerRuntime) {
    let connected = matches!(peer.fsm.state(), PunchState::Connected { .. });
    let desired: &[Ipv6Route] = if connected { &peer.routes } else { &[] };
    match route_mgr
        .sync(&PlatformRoutes, &ctx.device_name, &peer.key_b64, desired)
        .await
    {
        Ok(outcome) => {
            for r in &outcome.added {
                info!(peer = %peer.name, route = %r, "安装通告路由（site-to-site）");
            }
            for r in &outcome.removed {
                info!(peer = %peer.name, route = %r, "移除通告路由（site-to-site）");
            }
        }
        Err(e) => warn!(
            peer = %peer.name,
            error = %e,
            "同步通告路由失败（下一 tick 重试）"
        ),
    }
}

fn peer_state_of(peer: &PeerRuntime, cache: &EndpointCache, route_mgr: &RouteManager) -> PeerState {
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
    let lan_endpoints = peer
        .discovered
        .iter()
        .filter(|(s, _)| *s == Source::Lan)
        .count();
    let gossip_endpoints = peer
        .discovered
        .iter()
        .filter(|(s, _)| *s == Source::Gossip)
        .count();
    PeerState {
        name: peer.name.clone(),
        public_key: peer.key_b64.clone(),
        address: peer.overlay,
        punch_state: punch_state.to_owned(),
        endpoint,
        endpoint_source: endpoint_source(endpoint, &sources).to_owned(),
        lan_endpoints,
        gossip_endpoints,
        relay_via: if punch_state == "relayed" {
            peer.relay.as_ref().map(|l| l.via_name.clone())
        } else {
            None
        },
        routes: route_mgr.routes_of(&peer.key_b64).to_vec(),
        candidates: peer.fsm.candidates_len(),
        candidate_index,
        rounds,
    }
}

async fn apply_actions(
    backend: &(dyn hextet_wg::WgBackend + Send + Sync),
    ctx: &Ctx,
    nudge: &UdpSocket,
    cache: &mut EndpointCache,
    peer: &PeerRuntime,
    actions: &[Action],
) {
    for action in actions {
        match *action {
            Action::SetEndpoint(ep) => {
                match backend.set_peer_endpoint(&ctx.device_name, &peer.wg_public, ep) {
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

#[cfg(test)]
mod tests {
    use super::spawn_on;

    /// `stop()` 立即返回、`wait()` 在任务快速失败（配置路径不存在）后不挂起地完成。
    ///
    /// 用不存在的配置路径让 `run_async` 在 `load_config_and_identity` 处立刻失败，避免
    /// 真建 WG 设备 / 要 root；`stop()` 走 watch 信号（此刻可能已无接收者，但 `send`
    /// 只是空操作），`wait()` 等任务退出，两者都不能挂起。
    #[test]
    fn stop_and_wait_complete_without_hanging() {
        let rt = tokio::runtime::Runtime::new().expect("创建测试 runtime");
        let handle = rt.handle().clone();
        let daemon = spawn_on(
            handle,
            std::path::Path::new("/definitely/not/a/hextet.toml"),
        )
        .expect("spawn_on 应立即返回 Ok");
        daemon.stop();
        rt.block_on(daemon.wait());
        rt.shutdown_timeout(std::time::Duration::from_secs(5));
    }
}
