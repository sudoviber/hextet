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
use hextet_core::config::{DdnsProvider, load_config_and_identity};
use hextet_core::defaults::LAN_MULTICAST_GROUP;
use hextet_core::identity::NodePublicKey;
use hextet_core::network::NetworkPrefix;
use hextet_core::network::{derive_lan_key, derive_probe_key, derive_relay_key};
use hextet_core::route::{Ipv6Route, allowed_ips_for};
use hextet_discovery::ddns::derive_ddns_key;
use hextet_discovery::ddns::updater::DdnsUpdater;
use hextet_platform::{
    AddrEvent, PlatformError, list_multicast_interfaces, setup_interface, watch_ipv6_addresses,
};
use hextet_wg::types::PeerSpec;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::cache::EndpointCache;
use crate::candidates::{
    CandidateSources, DiscoveredEndpoints, MAX_CANDIDATES, Source, build_candidates, normalize,
};
use crate::ddns::{DdnsConfig, DdnsControl, DdnsEvent, DdnsPeer};
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

/// 升级回直连失败后最多重试几次。
///
/// 升级是事件驱动的（LAN/gossip 只在端点**集合变化**时喂新线索，之后同集合的公告
/// 被 dedup），所以一次直连握手没赶上就会永远卡在中继上。给一个有限的重试窗口
/// （驱动循环每个 tick 里、FSM 弹回中继时最多试一次），既修掉这个 flake，又不至于
/// 在「直连确实回不来」时无限刷 `retry_from`（netns-e2e-relay.sh 的升级直连阶段
/// 实跑 ~25% 偶发超时，根因在此）。
const UPGRADE_MAX_RETRIES: u32 = 8;

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
    /// 升级失败后已重试的次数（上限 [`UPGRADE_MAX_RETRIES`]）。
    upgrade_retries: u32,
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
    /// 这个 peer 的 DDNS 会合 FQDN（配置里 `[[peers]] ddns`；gossip 准入的成员为 None）。
    ddns: Option<String>,
    /// 会合层当下发现的 endpoint（阶段 B：LAN 公告；阶段 D：gossip 转介），
    /// 每项带来源标签，按来源优先级排好序。
    discovered: Vec<(Source, SocketAddrV6)>,
    /// 中继逃生舱（spec D5）。
    relay: Option<RelayLink>,
    /// 按需连接（`keepalive = 0`）：关掉主动 nudge，等出站流量触发 WG 握手省电。
    /// 打洞状态机照常轮换/跟随，只是不主动发握手包。
    on_demand: bool,
    /// 该 peer 的 WG 持久 keepalive 秒数（`None` = 关闭）。`Rehandshake` 重加 peer
    /// 时要原样带回去，否则 flush 会话会把 keepalive 丢掉。
    keepalive: Option<u16>,
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
    /// WG 持久 keepalive 秒数（`0` = 关闭，移动端按需连接）。
    keepalive: u16,
    /// 中继控制帧的认证密钥。
    relay_key: [u8; 32],
    cache_path: PathBuf,
    state_path: PathBuf,
    /// gossip 准入成员表的持久化路径。
    members_path: PathBuf,
}

/// 一个已 spawn 到后台的守护进程句柄（供 Windows service / M7 Android FFI 在进程内
/// 运行并优雅停机）。
pub struct DaemonHandle {
    shutdown_tx: mpsc::Sender<()>,
    task: tokio::task::JoinHandle<anyhow::Result<()>>,
}

impl DaemonHandle {
    /// 请求优雅停机并等待守护进程退出（teardown 含移除通告路由）。
    pub async fn shutdown(self) -> anyhow::Result<()> {
        let _ = self.shutdown_tx.send(()).await;
        self.task.await.context("daemon 任务 join 失败")?
    }
}

/// 数据面传输：桌面平台按 `cfg(target_os)` 选默认后端（内核 WG / gotatun 命名 TUN），
/// Android 用 `VpnService` 返回的裸 fd（M7 切片 B/C）。
///
/// `Platform` 只在桌面三平台可用（`platform_default` 是 linux/macos/windows 的）；
/// Android 只有 `Fd` 变体——`run_async` 的 match 里 `Platform` 分支也按同一 cfg 门控，
/// 保证本 crate 在 Android 上能编译（M7 的 Rust 侧编译前置）。
enum Transport {
    /// 平台默认（Linux 内核 WG；macOS/Windows gotatun 命名 TUN）。
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    Platform,
    /// 裸 fd（Android VpnService）：`apply_with_fd` 构建数据面，跳过 `setup_interface`
    /// （VpnService 已配好地址/MTU）。
    #[cfg(unix)]
    Fd { fd: std::os::fd::RawFd, mtu: u16 },
}

/// 在**当前 tokio runtime** 上后台 spawn 守护进程，返回停机句柄。
///
/// 调用方必须已处于 tokio runtime 上下文（Windows service / Android 的进程内运行）。
/// 阻塞式前台运行请用 [`run`]。仅桌面三平台（Android 用 [`spawn_with_fd`]）。
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub fn spawn(config_path: &Path) -> anyhow::Result<DaemonHandle> {
    spawn_with_transport(config_path, Transport::Platform)
}

/// 用裸 fd（Android VpnService）spawn 守护进程（M7 切片 B/C）。`fd` 是
/// `VpnService.Builder.establish()` 返回的 fd，`mtu` 是 VpnService 配的 MTU。
#[cfg(unix)]
pub fn spawn_with_fd(
    config_path: &Path,
    tun_fd: std::os::fd::RawFd,
    mtu: u16,
) -> anyhow::Result<DaemonHandle> {
    spawn_with_transport(config_path, Transport::Fd { fd: tun_fd, mtu })
}

fn spawn_with_transport(config_path: &Path, transport: Transport) -> anyhow::Result<DaemonHandle> {
    let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>(1);
    let path = config_path.to_owned();
    let task = tokio::spawn(async move { run_async(&path, shutdown_rx, transport).await });
    Ok(DaemonHandle { shutdown_tx, task })
}

/// 启动守护进程，阻塞直到收到 SIGINT/SIGTERM。仅桌面三平台（Android 走
/// [`spawn_with_fd`] 进程内运行）。
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub fn run(config_path: &Path) -> anyhow::Result<()> {
    let rt = tokio::runtime::Runtime::new().context("创建 tokio runtime")?;
    rt.block_on(async {
        let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>(1);
        // 把 SIGINT/SIGTERM 桥接到停机通道——`run_async` 只认通道、不直接碰信号，
        // 这样 `spawn`（进程内）与 `run`（前台）共用同一主循环。
        tokio::spawn(signal_shutdown_bridge(shutdown_tx));
        run_async(config_path, shutdown_rx, Transport::Platform).await
    })
}

/// 等待 SIGINT（Ctrl+C）或 SIGTERM（仅 Unix），任一到达即向停机通道发一次信号。
///
/// 只有前台 [`run`] 用（桌面三平台）；Android 走 [`spawn_with_fd`] 进程内运行、由宿主
/// 管理生命周期，不需要信号桥。
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
async fn signal_shutdown_bridge(tx: mpsc::Sender<()>) {
    #[cfg(unix)]
    let terminate = {
        use tokio::signal::unix::{SignalKind, signal};
        let mut sig = signal(SignalKind::terminate()).expect("注册 SIGTERM handler");
        async move { sig.recv().await }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::pin!(terminate);
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = &mut terminate => {}
    }
    let _ = tx.send(()).await;
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
    mut shutdown_rx: mpsc::Receiver<()>,
    transport: Transport,
) -> anyhow::Result<()> {
    let (cfg, id) = load_config_and_identity(config_path)?;
    let own = derive_node_addr(cfg.prefix, &id.public())?;

    ensure_state_dir(&cfg.node.state_dir)?;

    // 1) 数据面就位。用 `Arc<dyn WgBackend + Send + Sync>` 包一层，供打洞主循环与 HTTP
    // 状态服务共享**同一实例**——`UserspaceBackend` 持有 `Mutex` 注册表 + `DeviceHandle`，
    // 不 `Clone`。桌面走 `platform_default` + `apply`（命名 TUN），Android 走
    // `apply_with_fd`（VpnService fd，M7 切片 B/C）。
    let spec = build_device_spec(&cfg, &id);
    let (backend, real_name, skip_setup): (
        std::sync::Arc<dyn hextet_wg::WgBackend + Send + Sync>,
        String,
        bool,
    ) = match transport {
        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
        Transport::Platform => {
            // 后端按平台选择（ADR-0007 决策 3 / ADR-0009 决策 4）：Linux 内核 WG，
            // macOS/Windows gotatun 用户态。
            let backend: std::sync::Arc<dyn hextet_wg::WgBackend + Send + Sync> =
                std::sync::Arc::new(crate::backend::platform_default());
            // `apply` 返回 OS 层真实设备名（ADR-0009 决策 3）。Linux 恒等于配置名；macOS
            // 读回真实 `utunN`。真实名只用于「按名操作设备」；配置名保留为人类/配置身份。
            let real_name = backend
                .apply(&spec)
                .context("配置 WireGuard 设备（需要 root/CAP_NET_ADMIN）")?;
            (backend, real_name, false)
        }
        #[cfg(unix)]
        Transport::Fd { fd, mtu } => {
            let us = hextet_wg_userspace::UserspaceBackend::new();
            let real_name = us
                .apply_with_fd(&spec, fd, mtu)
                .context("用 VpnService fd 配置 WireGuard 设备")?;
            (std::sync::Arc::new(us), real_name, true)
        }
    };
    // Linux-only 断言：内核后端恒返回配置名。macOS 返回 `utunN`（≠ `hextet0`），此断言不成立。
    #[cfg(target_os = "linux")]
    debug_assert_eq!(real_name, cfg.node.interface, "Linux 内核后端恒返回配置名");
    if !skip_setup {
        setup_interface(
            &real_name,
            own.address,
            NetworkPrefix::PREFIX_LEN,
            cfg.node.mtu,
        )
        .await
        .context("配置接口地址/MTU")?;
        // macOS：显式加 overlay /48 路由，与 Linux「内核配地址即自动下直连 /48 路由」语义
        // 对齐（ADR-0009 决策 4，与 `hextet up` 同路径）。设备随 daemon 进程存活，退出即随
        // backend drop 自动销毁，无需显式移除。
        #[cfg(target_os = "macos")]
        hextet_platform::add_route(&real_name, cfg.prefix.network(), NetworkPrefix::PREFIX_LEN)
            .await
            .context("添加 overlay /48 路由")?;
    }

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
                    upgrade_retries: 0,
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
                ddns: p.ddns.clone(),
                discovered: Vec::new(),
                relay,
                on_demand: crate::spec::peer_keepalive_secs(p, cfg.node.keepalive).is_none(),
                keepalive: crate::spec::peer_keepalive_secs(p, cfg.node.keepalive),
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
            ddns: None,
            discovered: Vec::new(),
            relay: None,
            on_demand: crate::spec::keepalive_opt(cfg.node.keepalive).is_none(),
            keepalive: crate::spec::keepalive_opt(cfg.node.keepalive),
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
    if cfg.node.gossip {
        let gossip_targets: Vec<Ipv6Addr> = peers.iter().map(|p| p.overlay).collect();
        let gossip_cfg = GossipConfig {
            port: cfg.node.gossip_port,
            own_address: own.address,
            prefix: cfg.prefix,
            own_identity: id,
            listen_port: cfg.node.listen_port,
            exclude_interface: ctx.device_name.clone(),
            admin_keys: cfg.node.admin_keys.clone(),
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
    } else {
        info!("隧道内 gossip 已关闭（[node] gossip = false）");
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

    // 3.985) DDNS 会合（会合兜底链第 ⑥ 层）：发布到用户自有域名 + 按 FQDN 查询，尽力而为
    let (ddns_tx, mut ddns_rx) = mpsc::channel::<DdnsEvent>(64);
    let (ddns_ctl_tx, ddns_ctl_rx) = mpsc::channel::<DdnsControl>(4);
    let (ddns_kick_tx, ddns_kick_rx) = mpsc::channel::<()>(4);
    let ddns_publish = cfg.node.ddns && cfg.node.ddns_fqdn.is_some();
    let ddns_query = peers.iter().any(|p| p.ddns.is_some());
    if ddns_publish || ddns_query {
        let updater: Option<DdnsUpdater> = if ddns_publish {
            build_ddns_updater(&cfg)
        } else {
            None
        };
        let ddns_cfg = DdnsConfig {
            ddns_key: derive_ddns_key(&cfg.network_key),
            listen_port: cfg.node.listen_port,
            exclude_interface: ctx.device_name.clone(),
            fqdn: cfg.node.ddns_fqdn.clone(),
            updater,
            resolver_addr: cfg.node.ddns_resolver,
            peers: peers
                .iter()
                .map(|p| DdnsPeer {
                    key_b64: p.key_b64.clone(),
                    fqdn: p.ddns.clone(),
                })
                .collect(),
        };
        info!("DDNS 会合已接线（发布 + 查询，走用户自有域名）");
        tokio::spawn(async move {
            match crate::ddns::serve(ddns_cfg, ddns_tx, ddns_ctl_rx, ddns_kick_rx).await {
                Ok(()) => debug!("DDNS 会合正常结束"),
                Err(e) => warn!(error = %e, "DDNS 会合不可用：会合第 ⑥ 层降级（不影响数据面）"),
            }
        });
    } else {
        info!("DDNS 会合未启用（无 [node] ddns_fqdn 且无 peer ddns）");
        drop(ddns_tx);
        drop(ddns_ctl_rx);
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
                if tick_once(&*backend, &ctx, &nudge, &mut cache, &mut peers, &relay_tx, &mut route_mgr).await {
                    // 有 peer 从 Probing 转 Connected：隧道刚通，立刻补发一次 gossip 广播。
                    // 否则启动时的首条广播可能落在隧道未就绪前被丢（Destination address
                    // required），要等 30s 周期才重发——gossip 转介的收敛时间退化成
                    // 「看 30s 周期碰不碰得上」（netns-e2e-gossip 转介超时的根因）。
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
                // 本机换了地址 → 立刻补发一条 LAN 公告 + 一条 gossip 广播 + 一条 DHT 重发
                // + 一条 DDNS 重发，别让同 LAN / 已连的对端等一个周期。通道满或已关闭都
                // 无所谓：周期兜底。
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
                        let ctl = RendezvousCtl {
                            gossip: &gossip_ctl_tx,
                            dht: &dht_ctl_tx,
                            ddns: &ddns_ctl_tx,
                        };
                        on_membership_event(&*backend, &ctx, &mut peers, &mut members, other, &ctl).await;
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
            _ = shutdown_rx.recv() => {
                info!("收到停机请求");
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
    let mut peer_states = Vec::with_capacity(peers.len());
    let mut any_connected = false;
    for peer in peers.iter_mut() {
        let observed = by_key.get(&peer.wg_public);
        let obs = Observation {
            last_handshake: observed.and_then(|s| s.last_handshake),
            kernel_endpoint: observed.and_then(|s| kernel_endpoint(s.endpoint)),
        };
        let actions = peer.fsm.tick(now, obs);
        if actions.iter().any(|a| matches!(a, Action::MarkGood(_))) {
            any_connected = true;
        }
        apply_actions(backend, ctx, nudge, cache, &*peer, &actions).await;
        // 升级重试（retry_from）由 drive_relay 返回、这里应用。
        let relay_actions = drive_relay(peer, ctx, cache, relay_tx, Instant::now());
        apply_actions(backend, ctx, nudge, cache, &*peer, &relay_actions).await;
        // site-to-site：只有连上才装路由，断开/重连期间清掉，避免流量黑洞
        sync_peer_routes(route_mgr, ctx, peer).await;
        peer_states.push(peer_state_of(&*peer, cache, route_mgr, observed.copied()));
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
/// 绝不能阻塞每秒一次的主循环。返回的 [`Action`]（升级重试）由调用方 [`tick_once`]
/// 经 [`apply_actions`] 应用。
fn drive_relay(
    peer: &mut PeerRuntime,
    ctx: &Ctx,
    cache: &EndpointCache,
    relay_tx: &mpsc::Sender<RelayRegistered>,
    now: Instant,
) -> Vec<Action> {
    let state = peer.fsm.state();
    let peer_name = peer.name.clone();
    if peer
        .relay
        .as_ref()
        .is_none_or(|link| link.control.is_empty())
    {
        return Vec::new();
    }

    // 候选列表在下面这段里可能需要重算；重算要借 &peer，所以先结束对 link 的可变借用。
    // 升级失败后的 retry_from 也一样：需要 session.endpoint 当「avoid」、又要借 &peer
    // 整体（candidates_for），defer 到 link 借用结束之后。
    let mut recompute = false;
    let mut retry_avoid: Option<SocketAddrV6> = None;
    {
        let Some(link) = peer.relay.as_mut() else {
            return Vec::new();
        };
        match state {
            PunchState::Connected { endpoint } => {
                let Some(session) = link.session else {
                    return Vec::new();
                };
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
                    link.upgrade_retries = 0;
                    link.last_register = None;
                    link.retry_after = None;
                    recompute = true;
                } else {
                    // 稳定在中继上
                    if link.upgrade_pending {
                        if link.upgrade_retries < UPGRADE_MAX_RETRIES {
                            // 升级失败：FSM 弹回中继。事件驱动的升级线索只来一次（同集合
                            // 的 LAN 公告会被 dedup），不重试就永远卡在中继——每 tick
                            // 重试一次 retry_from 直连候选，直到成功或重试耗尽。
                            link.upgrade_retries += 1;
                            debug!(
                                peer = %peer_name,
                                retries = link.upgrade_retries,
                                "升级直连未成功，重试直连"
                            );
                            retry_avoid = Some(session.endpoint);
                        } else {
                            debug!(peer = %peer_name, "升级直连未成功，继续走中继");
                            link.upgrade_pending = false;
                            link.upgrade_retries = 0;
                            recompute = true;
                        }
                    }
                    // 按节奏续期（服务端会话 TTL 180s）
                    let due = link
                        .last_register
                        .is_none_or(|t| now.duration_since(t) >= relay_client::REGISTER_INTERVAL);
                    // 续期同样要尊重注册失败的冷却：否则中继控制面不可达、但 FSM 还
                    // Connected 在旧会话上（最多 180s）时，每个 ~5-6s 就发一次注定
                    // 超时的注册，违背 RELAY_RETRY_COOLDOWN 的本意。
                    if due && !link.pending && !link.retry_after.is_some_and(|t| now < t) {
                        link.pending = true;
                        spawn_register(ctx, link, &peer_name, relay_tx.clone());
                    }
                }
            }
            PunchState::Probing { rounds, .. } => {
                // 升级回直连期间：中继还是活的，专心试直连，别重注册。
                if link.upgrade_pending {
                    return Vec::new();
                }
                if link.pending {
                    return Vec::new();
                }
                if link.retry_after.is_some_and(|t| now < t) {
                    return Vec::new();
                }
                // 会话还在（握手失效后的死会话，或刚注册待握手）：按续期节奏重新注册。
                // 死会话靠它续回来——否则 Probing 期间永远不再注册，relay 数据面一断就
                // 永久卡死；刚注册场景 last_register 很新、due=false 不会重复注册。
                if link.session.is_some() {
                    let due = link
                        .last_register
                        .is_none_or(|t| now.duration_since(t) >= relay_client::REGISTER_INTERVAL);
                    if !due {
                        return Vec::new();
                    }
                    info!(
                        peer = %peer_name,
                        via = %link.via_name,
                        "中继会话失效，重新注册"
                    );
                    link.pending = true;
                    spawn_register(ctx, link, &peer_name, relay_tx.clone());
                    return Vec::new();
                }
                // 首次回中继：给直连完整机会（轮换 RELAY_AFTER_ROUNDS 轮）
                if rounds < RELAY_AFTER_ROUNDS {
                    return Vec::new();
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
    if let Some(avoid) = retry_avoid {
        // 重试升级：先换回完整候选列表（upgrade_pending 仍 true，candidates_for 返回
        // 直连+中继），再 retry_from_flush 离开中继去试直连——必须 flush 旧中继会话，
        // 否则内核沿旧会话 roaming、不产生新握手，Probing 观察不到升级。
        let candidates = candidates_for(&*peer, cache);
        let _ = peer.fsm.set_candidates(candidates, SystemTime::now());
        return peer.fsm.retry_from_flush(Some(avoid), SystemTime::now());
    }
    if recompute {
        let candidates = candidates_for(&*peer, cache);
        // `Connected` 状态下 `set_candidates` 契约上只换列表、不产生动作
        let _ = peer.fsm.set_candidates(candidates, SystemTime::now());
    }
    Vec::new()
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
            let previous = link.session;
            if previous == Some(session) {
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
            // 会话端点变了（relay 重启后重新分配端口）：若此刻还 Connected 在旧会话
            // 端点上，立刻 retry_from 切到新端点，而不是等 180s 握手失效——否则
            // drive_relay 会把「Connected 端点 != 会话端点」误判成直连升级成功，
            // 把刚拿到的会话又注销掉。
            if let Some(prev) = previous
                && let PunchState::Connected { endpoint } = peer.fsm.state()
                && endpoint == prev.endpoint
            {
                let actions = peer.fsm.retry_from(Some(prev.endpoint), SystemTime::now());
                apply_actions(backend, ctx, nudge, cache, &*peer, &actions).await;
            }
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
        link.upgrade_retries = 0;
        info!(
            peer = %peer.name,
            "有了新的直连线索，尝试从中继升级回直连"
        );
        let candidates = candidates_for(&*peer, cache);
        let mut actions = peer.fsm.set_candidates(candidates, SystemTime::now());
        actions.extend(peer.fsm.retry_from_flush(Some(relay_ep), SystemTime::now()));
        apply_actions(backend, ctx, nudge, cache, &*peer, &actions).await;
        return;
    }

    // 对端换了地址：会合层刚给出一个**不再包含当前连接地址**的新集合，且当前地址
    // 既不是配置里手填的、也不再被任何"权威"会合源在报 → 说明它已经失效，主动离开
    // 它去试新地址。否则 `Connected` 状态（`set_candidates` 刻意不打扰）会一直等到
    // 180s 握手过期才退回 Probing——双端同时换前缀、LAN 又关掉（只剩 DHT 会合）时，
    // 这个延迟远超秒级收敛目标（netns-e2e-dht.sh 换址恢复阶段实跑发现的根因）。
    //
    // 权威源**故意排除 gossip**：gossip 是转述，且要沿现有隧道传播——双端同时换前缀、
    // 隧道已断时它拿不到对端新地址，旧条目会一直留在表里。若不排除，gossip 在换址前
    // 就把旧地址喂给了对端，`still_current` 恒真、永远不切，换址恢复就成了"看运气"
    // （gossip 有没有赶在换址前送达）。LAN/DHT/DDNS 则都是对端"自己报/即时可查"的
    // 活地址，可以采信。
    if let PunchState::Connected { endpoint } = peer.fsm.state() {
        let is_configured = peer.configured.iter().any(|c| normalize(*c) == endpoint);
        // 剪枝（可靠源判断，无权威源时回落到 gossip）：离开失效地址前先把它从端点
        // 缓存逐出——否则缓存的 last_good/seen 会把死地址喂回候选列表，FSM 在
        // [死 b, 活 bb] 之间来回轮换、永远收敛不了（netns-e2e-gossip 换址恢复卡死的根因）。
        if !is_configured && !reported_by_reliable_source(&peer.discovered, endpoint) {
            cache.evict(&peer.key_b64, endpoint);
            // 逐出要落盘：否则 daemon 重启会从 endpoints.json 把死 last_good/seen
            // 重新读回来，启动时又拿死地址当首候选（与 record_good 的落盘同语义）。
            if let Err(e) = cache.save(&ctx.cache_path) {
                warn!(path = %ctx.cache_path.display(), error = %e, "写端点缓存失败（逐出后）");
            }
        }
        // 切换（权威源判断，故意排除 gossip）：与剪枝是**两个独立决策**——gossip 仍报旧
        // 地址（换址前的在途消息）时剪枝不该动（旧地址可能还活），但切换也不该采信 gossip。
        if !is_configured && !still_reported_by_authoritative_source(&peer.discovered, endpoint) {
            let candidates = candidates_for(&*peer, cache);
            let mut actions = peer.fsm.set_candidates(candidates, SystemTime::now());
            actions.extend(peer.fsm.retry_from(Some(endpoint), SystemTime::now()));
            apply_actions(backend, ctx, nudge, cache, &*peer, &actions).await;
            return;
        }
    }
    // 未触发「离开失效地址」：照常换列表（`set_candidates` 在 Connected 下契约上不产生动作）。
    let candidates = candidates_for(&*peer, cache);
    let actions = peer.fsm.set_candidates(candidates, SystemTime::now());
    apply_actions(backend, ctx, nudge, cache, &*peer, &actions).await;
}

/// 判断 `endpoint` 是否仍被「可靠」会合源在报（用于**剪枝**死地址，而非切换决策）。
///
/// 与 [`still_reported_by_authoritative_source`] 的差别：该函数把 gossip 排除在「权威」
/// 之外（切换不能信转述）；但**剪枝**时，若这个 peer 没有任何权威源（LAN/DHT/DDNS 全无，
/// gossip 是唯一会合手段），则回落到 gossip——gossip 是对端自己签发的广播，可信地反映
/// 「对端当前在哪些地址」。有权威源时仍只看权威源，gossip 的旧地址不参与判断。
fn reported_by_reliable_source(
    discovered: &[(Source, SocketAddrV6)],
    endpoint: SocketAddrV6,
) -> bool {
    let has_authoritative = discovered.iter().any(|(s, _)| *s != Source::Gossip);
    if has_authoritative {
        still_reported_by_authoritative_source(discovered, endpoint)
    } else {
        discovered.iter().any(|(_, e)| normalize(*e) == endpoint)
    }
}

/// 判断 `endpoint` 是否仍被「权威」会合源在报。
///
/// 权威源 = LAN / DHT / DDNS，**故意排除 gossip**：gossip 是转述、且要沿现有隧道
/// 传播——双端同时换前缀、隧道已断时它拿不到对端新地址，旧条目会一直留在表里。
/// 若把 gossip 也采信，换址前的旧地址会卡死 [`on_discovered`] 的主动切换，让恢复
/// 变成「看 gossip 有没有赶在换址前送达」的运气（netns-e2e-dht.sh 偶发超时的根因）。
/// LAN/DHT/DDNS 则都是对端「自己报 / 即时可查」的活地址，可以采信。
fn still_reported_by_authoritative_source(
    discovered: &[(Source, SocketAddrV6)],
    endpoint: SocketAddrV6,
) -> bool {
    discovered
        .iter()
        .any(|(s, e)| *s != Source::Gossip && normalize(*e) == endpoint)
}

/// 会合/控制任务的发送端集合（成员增删时一起更新 gossip/DHT/DDNS 的查询目标）。
struct RendezvousCtl<'a> {
    gossip: &'a mpsc::Sender<GossipControl>,
    dht: &'a mpsc::Sender<DhtControl>,
    ddns: &'a mpsc::Sender<DdnsControl>,
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
    ctl: &RendezvousCtl<'_>,
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
                    persistent_keepalive: crate::spec::keepalive_opt(ctx.keepalive),
                },
            );
            peers.push(PeerRuntime {
                name: name.clone(),
                key_b64: key_b64.clone(),
                wg_public,
                overlay: address,
                configured: Vec::new(),
                routes: Vec::new(),
                ddns: None,
                discovered: Vec::new(),
                relay: None,
                on_demand: crate::spec::keepalive_opt(ctx.keepalive).is_none(),
                keepalive: crate::spec::keepalive_opt(ctx.keepalive),
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
            let _ = ctl.gossip.send(GossipControl::UpdateTargets(targets)).await;
            let _ = ctl
                .dht
                .send(DhtControl::UpdatePeers(
                    peers.iter().map(|p| p.key_b64.clone()).collect(),
                ))
                .await;
            let _ = ctl
                .ddns
                .send(DdnsControl::UpdatePeers(
                    peers
                        .iter()
                        .map(|p| DdnsPeer {
                            key_b64: p.key_b64.clone(),
                            fqdn: p.ddns.clone(),
                        })
                        .collect(),
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
            if members.remove(&key_b64)
                && let Err(e) = members.save(&ctx.members_path)
            {
                warn!(path = %ctx.members_path.display(), error = %e, "写成员表失败");
            }
            let targets: Vec<Ipv6Addr> = peers.iter().map(|p| p.overlay).collect();
            let _ = ctl.gossip.send(GossipControl::UpdateTargets(targets)).await;
            let _ = ctl
                .dht
                .send(DhtControl::UpdatePeers(
                    peers.iter().map(|p| p.key_b64.clone()).collect(),
                ))
                .await;
            let _ = ctl
                .ddns
                .send(DdnsControl::UpdatePeers(
                    peers
                        .iter()
                        .map(|p| DdnsPeer {
                            key_b64: p.key_b64.clone(),
                            fqdn: p.ddns.clone(),
                        })
                        .collect(),
                ))
                .await;
        }
        GossipEvent::Discovered(_) => unreachable!("端点转介在 select 循环里单独处理"),
    }
}

/// 按配置构建 DDNS 更新器（webhook / cloudflare）。构建失败只 warn 并返回 `None`
/// （DDNS 发布降级，查询照常），绝不阻断 daemon 启动。
fn build_ddns_updater(cfg: &hextet_core::config::Config) -> Option<DdnsUpdater> {
    match cfg.node.ddns_provider {
        DdnsProvider::Webhook => {
            let url = cfg.node.ddns_webhook_url.clone()?;
            match DdnsUpdater::webhook(url, cfg.node.ddns_secret.clone()) {
                Ok(u) => Some(u),
                Err(e) => {
                    warn!(error = %e, "构建 webhook 更新器失败，DDNS 发布降级");
                    None
                }
            }
        }
        DdnsProvider::Cloudflare => {
            let token = cfg.node.ddns_secret.clone()?;
            let zone = cfg.node.ddns_zone.clone()?;
            match DdnsUpdater::cloudflare(token, zone) {
                Ok(u) => Some(u),
                Err(e) => {
                    warn!(error = %e, "构建 cloudflare 更新器失败，DDNS 发布降级");
                    None
                }
            }
        }
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

fn peer_state_of(
    peer: &PeerRuntime,
    cache: &EndpointCache,
    route_mgr: &RouteManager,
    observed: Option<&hextet_wg::types::PeerStatus>,
) -> PeerState {
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
    let ddns_endpoints = peer
        .discovered
        .iter()
        .filter(|(s, _)| *s == Source::Ddns)
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
        ddns_endpoints,
        relay_via: if punch_state == "relayed" {
            peer.relay.as_ref().map(|l| l.via_name.clone())
        } else {
            None
        },
        routes: route_mgr.routes_of(&peer.key_b64).to_vec(),
        // WG 统计（供跨进程/跨线程 status 读，不必再访问进程内后端）。
        last_handshake_secs: observed
            .and_then(|s| s.last_handshake)
            .and_then(|t| SystemTime::now().duration_since(t).ok())
            .map(|d| d.as_secs()),
        rx_bytes: observed.map(|s| s.rx_bytes).unwrap_or(0),
        tx_bytes: observed.map(|s| s.tx_bytes).unwrap_or(0),
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
            Action::Rehandshake(ep) => {
                // flush 掉旧会话再按直连 endpoint 重加，逼下一个 nudge 触发真正的新握手。
                // allowed_ips 必须用完整派生（site/64 + 通告路由），keepalive 原样带回。
                if let Err(e) = backend.remove_peer(&ctx.device_name, &peer.wg_public) {
                    warn!(peer = %peer.name, error = %e, "重握手：移除 peer 失败");
                }
                match backend.add_peer(
                    &ctx.device_name,
                    &PeerSpec {
                        wg_public: peer.wg_public,
                        endpoint: Some(ep),
                        allowed_ips: allowed_ips_for(site_of(peer.overlay), &peer.routes),
                        persistent_keepalive: peer.keepalive,
                    },
                ) {
                    Ok(()) => {
                        debug!(peer = %peer.name, endpoint = %ep, "重握手（remove+add 以强制新握手）")
                    }
                    Err(e) => {
                        warn!(peer = %peer.name, endpoint = %ep, error = %e, "重握手：重新添加 peer 失败")
                    }
                }
            }
            Action::Nudge => {
                // 按需连接（keepalive=0）：不主动发 nudge，省电。endpoint 照常
                // 由 SetEndpoint 更新，出站流量会触发 WG 按需握手，FSM 观察到
                // 新鲜握手后照常回到 Connected。
                if peer.on_demand {
                    debug!(peer = %peer.name, "按需连接：跳过主动 nudge（等出站流量触发握手）");
                    continue;
                }
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
    use super::*;

    fn ep(s: &str) -> SocketAddrV6 {
        s.parse().unwrap()
    }

    /// 「权威源是否还在报这个地址」：LAN/DHT/DDNS 采信，gossip 故意不采信。
    #[test]
    fn authoritative_source_excludes_gossip() {
        let target = ep("[2001:db8::1]:4193");
        let other = ep("[2001:db8::2]:4193");

        // 各权威源单独在报 → 采信
        for source in [Source::Lan, Source::Dht, Source::Ddns] {
            assert!(
                still_reported_by_authoritative_source(&[(source, target)], target),
                "{source:?} 在报的地址应被采信"
            );
        }

        // 只有 gossip 在报 → 不采信（这是 anti-flake 的关键不变量）
        assert!(
            !still_reported_by_authoritative_source(&[(Source::Gossip, target)], target),
            "只有 gossip 在报的地址不应被采信"
        );

        // 地址不在任何源里 → 不采信
        assert!(
            !still_reported_by_authoritative_source(&[(Source::Gossip, other)], target),
            "没人在报的地址不应被采信"
        );

        // gossip 也在报、但 DHT 同时在报 → 采信（权威源在场即可）
        assert!(
            still_reported_by_authoritative_source(
                &[(Source::Gossip, target), (Source::Dht, target)],
                target
            ),
            "gossip 之外还有 DHT 在报，应采信"
        );
    }

    /// 剪枝用的「可靠源」判断：无权威源时回落到 gossip，有权威源时仍只看权威源。
    #[test]
    fn reliable_source_falls_back_to_gossip_without_authoritative() {
        let target = ep("[2001:db8::1]:4193");
        let other = ep("[2001:db8::2]:4193");

        // 无权威源、只有 gossip 在报 target → 剪枝采信（gossip 是唯一会合手段）
        assert!(
            reported_by_reliable_source(&[(Source::Gossip, target)], target),
            "无权威源时应回落采信 gossip"
        );
        // 无权威源、gossip 报的是别的地址 → 不采信（target 已失效）
        assert!(
            !reported_by_reliable_source(&[(Source::Gossip, other)], target),
            "gossip 已不再报 target，应判失效"
        );
        // 有权威源（DHT 在场）、但 DHT 没报 target → 即使 gossip 报也不采信
        assert!(
            !reported_by_reliable_source(&[(Source::Gossip, target), (Source::Dht, other)], target),
            "有权威源时不该采信 gossip 的转述"
        );
        // 有权威源、DHT 在报 target → 采信
        assert!(
            reported_by_reliable_source(&[(Source::Gossip, other), (Source::Dht, target)], target),
            "权威源在报 target 应采信"
        );
    }

    /// 归一化：带 flowinfo/scope_id 的地址要能命中（跨来源比较必须先归一化）。
    #[test]
    fn authoritative_source_normalizes_endpoint() {
        let raw = SocketAddrV6::new("2001:db8::1".parse().unwrap(), 4193, 7, 9);
        let clean = ep("[2001:db8::1]:4193");
        assert!(
            still_reported_by_authoritative_source(&[(Source::Dht, raw)], clean),
            "带 scope_id 的 discovered 地址应与归一化后的 endpoint 匹配"
        );
    }

    /// gossip 准入新成员时，`add_peer` 的 keepalive 必须跟随 `[node] keepalive` 配置
    /// （`0` → 关闭持久 keepalive）。这是「gossip 运行时加 peer」路径与 `build_device_spec`
    /// 初始 apply 路径保持一致的关键——两处都走 `spec::keepalive_opt`。
    async fn admit_keepalive(keepalive: u16) -> Option<u16> {
        let mock = hextet_wg::mock::MockBackend::default();
        let dir = tempfile::tempdir().unwrap();
        let ctx = Ctx {
            interface: "hextet0".into(),
            device_name: "hextet0".into(),
            node_address: "fd00::1".parse().unwrap(),
            node_public_key: "self".into(),
            own_public: hextet_core::identity::NodeIdentity::generate().public(),
            listen_port: 4193,
            keepalive,
            relay_key: [0u8; 32],
            cache_path: dir.path().join("endpoints.json"),
            state_path: dir.path().join("state.json"),
            members_path: dir.path().join("members.json"),
        };
        let (gossip_tx, _) = mpsc::channel::<GossipControl>(1);
        let (dht_tx, _) = mpsc::channel::<DhtControl>(1);
        let (ddns_tx, _) = mpsc::channel::<DdnsControl>(1);
        let ctl = RendezvousCtl {
            gossip: &gossip_tx,
            dht: &dht_tx,
            ddns: &ddns_tx,
        };
        let mut peers: Vec<PeerRuntime> = Vec::new();
        let mut members = MembersFile::new();
        let node = hextet_core::identity::NodeIdentity::generate().public();
        on_membership_event(
            &mock,
            &ctx,
            &mut peers,
            &mut members,
            GossipEvent::MemberAdmitted {
                node,
                name: "newbie".into(),
                address: "fd00::beef".parse().unwrap(),
            },
            &ctl,
        )
        .await;

        // 运行时表 + 成员表都进了；数据面 add_peer 恰好一次
        assert_eq!(peers.len(), 1, "gossip 准入应进运行时表");
        assert_eq!(members.members.len(), 1, "gossip 准入应落成员表");
        let added = mock.added_peers.lock().unwrap();
        assert_eq!(added.len(), 1, "add_peer 应恰好调用一次");
        assert_eq!(added[0].0, "hextet0", "add_peer 应作用于真实设备名");
        added[0].1.persistent_keepalive
    }

    #[tokio::test]
    async fn gossip_admission_follows_configured_keepalive() {
        // 默认（常电）：25s
        assert_eq!(admit_keepalive(25).await, Some(25));
        // 移动端按需：0 → 关闭持久 keepalive
        assert_eq!(admit_keepalive(0).await, None);
    }

    fn relay_ctx() -> Ctx {
        Ctx {
            interface: "hextet0".into(),
            device_name: "hextet0".into(),
            node_address: "fd00::1".parse().unwrap(),
            node_public_key: "self".into(),
            own_public: hextet_core::identity::NodeIdentity::generate().public(),
            listen_port: 4193,
            keepalive: 25,
            relay_key: [0u8; 32],
            cache_path: PathBuf::from("/tmp/hextet-test-cache.json"),
            state_path: PathBuf::from("/tmp/hextet-test-state.json"),
            members_path: PathBuf::from("/tmp/hextet-test-members.json"),
        }
    }

    /// 构造一个带中继逃生舱、FSM 处于给定状态的 peer。
    fn relay_peer(
        fsm: PeerFsm,
        session: Option<RelaySession>,
        last_register: Option<Instant>,
    ) -> PeerRuntime {
        PeerRuntime {
            name: "nas".into(),
            key_b64: "peer".into(),
            wg_public: [0u8; 32],
            overlay: "fd00::2".parse().unwrap(),
            configured: vec![],
            routes: vec![],
            ddns: None,
            discovered: vec![],
            relay: Some(RelayLink {
                via_name: "relay".into(),
                control: vec![ep("[2001:db8::ff]:4196")],
                peer_public: hextet_core::identity::NodeIdentity::generate().public(),
                session,
                pending: false,
                upgrade_pending: false,
                upgrade_retries: 0,
                last_register,
                retry_after: None,
            }),
            on_demand: false,
            keepalive: Some(25),
            fsm,
        }
    }

    /// 回归（relay 数据面断开后的重注册）：握手失效退回 Probing、但会话还挂着时，
    /// drive_relay 必须按续期节奏重新注册，而不是被 `session.is_some()` 永久卡住。
    #[tokio::test]
    async fn drive_relay_reregisters_when_session_goes_stale_while_probing() {
        let ep = ep("[2001:db8::ff]:4196");
        let session = RelaySession {
            endpoint: ep,
            control: ep,
        };
        let mut peer = relay_peer(
            PeerFsm::new(vec![ep], SystemTime::now()),
            Some(session),
            // 续期节奏 30s，已过期 → 死会话
            Some(Instant::now() - Duration::from_secs(31)),
        );
        let ctx = relay_ctx();
        let cache = EndpointCache::new();
        let (tx, _rx) = mpsc::channel::<RelayRegistered>(1);

        let actions = drive_relay(&mut peer, &ctx, &cache, &tx, Instant::now());
        assert!(actions.is_empty(), "重注册只发注册任务，不改 FSM 动作");
        assert!(
            peer.relay.as_ref().unwrap().pending,
            "会话失效应触发重新注册"
        );
    }

    /// 刚注册、正在等握手的会话不应被重复注册（last_register 很新 → due=false）。
    #[tokio::test]
    async fn drive_relay_does_not_reregister_fresh_session_while_probing() {
        let ep = ep("[2001:db8::ff]:4196");
        let session = RelaySession {
            endpoint: ep,
            control: ep,
        };
        let mut peer = relay_peer(
            PeerFsm::new(vec![ep], SystemTime::now()),
            Some(session),
            Some(Instant::now()),
        );
        let ctx = relay_ctx();
        let cache = EndpointCache::new();
        let (tx, _rx) = mpsc::channel::<RelayRegistered>(1);

        let _ = drive_relay(&mut peer, &ctx, &cache, &tx, Instant::now());
        assert!(
            !peer.relay.as_ref().unwrap().pending,
            "刚注册的会话不应重复注册"
        );
    }

    /// Connected 续期同样要尊重注册失败的冷却（否则控制面不可达时会每 ~5s 刷一次
    /// 注定超时的注册）。
    #[tokio::test]
    async fn drive_relay_respects_cooldown_in_connected_renewal() {
        let ep = ep("[2001:db8::ff]:4196");
        let now = SystemTime::now();
        let mut fsm = PeerFsm::new(vec![ep], now);
        let _ = fsm.tick(
            now,
            Observation {
                last_handshake: Some(now),
                kernel_endpoint: Some(ep),
            },
        );
        assert_eq!(fsm.state(), PunchState::Connected { endpoint: ep });

        let session = RelaySession {
            endpoint: ep,
            control: ep,
        };
        let mut peer = relay_peer(
            fsm,
            Some(session),
            // 续期节奏 30s 已过期 → 想续期
            Some(Instant::now() - Duration::from_secs(31)),
        );
        // 但上一次注册刚失败，还在 60s 冷却内
        peer.relay.as_mut().unwrap().retry_after = Some(Instant::now() + Duration::from_secs(60));
        let ctx = relay_ctx();
        let cache = EndpointCache::new();
        let (tx, _rx) = mpsc::channel::<RelayRegistered>(1);

        let _ = drive_relay(&mut peer, &ctx, &cache, &tx, Instant::now());
        assert!(
            !peer.relay.as_ref().unwrap().pending,
            "冷却期内不应重新注册"
        );
    }

    /// 回归（relay 重启后会话端点变了）：on_relay_registered 拿到新端点的会话时，
    /// 若 FSM 还 Connected 在旧会话端点上，应立刻 retry_from 切到新端点，而不是
    /// 让 drive_relay 把「端点不一致」误判成直连升级成功、把新会话又注销掉。
    #[tokio::test]
    async fn relay_session_endpoint_change_moves_fsm_to_new_endpoint() {
        let e1 = ep("[2001:db8::ff]:4196");
        let e2 = ep("[2001:db8::ff]:4197");
        let now = SystemTime::now();
        let mut fsm = PeerFsm::new(vec![e1, e2], now);
        // 先连在旧会话端点 e1 上
        let _ = fsm.tick(
            now,
            Observation {
                last_handshake: Some(now),
                kernel_endpoint: Some(e1),
            },
        );
        assert_eq!(fsm.state(), PunchState::Connected { endpoint: e1 });

        let peer = relay_peer(
            fsm,
            Some(RelaySession {
                endpoint: e1,
                control: e1,
            }),
            Some(Instant::now()),
        );
        let ctx = relay_ctx();
        let mut cache = EndpointCache::new();
        let backend = hextet_wg::mock::MockBackend::default();
        let nudge = tokio::net::UdpSocket::bind("[::]:0").await.unwrap();
        let mut peers = vec![peer];

        on_relay_registered(
            &backend,
            &ctx,
            &nudge,
            &mut cache,
            &mut peers,
            RelayRegistered {
                peer_key: "peer".into(),
                session: Some(RelaySession {
                    endpoint: e2,
                    control: e2,
                }),
            },
        )
        .await;

        let p = &peers[0];
        assert_eq!(p.relay.as_ref().unwrap().session.unwrap().endpoint, e2);
        // retry_from 离开旧的 Connected(e1)，落到 Probing 并指向新端点 e2
        assert!(matches!(p.fsm.state(), PunchState::Probing { .. }));
        assert_eq!(p.fsm.current_candidate(), Some(e2));
        // relay 会话换端点走 `retry_from`（SetEndpoint + Nudge），不是 flush——旧会话
        // 已因 relay 重启而失效，SetEndpoint 后 nudge 会自然触发新握手。
        let updates = backend.endpoint_updates.lock().unwrap();
        assert_eq!(updates.len(), 1, "应恰好一次 SetEndpoint 切到新会话端点");
        assert_eq!(updates[0].2, e2);
        drop(updates);
        let removed = backend.removed_peers.lock().unwrap();
        assert_eq!(removed.len(), 0, "relay 换端点不 flush 会话");
        let added = backend.added_peers.lock().unwrap();
        assert_eq!(added.len(), 0, "relay 换端点不重加 peer");
    }

    /// 回归（升级直连的强制重握手）：`Rehandshake(ep)` 必须走 remove_peer + add_peer
    /// （不是 SetEndpoint），且 add_peer 用**完整** AllowedIPs（site/64 + 通告路由）与
    /// peer 的 keepalive——否则 flush 会话会清掉通告路由 / 丢掉 keepalive。
    #[tokio::test]
    async fn rehandshake_readds_with_full_allowed_ips_and_keepalive() {
        let direct = ep("[2001:db8::1]:4193");
        let mut peer = relay_peer(PeerFsm::new(vec![direct], SystemTime::now()), None, None);
        peer.routes = vec!["2001:db8:dead::/64".parse().unwrap()];
        let ctx = relay_ctx();
        let mut cache = EndpointCache::new();
        let backend = hextet_wg::mock::MockBackend::default();
        let nudge = tokio::net::UdpSocket::bind("[::]:0").await.unwrap();

        apply_actions(
            &backend,
            &ctx,
            &nudge,
            &mut cache,
            &peer,
            &[Action::Rehandshake(direct)],
        )
        .await;

        let removed = backend.removed_peers.lock().unwrap();
        assert_eq!(removed.len(), 1, "应恰好一次 remove_peer 清会话");
        assert_eq!(removed[0].1, peer.wg_public);
        let added = backend.added_peers.lock().unwrap();
        assert_eq!(added.len(), 1, "应恰好一次 add_peer 重加");
        assert_eq!(added[0].1.endpoint, Some(direct));
        let expected_ips = allowed_ips_for(site_of(peer.overlay), &peer.routes);
        assert_eq!(
            added[0].1.allowed_ips, expected_ips,
            "重加必须用完整 AllowedIPs（site/64 + 通告路由）"
        );
        assert!(added[0].1.allowed_ips.len() >= 2, "应含 site/64 + 通告路由");
        assert_eq!(added[0].1.persistent_keepalive, peer.keepalive);
        assert_eq!(
            backend.endpoint_updates.lock().unwrap().len(),
            0,
            "Rehandshake 不走 SetEndpoint"
        );
    }

    /// `candidates_for` 的核心不变量：会话已建且非升级 → 候选收窄到只剩中继；
    /// 无会话 → 只有直连；升级中 → 直连 + 中继都留。
    #[test]
    fn candidates_for_narrows_to_relay_while_connected() {
        let relay_ep = ep("[2001:db8::ff]:4196");
        let direct = ep("[2001:db8::1]:4193");
        let session = RelaySession {
            endpoint: relay_ep,
            control: relay_ep,
        };
        let cache = EndpointCache::new();

        // 会话已建 + 非升级 → 只留中继
        let mut connected = relay_peer(
            PeerFsm::new(vec![direct], SystemTime::now()),
            Some(session),
            Some(Instant::now()),
        );
        connected.configured.push(direct);
        assert_eq!(candidates_for(&connected, &cache), vec![relay_ep]);

        // 无会话 → 只有直连（不含中继）
        let mut no_session = relay_peer(PeerFsm::new(vec![direct], SystemTime::now()), None, None);
        no_session.configured.push(direct);
        let cands = candidates_for(&no_session, &cache);
        assert!(cands.contains(&direct));
        assert!(!cands.contains(&relay_ep), "无会话时不该有中继候选");

        // 升级中（会话还在）→ 直连 + 中继都留
        let mut upgrading = relay_peer(
            PeerFsm::new(vec![direct], SystemTime::now()),
            Some(session),
            Some(Instant::now()),
        );
        upgrading.configured.push(direct);
        upgrading.relay.as_mut().unwrap().upgrade_pending = true;
        let cands = candidates_for(&upgrading, &cache);
        assert!(cands.contains(&direct), "升级中应保留直连候选");
        assert!(cands.contains(&relay_ep), "升级中应保留中继作为回退");
    }
}
