//! `hextet service`：把 `hextet daemon` 跑成 Windows 服务（ADR-0010 决策 4）。
//!
//! 用 `windows-service` crate（Mullvad 维护，MIT OR Apache-2.0）：unsafe 全部内聚在 crate
//! 内，本模块**零 unsafe**。注意：`windows-service` 的 `define_windows_service!` 宏会展开出
//! 一个 `unsafe { }` 块，触发 workspace 的 `unsafe_code = "deny"`，故这里**不用**该宏，而是
//! 手写一个**安全**的 `extern "system" fn` 入口（不碰原始参数指针，只忽略它们——配置路径由
//! clap 解析后放进 [`CONFIG_PATH`]，不依赖 SCM 的 service arguments）。
//!
//! 诚实边界（ADR-0010 决策 4）：`ServiceControl::Stop` 的优雅关停需要 engine 在 Windows 上的
//! 信号处理（把 SCM Stop 转成 daemon 的 tokio 信号），本切片不碰 `crates/engine`（本 session
//! 另一 agent 持有），故 Stop 时报告 `Stopped` 后退出进程、daemon 线程随之终止，**非优雅**
//! 关停（接口不拆除——拆除本就是 `hextet down` 的职责，与前台 daemon 一致）。

use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::Duration;

use windows_service::service::{
    ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
    ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_dispatcher;
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

const SERVICE_NAME: &str = "hextet";
const SERVICE_DISPLAY_NAME: &str = "hextet mesh VPN daemon";
const DEFAULT_CONFIG_PATH: &str = "C:\\ProgramData\\hextet\\hextet.toml";

/// 服务运行时读取的配置文件路径（由 `run --config` 在 `service_dispatcher::start` 前写入）。
static CONFIG_PATH: OnceLock<PathBuf> = OnceLock::new();

/// `hextet service` 子命令。
#[derive(clap::Subcommand)]
pub enum Args {
    /// 安装为 Windows 服务（LocalSystem，开机自启）
    Install,
    /// 卸载 Windows 服务
    Uninstall,
    /// 以服务方式运行守护进程（由 SCM 调用，勿手动运行）
    Run {
        /// 配置文件路径
        #[arg(short, long, default_value = DEFAULT_CONFIG_PATH)]
        config: PathBuf,
    },
}

/// 运行 `hextet service` 子命令。
pub fn run(args: Args) -> anyhow::Result<()> {
    match args {
        Args::Install => install(),
        Args::Uninstall => uninstall(),
        Args::Run { config } => run_as_service(config),
    }
}

/// 安装服务：`ServiceManager::create_service`，`binPath = "<exe> service run --config <path>"`。
fn install() -> anyhow::Result<()> {
    let manager =
        ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CREATE_SERVICE)
            .map_err(|e| anyhow::anyhow!("open service manager failed: {e}"))?;

    let exe = std::env::current_exe().map_err(|e| anyhow::anyhow!("current_exe failed: {e}"))?;
    let service_info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(SERVICE_DISPLAY_NAME),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe,
        launch_arguments: vec![
            OsString::from("service"),
            OsString::from("run"),
            OsString::from("--config"),
            OsString::from(DEFAULT_CONFIG_PATH),
        ],
        dependencies: vec![],
        account_name: None, // LocalSystem
        account_password: None,
    };
    manager
        .create_service(&service_info, ServiceAccess::QUERY_STATUS)
        .map_err(|e| anyhow::anyhow!("create service failed: {e}"))?;
    println!("installed service {SERVICE_NAME} (LocalSystem, auto-start)");
    println!(
        "wintun.dll must be placed next to the executable, or the service will fail to open the TUN device"
    );
    Ok(())
}

/// 卸载服务：`Service::delete`。
fn uninstall() -> anyhow::Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|e| anyhow::anyhow!("open service manager failed: {e}"))?;
    let service = manager
        .open_service(SERVICE_NAME, ServiceAccess::DELETE)
        .map_err(|e| anyhow::anyhow!("open service failed: {e}"))?;
    service
        .delete()
        .map_err(|e| anyhow::anyhow!("delete service failed: {e}"))?;
    println!("uninstalled service {SERVICE_NAME}");
    Ok(())
}

/// 以服务方式运行：记录配置路径 → 注册 dispatcher → 阻塞直到服务被停止。
fn run_as_service(config: PathBuf) -> anyhow::Result<()> {
    // 配置路径经 clap 解析后写入静态变量，供后台 service_main 线程读取（SCM 的 service
    // arguments 为空，配置不从那走）。
    let _ = CONFIG_PATH.set(config);
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
        .map_err(|e| anyhow::anyhow!("start service dispatcher failed: {e}"))
}

/// 服务入口（安全 `extern "system" fn`，对应 SCM 的 `SERVICE_TABLE_ENTRYW.lpServiceProc`）。
///
/// 不用 `define_windows_service!` 宏：该宏会展开出 `unsafe { }` 块，触发本 crate 继承的
/// `unsafe_code = "deny"`。这里直接声明安全的 `extern "system" fn`，忽略原始参数指针
/// （配置路径已由 [`run_as_service`] 写入 [`CONFIG_PATH`]）。
extern "system" fn ffi_service_main(_argc: u32, _argv: *mut *mut u16) {
    if let Err(e) = service_main() {
        eprintln!("hextet service main failed: {e}");
    }
}

/// 服务主体：注册 control handler、报告 Running、跑 daemon、等 Stop、报告 Stopped。
fn service_main() -> windows_service::Result<()> {
    let (shutdown_tx, shutdown_rx) = std::sync::mpsc::channel();

    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop => {
                let _ = shutdown_tx.send(());
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };
    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;
    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    let config = CONFIG_PATH
        .get()
        .cloned()
        .unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG_PATH));
    // daemon 自带 tokio runtime 并阻塞；放到独立线程，让本线程能响应 Stop。
    let daemon_thread = std::thread::spawn(move || {
        if let Err(e) = hextet_engine::daemon::run(&config) {
            eprintln!("hextet daemon failed: {e:#}");
        }
    });

    // 等 SCM 的 Stop。优雅关停（Stop → daemon 的 tokio 信号）需 engine 侧 Windows 信号处理，
    // 本切片不碰 engine，故 Stop 后直接报告 Stopped、退出进程（daemon 线程随进程终止）。
    let _ = shutdown_rx.recv();
    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;
    drop(daemon_thread);
    Ok(())
}
