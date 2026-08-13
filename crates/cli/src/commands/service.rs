//! `hextet service run`：Windows 服务入口（ADR-0011 决策 3）。
//!
//! Windows 上把 `hextet daemon` 包装成 Windows service（`windows-service` crate，
//! LocalSystem 账户）。服务内用 [`hextet_engine::daemon::spawn`] 进程内运行守护进程，
//! `ServiceControl::Stop` 时经 [`DaemonHandle::shutdown`](hextet_engine::daemon::DaemonHandle)
//! 优雅停机（移除通告路由后退出）。
//!
//! 安装/卸载用系统自带 `sc.exe`（见 docs/guides/install.md 的 Windows 章节，后续补）：
//! ```text
//! sc.exe create hextet binPath="C:\Program Files\hextet\hextet.exe service run" start=auto
//! sc.exe start hextet
//! sc.exe stop hextet
//! sc.exe delete hextet
//! ```

/// Arguments for the service command（无参数：配置路径固定为
/// `C:\ProgramData\hextet\hextet.toml`，与 Unix 的 `/etc/hextet` 对齐）。
#[derive(clap::Args)]
pub struct Args {}

/// Run the service command.
pub fn run(_args: Args) -> anyhow::Result<()> {
    #[cfg(not(windows))]
    {
        anyhow::bail!("hextet service 仅支持 Windows（其他平台用 launchd/systemd 单元）");
    }

    #[cfg(windows)]
    {
        imp::main()
    }
}

#[cfg(windows)]
mod imp {
    use std::ffi::OsString;
    use std::path::Path;
    use std::sync::mpsc;
    use std::time::Duration;

    use anyhow::Context as _;
    use windows_service::{
        define_windows_service,
        service::{
            ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
            ServiceType,
        },
        service_control_handler::{self, ServiceControlHandlerResult},
        service_dispatcher,
    };

    const SERVICE_NAME: &str = "hextet";
    const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;
    /// 固定配置路径（Windows 惯例：`C:\ProgramData\hextet\hextet.toml`）。
    const CONFIG_PATH: &str = "C:\\ProgramData\\hextet\\hextet.toml";

    /// 启动服务分发器（阻塞直到服务停止）。
    pub fn main() -> anyhow::Result<()> {
        service_dispatcher::start(SERVICE_NAME, ffi_service_main)
            .map_err(|e| anyhow::anyhow!("启动服务分发器失败: {e}"))
    }

    // 生成 `ffi_service_main`（SCM 的低层入口），把服务参数解析后转交 `my_service_main`。
    define_windows_service!(ffi_service_main, my_service_main);

    /// 服务入口（SCM 在后台线程调用；此刻无 stdout/stderr，日志走 tracing）。
    fn my_service_main(_arguments: Vec<OsString>) {
        if let Err(e) = run_service() {
            // 服务内无 stdout/stderr；tracing 已由 run_service 初始化为日志文件（若失败
            // 则无从落盘，仅 eprintln 兜底）。
            eprintln!("hextet 服务运行失败: {e:#}");
        }
    }

    fn run_service() -> anyhow::Result<()> {
        // 初始化日志（服务内无 stdout/stderr，默认落到 stderr 即丢失；落文件是后续
        // TODO，先保持与 CLI daemon 一致的默认行为）。
        tracing_subscriber::fmt().with_ansi(false).init();

        let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>();
        let event_handler = move |control_event| -> ServiceControlHandlerResult {
            match control_event {
                ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                ServiceControl::Stop => {
                    let _ = shutdown_tx.send(());
                    ServiceControlHandlerResult::NoError
                }
                _ => ServiceControlHandlerResult::NotImplemented,
            }
        };
        let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;
        status_handle.set_service_status(ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: ServiceState::Running,
            controls_accepted: ServiceControlAccept::STOP,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })?;

        // 进程内 spawn 守护进程（DaemonHandle），阻塞等 Stop 信号后优雅停机。
        let rt = tokio::runtime::Runtime::new().context("创建 tokio runtime")?;
        rt.block_on(async {
            let handle = hextet_engine::daemon::spawn(Path::new(CONFIG_PATH))?;
            // 阻塞等 Stop 信号（std mpsc 放到 spawn_blocking，避免占住 async worker）。
            let _ = tokio::task::spawn_blocking(move || shutdown_rx.recv()).await;
            handle.shutdown().await
        })?;

        status_handle.set_service_status(ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: ServiceState::Stopped,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })?;
        Ok(())
    }
}
