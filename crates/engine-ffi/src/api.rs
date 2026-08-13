//! FFI 面：engine 控制面的同步导出（M7 切片 D，ADR-0014 D3/D4/D5）。
//!
//! 类型映射纪律（ADR-0012 决策 4）：`Arc<dyn WgBackend>` 是 dyn trait，无 Record 映射，
//! 跨 FFI 只能以**进程内注册表 + `u64` 句柄**传递；`RawFd` 映射为 `i32`（unix 上
//! `RawFd = i32`，恒等转换、无 unsafe）；路径映射为 `String`。

use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use hextet_wg::WgBackend;

use crate::error::FfiError;

/// 进程内后端注册表：`u64` 句柄 → 后端实例（`Arc<dyn WgBackend + Send + Sync>`）。
///
/// `OnceLock` 惰性初始化，`Mutex` 保证并发访问安全（UniFFI 入口同步，但 Kotlin 侧可能
/// 从多线程调用）。句柄由 [`create_backend`] 分配、`stop_daemon` 不回收后端（随
/// VpnService 进程退出回收，ADR-0014 D3 的已知代价）。
static BACKENDS: OnceLock<Mutex<HashMap<u64, Arc<dyn WgBackend + Send + Sync>>>> = OnceLock::new();

/// 已启动的 daemon 控制句柄：`u64` 句柄 → [`DaemonHandle`]。
static DAEMONS: OnceLock<Mutex<HashMap<u64, hextet_engine::daemon::DaemonHandle>>> =
    OnceLock::new();

/// Android 上 `GotatunBackend` 的**具体类型**注册表（与 [`BACKENDS`] 指向同一实例）。
///
/// [`backend_set_tun_fd`] 需要 `GotatunBackend::set_tun_fd`（具体类型方法，不在
/// [`WgBackend`] trait 上），而 `Arc<dyn WgBackend>` 无法 downcast（trait 无 `Any`
/// 上界，且不引入 unsafe）。因此在 `create_backend` 时同时把具体 `Arc<GotatunBackend>`
/// 与 dyn 视图（指针克隆 + unsize 强转，同一实例）分别登记，fd 注入走具体表、spawn 走
/// dyn 表，两条路径闭环在同一实例上（ADR-0014 D3/D4）。
#[cfg(target_os = "android")]
static GOTATUN_BACKENDS: OnceLock<Mutex<HashMap<u64, Arc<hextet_wg_userspace::GotatunBackend>>>> =
    OnceLock::new();

/// 自增句柄计数器（从 1 开始；0 保留为「无句柄」语义，与 Kotlin 侧约定）。
static NEXT_HANDLE: AtomicU64 = AtomicU64::new(1);

/// 平台后端工厂（非 Android）：与 `hextet_engine::backend::platform_default` 同构。
///
/// 只用于 macOS/Linux 分支——让本 crate 在 workspace 门禁（`cargo build --workspace` /
/// `cargo test`）下可编译、可单测（构造空后端，不建真实设备）。Android 分支不走这里：
/// [`create_backend`] 需要在登记 dyn 视图的同时保留具体 `Arc<GotatunBackend>` 供
/// [`backend_set_tun_fd`] 注入 fd，因此 Android 上内联构造（见 [`create_backend`]）。
#[cfg(target_os = "macos")]
fn platform_backend() -> Arc<dyn WgBackend + Send + Sync> {
    Arc::new(hextet_wg_userspace::UserspaceBackend::new())
}

#[cfg(target_os = "linux")]
fn platform_backend() -> Arc<dyn WgBackend + Send + Sync> {
    Arc::new(hextet_wg::kernel::KernelBackend)
}

/// 取回 `handle` 对应的后端 `Arc`（克隆指针，同一实例）。
fn backend(handle: u64) -> Result<Arc<dyn WgBackend + Send + Sync>, FfiError> {
    BACKENDS
        .get_or_init(Default::default)
        .lock()
        .map_err(|_| FfiError::Backend("backend registry lock poisoned".into()))?
        .get(&handle)
        .cloned()
        .ok_or(FfiError::UnknownHandle(handle))
}

/// 构造一个平台后端并登记到进程内注册表，返回自增 `u64` 句柄。
///
/// Android 上构造 `GotatunBackend`（空后端，未注入 fd）；macOS/Linux 上构造对应后端。
/// 返回的句柄随后交给 [`backend_set_tun_fd`]（Android 专用）与 [`spawn_daemon`]。
#[uniffi::export]
pub fn create_backend() -> u64 {
    let id = NEXT_HANDLE.fetch_add(1, Ordering::Relaxed);
    #[cfg(target_os = "android")]
    {
        let gotatun: Arc<hextet_wg_userspace::GotatunBackend> =
            Arc::new(hextet_wg_userspace::GotatunBackend::new());
        let dyn_backend: Arc<dyn WgBackend + Send + Sync> = gotatun.clone();
        GOTATUN_BACKENDS
            .get_or_init(Default::default)
            .lock()
            .expect("gotatun backend registry lock poisoned")
            .insert(id, gotatun);
        BACKENDS
            .get_or_init(Default::default)
            .lock()
            .expect("backend registry lock poisoned")
            .insert(id, dyn_backend);
    }
    #[cfg(not(target_os = "android"))]
    {
        BACKENDS
            .get_or_init(Default::default)
            .lock()
            .expect("backend registry lock poisoned")
            .insert(id, platform_backend());
    }
    id
}

/// 把 JNI 传进来的 VpnService tun fd 注入到后端（Android 专用）。
///
/// 时序上必须在 [`spawn_daemon`]（进而 `WgBackend::apply`）之前调用（ADR-0014 D3/D4）：
/// `set_tun_fd` 只把 fd 存进后端的 `pending_fd`，`apply` 时经 `raw_fd` 接线。重复注入
/// 覆盖旧值。非 Android 平台诚实返回 [`FfiError::Unsupported`]。
#[uniffi::export]
pub fn backend_set_tun_fd(handle: u64, fd: i32) -> Result<(), FfiError> {
    #[cfg(target_os = "android")]
    {
        let raw: std::os::fd::RawFd = fd;
        let gotatun = GOTATUN_BACKENDS
            .get_or_init(Default::default)
            .lock()
            .map_err(|_| FfiError::Backend("gotatun backend registry lock poisoned".into()))?
            .get(&handle)
            .cloned()
            .ok_or(FfiError::UnknownHandle(handle))?;
        gotatun
            .set_tun_fd(raw)
            .map_err(|e| FfiError::Backend(format!("{e:#}")))?;
        Ok(())
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = (handle, fd);
        Err(FfiError::Unsupported(
            "fd injection is only available on Android VpnService".into(),
        ))
    }
}

/// 用 `handle` 对应的后端启动 daemon（`spawn_with_backend` 路径，fd 时序闭环）。
///
/// Android 上本 crate 拥有自己的 tokio runtime：spawn 一个专用线程 `block_on` 持有
/// runtime（ADR-0012 决策 6 / ADR-0014 D3），再经 `spawn_with_backend` 把主循环挂上去。
/// 返回后 daemon 在后台运行，`DaemonHandle` 存入并行注册表供 [`stop_daemon`] 停机。
#[uniffi::export]
pub fn spawn_daemon(handle: u64, config_path: String) -> Result<(), FfiError> {
    let backend = backend(handle)?;
    {
        let daemons = DAEMONS
            .get_or_init(Default::default)
            .lock()
            .map_err(|_| FfiError::Spawn("daemon registry lock poisoned".into()))?;
        if daemons.contains_key(&handle) {
            return Err(FfiError::AlreadySpawned(handle));
        }
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| FfiError::Runtime(format!("{e:#}")))?;
    let rt_handle = runtime.handle().clone();
    let daemon =
        hextet_engine::daemon::spawn_with_backend(rt_handle, Path::new(&config_path), backend)
            .map_err(|e| FfiError::Spawn(format!("{e:#}")))?;
    // 专用线程持有 runtime 常驻（daemon 主循环任务跑在上面）。第一片诚实接受：该线程在
    // 进程存续期内不退出，runtime 随进程结束回收（ADR-0014 D3 的已知代价）。
    std::thread::Builder::new()
        .name("hextet-engine-ffi-runtime".into())
        .spawn(move || {
            runtime.block_on(std::future::pending::<()>());
        })
        .map_err(|e| FfiError::Spawn(format!("runtime thread spawn failed: {e}")))?;
    DAEMONS
        .get_or_init(Default::default)
        .lock()
        .map_err(|_| FfiError::Spawn("daemon registry lock poisoned".into()))?
        .insert(handle, daemon);
    Ok(())
}

/// 请求 `handle` 对应的 daemon 停机（非阻塞；`watch` 信号，幂等）。
///
/// 无 daemon 时是空操作（graceful）。第一片只暴露 `stop`，不暴露 `wait`（`wait` 是
/// async，由 Kotlin 侧持有 runtime 收尾，避免跨 FFI 阻塞——ADR-0014 D3）。后端实例
/// 保留在注册表中，随 VpnService 进程退出回收。
#[uniffi::export]
pub fn stop_daemon(handle: u64) {
    if let Some(daemon) = DAEMONS
        .get_or_init(Default::default)
        .lock()
        .expect("daemon registry lock poisoned")
        .remove(&handle)
    {
        daemon.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 注册表生命周期：`create_backend` 返回递增且唯一的句柄，`stop_daemon` 对未 spawn
    /// 的句柄是空操作，未知句柄的 `spawn_daemon` 报错——全程不碰真实 WG 设备。
    #[test]
    fn registry_lifecycle_without_real_device() {
        let a = create_backend();
        let b = create_backend();
        assert_ne!(a, b, "句柄必须单调递增且唯一");

        stop_daemon(a);
        stop_daemon(b);

        // 未知句柄不 panic：spawn_daemon 在查注册表即报错（不建 runtime、不建设备）。
        assert!(matches!(
            spawn_daemon(u64::MAX, "/dev/null".into()),
            Err(FfiError::UnknownHandle(_))
        ));
    }

    /// `backend_set_tun_fd` 对未知句柄报错（android 报 `UnknownHandle`、其余平台报
    /// `Unsupported`），两者都不 panic；`stop_daemon` 幂等。
    #[test]
    fn set_tun_fd_and_stop_are_graceful_on_unknown_handle() {
        assert!(backend_set_tun_fd(u64::MAX, 0).is_err());
        stop_daemon(u64::MAX);
    }

    /// `RawFd` 在 unix 上是 `i32` 的别名，`i32 → RawFd` 是恒等转换、无 unsafe。
    #[test]
    #[cfg(unix)]
    fn i32_to_rawfd_is_identity() {
        let fd: i32 = 42;
        let raw: std::os::fd::RawFd = fd;
        assert_eq!(raw, 42);
    }
}
