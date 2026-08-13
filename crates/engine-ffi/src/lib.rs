//! hextet engine FFI（M7 Android 的 Rust 侧绑定，spec §8「engine FFI 化」）。
//!
//! 用 UniFFI 的 **UDL**（`src/hextet.udl` + `build.rs` 的 `generate_scaffolding` +
//! `include_scaffolding!`）把 engine 的关键能力导出成跨语言 FFI（计划初稿写的
//! `#[uniffi::export]` proc-macro 路线后来改用 UDL，见
//! docs/superpowers/plans/2026-08-14-m7-android.md）。本 crate 只做 Rust scaffolding
//! （编译 + 单测）；Kotlin 绑定由 `uniffi-bindgen` 在 `apps/android` 构建时生成
//! （届时给 `uniffi` 加 `cli` feature）。
//!
//! FFI 表面（最小可用集，见 docs/superpowers/plans/2026-08-14-m7-android.md）：
//! - [`load_config`]：读配置 → 打码的配置摘要 JSON（不含网络密钥/私钥）。
//! - [`status`]：读 state.json → 完整状态报告 JSON（**含 WG 统计**——rx/tx/last_handshake
//!   自 state.json v7 起已入盘，跨线程/跨进程读不再需要访问进程内 gotatun 后端）。

// UniFFI 生成的 `extern "C"` scaffolding 在 edition 2024 下用 `#[unsafe(no_mangle)]`
// （no_mangle 是 unsafe 属性），而 workspace 默认 `unsafe_code = "deny"`。这里与
// `platform::macos`/`wg_tun_name` 一样收窄放行：unsafe 只存在于 UniFFI 生成的代码里。
#![allow(unsafe_code)]

use std::path::Path;

use hextet_core::addr::derive_node_addr;
use serde::Serialize;

/// 打码的配置摘要（`load_config` 的返回，**不含网络密钥/私钥**）。
#[derive(Serialize)]
struct ConfigSummary {
    /// 网络名。
    network_name: String,
    /// 网络 ULA /48 前缀。
    prefix: String,
    /// 本节点 overlay 地址。
    node_address: String,
    /// 本节点公钥 base64。
    node_public_key: String,
    /// peer 摘要（名 + overlay 地址 + 公钥）。
    peers: Vec<PeerSummary>,
}

/// peer 摘要。
#[derive(Serialize)]
struct PeerSummary {
    /// peer 名。
    name: String,
    /// peer 公钥 base64。
    public_key: String,
    /// peer 的 overlay 地址。
    address: String,
}

/// 读配置并返回打码的配置摘要 JSON（供 App 展示网络/节点/peer 信息，不含秘密）。
///
/// 失败时返回 `{"error": "..."}` JSON（UniFFI flat-error 的 UDL 语法较重，第一片用
/// JSON 错误对象 + 成功 JSON 的约定，Kotlin 侧判 `error` 键区分）。
pub fn load_config(path: String) -> String {
    match load_config_inner(&path) {
        Ok(json) => json,
        Err(e) => serde_json::json!({ "error": e }).to_string(),
    }
}

fn load_config_inner(path: &str) -> Result<String, String> {
    let (cfg, id) = hextet_core::config::load_config_and_identity(Path::new(path))
        .map_err(|e| format!("加载配置失败: {e}"))?;
    let own =
        derive_node_addr(cfg.prefix, &id.public()).map_err(|e| format!("派生地址失败: {e}"))?;
    let summary = ConfigSummary {
        network_name: cfg.network_name.clone(),
        prefix: cfg.prefix.to_string(),
        node_address: own.address.to_string(),
        node_public_key: id.public().to_base64(),
        peers: cfg
            .peers
            .iter()
            .map(|p| PeerSummary {
                name: p.name.clone(),
                public_key: p.public_key.to_base64(),
                address: p.addr.address.to_string(),
            })
            .collect(),
    };
    serde_json::to_string(&summary).map_err(|e| format!("序列化配置摘要失败: {e}"))
}

/// 读 daemon 的 state.json 并返回完整状态报告 JSON（**含 WG 统计**，state.json v7 起）。
///
/// 失败时返回 `{"error": "..."}` JSON（同 [`load_config`] 的约定）。
pub fn status(config_path: String) -> String {
    match status_inner(&config_path) {
        Ok(json) => json,
        Err(e) => serde_json::json!({ "error": e }).to_string(),
    }
}

fn status_inner(config_path: &str) -> Result<String, String> {
    let (cfg, _id) = hextet_core::config::load_config_and_identity(Path::new(config_path))
        .map_err(|e| format!("加载配置失败: {e}"))?;
    // 从 state.json 组装完整报告（含 WG 统计，state.json v7 起），不需要进程内后端。
    let report = hextet_engine::status::build_report_from_state(&cfg, std::time::SystemTime::now())
        .map_err(|e| format!("组装状态报告失败: {e}"))?;
    serde_json::to_string(&report).map_err(|e| format!("序列化状态失败: {e}"))
}

// ---------------------------------------------------------------------------
// daemon 生命周期 FFI（进程内 spawn + 优雅停机，供 Android VpnService 用）。
// ---------------------------------------------------------------------------

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

use hextet_engine::daemon::DaemonHandle;

/// 全局 tokio runtime（daemon 后台任务跑在上面；懒初始化）。
static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
/// daemon 句柄注册表（handle id → DaemonHandle）。
static DAEMONS: std::sync::LazyLock<Mutex<HashMap<u64, DaemonHandle>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));
/// 下一个句柄 id。
static NEXT_HANDLE: AtomicU64 = AtomicU64::new(1);

fn runtime() -> &'static tokio::runtime::Runtime {
    RUNTIME.get_or_init(|| tokio::runtime::Runtime::new().expect("创建 tokio runtime 失败"))
}

/// 进程内 spawn daemon，返回 `{"handle":u64}`（或 `{"error":...}`）。
///
/// 成功时 daemon 后台任务跑在全局 runtime 上；`daemon_shutdown` 用返回的句柄停机。
pub fn daemon_spawn(config_path: String) -> String {
    match daemon_spawn_inner(&config_path) {
        Ok(id) => serde_json::json!({ "handle": id }).to_string(),
        Err(e) => serde_json::json!({ "error": e }).to_string(),
    }
}

fn daemon_spawn_inner(config_path: &str) -> Result<u64, String> {
    // 同步预检：配置/身份能加载才 spawn（fail fast，避免把错误推迟到后台任务里静默失败）。
    let (cfg, id) = hextet_core::config::load_config_and_identity(Path::new(config_path))
        .map_err(|e| format!("加载配置失败: {e}"))?;
    let _ = (cfg, id);
    let handle = runtime()
        .block_on(async {
            hextet_engine::daemon::spawn(Path::new(config_path)).map_err(|e| format!("{e:#}"))
        })
        .map_err(|e| format!("spawn daemon 失败: {e}"))?;
    let id = NEXT_HANDLE.fetch_add(1, Ordering::SeqCst);
    DAEMONS
        .lock()
        .map_err(|_| "daemon 注册表锁中毒".to_string())?
        .insert(id, handle);
    Ok(id)
}

/// 优雅停机并释放句柄，返回 `{}`（成功）或 `{"error":...}`。
pub fn daemon_shutdown(handle: u64) -> String {
    match daemon_shutdown_inner(handle) {
        Ok(()) => serde_json::json!({}).to_string(),
        Err(e) => serde_json::json!({ "error": e }).to_string(),
    }
}

fn daemon_shutdown_inner(handle: u64) -> Result<(), String> {
    let daemon = DAEMONS
        .lock()
        .map_err(|_| "daemon 注册表锁中毒".to_string())?
        .remove(&handle)
        .ok_or_else(|| format!("未找到 daemon 句柄 {handle}"))?;
    runtime()
        .block_on(async { daemon.shutdown().await })
        .map_err(|e| format!("停机失败: {e:#}"))
}

// 生成 UniFFI 的 `extern "C"` scaffolding（FFI 入口）。
uniffi::include_scaffolding!("hextet");

#[cfg(test)]
mod tests {
    use super::*;
    use hextet_core::network::NetworkKey;

    /// 在临时目录里写一份最小可用配置（`home` 网络 + 真实身份文件），返回配置路径。
    fn setup_config(dir: &tempfile::TempDir) -> (std::path::PathBuf, NetworkKey) {
        let nk = NetworkKey::generate();
        let text = hextet_core::config::Config::render_template(
            "home",
            &nk,
            Path::new("node.key"),
            4193,
            Some(dir.path()),
        );
        // render_template 只产 node.key 的引用；写一个真实身份文件供 load_config_and_identity 读。
        let key_path = dir.path().join("node.key");
        hextet_core::identity::NodeIdentity::generate()
            .save(&key_path)
            .unwrap();
        let cfg_path = dir.path().join("hextet.toml");
        std::fs::write(&cfg_path, text).unwrap();
        (cfg_path, nk)
    }

    #[test]
    fn load_config_returns_sanitized_summary() {
        let dir = tempfile::tempdir().unwrap();
        let (cfg_path, nk) = setup_config(&dir);

        let json = load_config(cfg_path.to_string_lossy().into_owned());
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["network_name"], "home");
        assert!(v["prefix"].as_str().unwrap().starts_with("fd"));
        assert!(v["node_address"].as_str().unwrap().starts_with("fd"));
        assert_eq!(v["peers"].as_array().unwrap().len(), 0);
        // 秘密（网络密钥）绝不出现在摘要里；节点公钥是公开信息，可以出现。
        assert!(!json.contains(&nk.to_base64()));
    }

    #[test]
    fn status_returns_report_json_without_daemon() {
        let dir = tempfile::tempdir().unwrap();
        let (cfg_path, _nk) = setup_config(&dir);

        let json = status(cfg_path.to_string_lossy().into_owned());
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(
            v.get("error").is_none(),
            "无 daemon 也应是成功报告，得到 {json}"
        );
        assert_eq!(
            v["daemon"],
            serde_json::Value::Null,
            "无 state.json → daemon null"
        );
        assert!(v["peers"].is_array(), "peers 应是数组");
    }

    #[test]
    fn status_missing_config_returns_error_json() {
        let json = status("/nonexistent/hextet.toml".to_string());
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(v["error"].is_string(), "应返回 error 字段，得到 {json}");
    }

    #[test]
    fn daemon_spawn_missing_config_returns_error_json() {
        // 配置不存在 → 在 root/真实数据面之前就报错，无需 root 即可验证错误路径。
        let json = daemon_spawn("/nonexistent/hextet.toml".to_string());
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(v["error"].is_string(), "应返回 error 字段，得到 {json}");
    }

    #[test]
    fn daemon_shutdown_unknown_handle_returns_error_json() {
        let json = daemon_shutdown(u64::MAX);
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(v["error"].is_string(), "应返回 error 字段，得到 {json}");
    }
}
