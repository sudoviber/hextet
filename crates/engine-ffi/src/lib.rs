//! hextet engine FFI（M7 Android 的 Rust 侧绑定，spec §8「engine FFI 化」）。
//!
//! 用 UniFFI 的 proc-macro（`#[uniffi::export]`）把 engine 的关键能力导出成跨语言
//! FFI。本 crate 只做 Rust scaffolding（编译 + 单测）；Kotlin 绑定由 `uniffi-bindgen`
//! 在 `apps/android` 构建时生成（届时给 `uniffi` 加 `cli` feature）。
//!
//! FFI 表面（最小可用集，见 docs/superpowers/plans/2026-08-14-m7-android.md）：
//! - [`load_config`]：读配置 → 打码的配置摘要 JSON（不含网络密钥/私钥）。
//! - [`status`]：读 state.json → 打洞状态 JSON（**不含 WG 统计**——rx/tx/last_handshake
//!   在进程内 gotatun 后端里，跨线程读取需「WG 统计进 state.json」补充切片，见计划 §3）。

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

/// 读 daemon 的 state.json 并返回打洞状态 JSON（**不含 WG 统计**，见模块文档）。
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
    let state_path = cfg.node.state_dir.join("state.json");
    let state = hextet_engine::state::read(&state_path).map_err(|e| format!("读状态失败: {e}"))?;
    serde_json::to_string(&state).map_err(|e| format!("序列化状态失败: {e}"))
}

// 生成 UniFFI 的 `extern "C"` scaffolding（FFI 入口）。
uniffi::include_scaffolding!("hextet");

#[cfg(test)]
mod tests {
    use super::*;
    use hextet_core::network::NetworkKey;

    #[test]
    fn load_config_returns_sanitized_summary() {
        let dir = tempfile::tempdir().unwrap();
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
        let id = hextet_core::identity::NodeIdentity::generate();
        id.save(&key_path).unwrap();
        let cfg_path = dir.path().join("hextet.toml");
        std::fs::write(&cfg_path, text).unwrap();

        let json = load_config(cfg_path.to_string_lossy().into_owned());
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["network_name"], "home");
        assert!(v["prefix"].as_str().unwrap().starts_with("fd"));
        assert!(v["node_address"].as_str().unwrap().starts_with("fd"));
        assert_eq!(v["peers"].as_array().unwrap().len(), 0);
        // 秘密（网络密钥）绝不出现在摘要里；节点公钥是公开信息，可以出现。
        assert!(!json.contains(&nk.to_base64()));
    }
}
