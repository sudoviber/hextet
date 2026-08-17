//! hextet 的 HTTP 状态服务器（切片 B）。
//!
//! 只读地暴露 `hextet status` 的同一份 [`hextet_proto::StatusReport`]：
//! `/healthz` 存活探测、`/api/status` 状态 JSON。
//!
//! 本模块是「HTTP 状态服务器」本身——给定一个 [`hextet_wg::WgBackend`] 与一份
//! [`hextet_core::config::Config`]，构造出可 serve 的 [`axum::Router`]。它被
//! [`crate::daemon`] 接进常驻主循环（`hextet daemon` 一边打洞一边 serve HTTP）。
//!
//! ## 静态前端托管（切片 C，config-gated，默认关）
//!
//! 当配置里 `[node] web_dir` 指向一个目录时，该目录里的构建产物（`web/` 的 React
//! 前端）经 [`tower_http::services::ServeDir`] 在 `/` 下静态托管，`/` 自动回退到
//! `index.html`；`/healthz` 与 `/api/status` 始终优先于静态回退。
//!
//! **偏离 spec 说明（诚实标注）**：spec §3 D6 说「路由器/headless 用 rust-embed 把
//! 前端编进 daemon，单二进制」。本切片先用 `ServeDir` 从磁盘路径读文件，换取开发/
//! 测试的简单性（`cargo test` 无需引入 rust-embed 的编译期资源，`web_dir` 指向 `web/dist`
//! 即可本地联调）；rust-embed 的「单二进制」优化留作路由器构建（`apps/desktop` 之后
//! 的后续切片）再做，届时 `web_dir` 仍作为可选的磁盘覆盖路径保留。
#![deny(missing_docs)]

use std::sync::Arc;
use std::time::SystemTime;

use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::http::{HeaderValue, StatusCode};
use axum::routing::get;
use hextet_core::config::Config;
use hextet_proto::StatusReport;

/// 状态服务器的共享状态。
///
/// backend 是调用方（[`crate::daemon`]）与打洞主循环共享的同一个 `Arc`——用户态后端
/// （`hextet_wg_userspace::UserspaceBackend`）持有 `Mutex` 注册表与 `DeviceHandle`，
/// **不** `Clone`，不能为 HTTP 服务器再造一份；内核后端（`KernelBackend`）与
/// [`hextet_wg::mock::MockBackend`] 同样不 `Clone`。因此这里直接接收并存储该 `Arc`，
/// 不再内部 `Arc::new` 包一层。
#[derive(Clone)]
struct AppState {
    backend: Arc<dyn hextet_wg::WgBackend + Send + Sync>,
    cfg: Arc<Config>,
}

/// 构造状态服务器的 [`axum::Router`]。
///
/// `backend` 是与打洞主循环共享的同一 `Arc<dyn WgBackend + Send + Sync>`（用户态后端
/// 不 `Clone`，必须共享实例），`cfg` 提供 peer 映射与状态文件路径。返回的 router
/// 可在 tokio 里 serve，也可用 `tower::ServiceExt::oneshot` 无头测试（见模块底部）。
pub fn router(backend: Arc<dyn hextet_wg::WgBackend + Send + Sync>, cfg: Config) -> Router {
    let web_dir = cfg.node.web_dir.clone();
    let state = AppState {
        backend,
        cfg: Arc::new(cfg),
    };
    let router = Router::new()
        .route("/healthz", get(healthz))
        .route("/api/status", get(api_status))
        // Tauri webview 是唯一的跨源消费者（`tauri://localhost` → `http://127.0.0.1:8080`）。
        // 必须用精确白名单而非 `permissive()`：`/api/status` 会泄露对端的真实 endpoint
        // 与网络拓扑，任意第三方网页可经 DNS rebinding 跨源读走（默认绑 loopback 挡不住
        // 浏览器发起的 localhost 请求）。vite dev（`/api` 走代理）与 `web_dir`（同源托管）
        // 都无需 CORS。
        .layer(tower_http::cors::CorsLayer::new().allow_origin([
            HeaderValue::from_static("tauri://localhost"),
            HeaderValue::from_static("http://tauri.localhost"),
        ]))
        .with_state(state);

    // 静态前端托管：仅在 [node] web_dir 指向目录时启用，`/` 回退到 index.html。
    // `/healthz` 与 `/api/status` 已在上方注册，axum 会先匹配它们，静态回退只在
    // 未命中任何 API 路由时才接手（ServeDir 找不到文件时返回 404）。
    match web_dir {
        Some(dir) => router.fallback_service(tower_http::services::ServeDir::new(dir)),
        None => router,
    }
}

/// 存活探测：恒返回 `{"status":"ok"}`。
async fn healthz() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok" }))
}

/// 状态报告：与 `hextet status --json` 完全相同的 `StatusReport` JSON。
async fn api_status(
    State(state): State<AppState>,
) -> Result<Json<StatusReport>, (StatusCode, Json<serde_json::Value>)> {
    match crate::status::build_report(&state.cfg, state.backend.as_ref(), SystemTime::now()) {
        Ok(report) => Ok(Json(report)),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e.to_string() })),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    /// 渲染一份临时配置（无 peer），`state_dir` 指向临时目录。
    fn test_config(state_dir: &std::path::Path) -> Config {
        let nk = hextet_core::network::NetworkKey::generate();
        let text = Config::render_template(
            "home",
            &nk,
            std::path::Path::new("node.key"),
            4193,
            Some(state_dir),
        );
        let path = state_dir.join("hextet.toml");
        std::fs::write(&path, text).unwrap();
        Config::load(&path, None).unwrap()
    }

    /// 同 [`test_config`]，但可选地在 `[node]` 段追加 `web_dir`。
    fn test_config_with_web_dir(
        state_dir: &std::path::Path,
        web_dir: Option<&std::path::Path>,
    ) -> Config {
        let nk = hextet_core::network::NetworkKey::generate();
        let mut text = Config::render_template(
            "home",
            &nk,
            std::path::Path::new("node.key"),
            4193,
            Some(state_dir),
        );
        if let Some(dir) = web_dir {
            text = text.replace(
                "key_file = \"node.key\"",
                &format!("key_file = \"node.key\"\nweb_dir = \"{}\"", dir.display()),
            );
        }
        let path = state_dir.join("hextet.toml");
        std::fs::write(&path, text).unwrap();
        Config::load(&path, None).unwrap()
    }

    #[tokio::test]
    async fn healthz_returns_ok() {
        let dir = tempfile::tempdir().unwrap();
        let app = router(
            Arc::new(hextet_wg::mock::MockBackend::default()),
            test_config(dir.path()),
        );
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["status"], "ok");
    }

    #[tokio::test]
    async fn api_status_returns_valid_report() {
        let dir = tempfile::tempdir().unwrap();
        let app = router(
            Arc::new(hextet_wg::mock::MockBackend::default()),
            test_config(dir.path()),
        );
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        // 反序列化回 StatusReport：证明线格式与 `hextet status --json` 一致。
        let report: StatusReport = serde_json::from_slice(&body).unwrap();
        // 没有 state.json → daemon 为 null；mock 后端没有 peer → peers 为空数组。
        assert!(report.daemon.is_none());
        assert!(report.peers.is_empty());
    }

    #[tokio::test]
    async fn serves_static_index_when_web_dir_set() {
        let dir = tempfile::tempdir().unwrap();
        let web = dir.path().join("web");
        std::fs::create_dir_all(&web).unwrap();
        let index = "<!doctype html><title>hextet</title>";
        std::fs::write(web.join("index.html"), index).unwrap();
        let app = router(
            Arc::new(hextet_wg::mock::MockBackend::default()),
            test_config_with_web_dir(dir.path(), Some(&web)),
        );

        // GET / → index.html 内容
        let response = app
            .clone()
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&body[..], index.as_bytes());

        // GET /api/status 仍优先于静态回退，返回合法 JSON 报告
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let report: StatusReport = serde_json::from_slice(&body).unwrap();
        assert!(report.daemon.is_none());
        assert!(report.peers.is_empty());
    }

    #[tokio::test]
    async fn api_status_sets_cors_for_tauri_origin() {
        let dir = tempfile::tempdir().unwrap();
        let app = router(
            Arc::new(hextet_wg::mock::MockBackend::default()),
            test_config(dir.path()),
        );
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/status")
                    .header("Origin", "tauri://localhost")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()["access-control-allow-origin"],
            "tauri://localhost"
        );
    }

    /// 任意第三方网页（DNS rebinding）不得跨源读 `/api/status`：不白名单的 origin
    /// 不返回 `access-control-allow-origin`，浏览器会挡住响应。
    #[tokio::test]
    async fn api_status_rejects_foreign_origin() {
        let dir = tempfile::tempdir().unwrap();
        let app = router(
            Arc::new(hextet_wg::mock::MockBackend::default()),
            test_config(dir.path()),
        );
        for origin in ["https://evil.example", "http://example.com"] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri("/api/status")
                        .header("Origin", origin)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert!(
                !response.headers().contains_key("access-control-allow-origin"),
                "origin {origin} 不该被允许跨源读状态"
            );
        }
    }

    #[tokio::test]
    async fn no_static_fallback_when_web_dir_unset() {
        let dir = tempfile::tempdir().unwrap();
        let app = router(
            Arc::new(hextet_wg::mock::MockBackend::default()),
            test_config(dir.path()),
        );
        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        // 没有 web_dir → 根路径没有静态回退，保持 404（行为不变）
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
