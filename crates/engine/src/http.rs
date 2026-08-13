//! hextet 的 HTTP 状态服务器（切片 B）。
//!
//! 只读地暴露 `hextet status` 的同一份 [`hextet_proto::StatusReport`]：
//! `/healthz` 存活探测、`/api/status` 状态 JSON。
//!
//! 本模块是「HTTP 状态服务器」本身——给定一个 [`hextet_wg::WgBackend`] 与一份
//! [`hextet_core::config::Config`]，构造出可 serve 的 [`axum::Router`]。它被
//! [`crate::daemon`] 接进常驻主循环（`hextet daemon` 一边打洞一边 serve HTTP）；
//! 静态前端托管（`web/` 的 React 构建产物）随切片 C 一起做。
#![deny(missing_docs)]

use std::sync::Arc;
use std::time::SystemTime;

use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
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
    let state = AppState {
        backend,
        cfg: Arc::new(cfg),
    };
    Router::new()
        .route("/healthz", get(healthz))
        .route("/api/status", get(api_status))
        .with_state(state)
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
}
