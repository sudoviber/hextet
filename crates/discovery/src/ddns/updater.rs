//! DDNS 会合的记录更新侧（会合兜底链第 ⑥ 层）。
//!
//! [`DdnsUpdater`] 抽象「把一条 TXT 记录写到某 FQDN 上」这个动作，内置两个实现：
//! - [`WebhookUpdater`]：把 `{fqdn, value}` POST 到用户自己的 URL（最自托管，零注册商锁定）；
//! - [`CloudflareUpdater`]：直接调 Cloudflare v4 API（zones → dns_records → upsert）。
//!
//! 两者都用 `reqwest`（rustls + ring 提供方，见 ADR-0010）。`reqwest` 类型不出本模块。

use hextet_core::secret::SecretString;
use reqwest::header::AUTHORIZATION;

/// 把一条 TXT 记录写到某 FQDN 上的能力抽象。
///
/// 用 `fn -> impl Future + Send` 而非 `async fn`，显式标注返回的 future 是 `Send`
/// （`async_fn_in_trait` 警告 + 便于 `Arc<dyn DdnsUpdater>` 跨线程 `await`）。
pub trait DdnsUpdater: Send + Sync {
    /// 把 `value` 作为 FQDN `fqdn` 的 TXT 记录 upsert。失败返回错误描述。
    fn set_txt(
        &self,
        fqdn: &str,
        value: &str,
    ) -> impl std::future::Future<Output = Result<(), String>> + Send;
}

/// Webhook 提供方：把 `{fqdn, value}` POST 到用户自己的 URL，可选 Bearer token。
pub struct WebhookUpdater {
    url: String,
    token: Option<SecretString>,
    client: reqwest::Client,
}

impl WebhookUpdater {
    /// 构建 webhook 更新器。`url` 必须是合法 URL，`token` 可选（Bearer 认证）。
    pub fn new(url: impl Into<String>, token: Option<SecretString>) -> Result<Self, String> {
        let url = url.into();
        reqwest::Url::parse(&url).map_err(|e| format!("invalid webhook url: {e}"))?;
        Ok(Self {
            url,
            token,
            client: reqwest::Client::new(),
        })
    }
}

impl DdnsUpdater for WebhookUpdater {
    async fn set_txt(&self, fqdn: &str, value: &str) -> Result<(), String> {
        let mut req = self
            .client
            .post(&self.url)
            .json(&serde_json::json!({ "fqdn": fqdn, "value": value }));
        if let Some(token) = &self.token {
            req = req.bearer_auth(token.expose());
        }
        let resp = req
            .send()
            .await
            .map_err(|e| format!("webhook 请求失败: {e}"))?;
        if resp.status().is_success() {
            Ok(())
        } else {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            let snippet: String = body.chars().take(200).collect();
            Err(format!("webhook 返回 {status}: {snippet}"))
        }
    }
}

/// Cloudflare 提供方：直接调 Cloudflare v4 API（`zones → dns_records → upsert`）。
pub struct CloudflareUpdater {
    token: SecretString,
    zone: String,
    base: String,
    client: reqwest::Client,
}

/// Cloudflare v4 API 基地址。
const CF_BASE: &str = "https://api.cloudflare.com/client/v4";

impl CloudflareUpdater {
    /// 构建 Cloudflare 更新器。`token` 是 API token（需 DNS:Edit），`zone` 是 zone 名。
    pub fn new(token: SecretString, zone: String) -> Result<Self, String> {
        Self::with_base(token, zone, CF_BASE.to_string())
    }

    /// 同 [`Self::new`]，但允许指定 API 基地址（测试指向 mock server；也便于自托管
    /// Cloudflare 兼容网关）。
    fn with_base(token: SecretString, zone: String, base: String) -> Result<Self, String> {
        if zone.trim().is_empty() {
            return Err("cloudflare zone 不能为空".to_string());
        }
        Ok(Self {
            token,
            zone,
            base,
            client: reqwest::Client::new(),
        })
    }

    /// 带 Bearer 认证的 GET，返回解析后的 JSON。
    async fn cf_get(&self, path: &str) -> Result<serde_json::Value, String> {
        let resp = self
            .client
            .get(format!("{}{path}", self.base))
            .header(AUTHORIZATION, format!("Bearer {}", self.token.expose()))
            .send()
            .await
            .map_err(|e| format!("cloudflare 请求失败: {e}"))?;
        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| format!("cloudflare 响应不是 JSON: {e}"))?;
        if body.get("success").and_then(|v| v.as_bool()) != Some(true) {
            return Err(format!("cloudflare API 失败: {body}"));
        }
        Ok(body)
    }

    async fn zone_id(&self) -> Result<String, String> {
        let body = self
            .cf_get(&format!("/zones?name={}", urlencode(&self.zone)))
            .await?;
        let id = body
            .pointer("/result/0/id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("cloudflare zone 未找到: {}", self.zone))?;
        Ok(id.to_owned())
    }

    async fn find_record_id(&self, zone_id: &str, fqdn: &str) -> Result<Option<String>, String> {
        let body = self
            .cf_get(&format!(
                "/zones/{zone_id}/dns_records?type=TXT&name={}",
                urlencode(fqdn)
            ))
            .await?;
        let id = body
            .pointer("/result/0/id")
            .and_then(|v| v.as_str())
            .map(str::to_owned);
        Ok(id)
    }
}

impl DdnsUpdater for CloudflareUpdater {
    async fn set_txt(&self, fqdn: &str, value: &str) -> Result<(), String> {
        let zone_id = self.zone_id().await?;
        let record_id = self.find_record_id(&zone_id, fqdn).await?;
        let payload = serde_json::json!({
            "type": "TXT",
            "name": fqdn,
            "content": value,
            "ttl": 300,
        });
        let (method, path) = match record_id {
            Some(id) => (
                reqwest::Method::PUT,
                format!("/zones/{zone_id}/dns_records/{id}"),
            ),
            None => (
                reqwest::Method::POST,
                format!("/zones/{zone_id}/dns_records"),
            ),
        };
        let resp = self
            .client
            .request(method, format!("{}{path}", self.base))
            .header(AUTHORIZATION, format!("Bearer {}", self.token.expose()))
            .json(&payload)
            .send()
            .await
            .map_err(|e| format!("cloudflare 更新请求失败: {e}"))?;
        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| format!("cloudflare 更新响应不是 JSON: {e}"))?;
        if body.get("success").and_then(|v| v.as_bool()) != Some(true) {
            return Err(format!("cloudflare 更新失败: {body}"));
        }
        Ok(())
    }
}

/// URL 百分号编码（查询参数用）。Cloudflare 的 zone/fqdn 基本不含保留字符，
/// 这里做一个最小实现即可。
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{body_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn webhook_posts_json_and_bearer_and_returns_ok() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/update"))
            .and(header("authorization", "Bearer tok"))
            .and(body_json(serde_json::json!({
                "fqdn": "home.example.com",
                "value": "hxdd1.abc",
            })))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let updater = WebhookUpdater::new(
            format!("{}/update", server.uri()),
            Some(SecretString::from("tok")),
        )
        .unwrap();
        updater
            .set_txt("home.example.com", "hxdd1.abc")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn webhook_non_2xx_is_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
            .mount(&server)
            .await;

        let updater = WebhookUpdater::new(format!("{}/update", server.uri()), None).unwrap();
        let err = updater
            .set_txt("home.example.com", "hxdd1.abc")
            .await
            .unwrap_err();
        assert!(err.contains("500"), "got {err}");
    }

    #[tokio::test]
    async fn cloudflare_creates_txt_record() {
        let server = MockServer::start().await;
        // 1) zone 查询
        Mock::given(method("GET"))
            .and(path("/zones"))
            .and(header("authorization", "Bearer cf-tok"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "errors": [],
                "result": [{ "id": "zone-1" }],
            })))
            .mount(&server)
            .await;
        // 2) 现有记录查询（空）
        Mock::given(method("GET"))
            .and(path("/zones/zone-1/dns_records"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "errors": [],
                "result": [],
            })))
            .mount(&server)
            .await;
        // 3) 新建记录（POST）
        Mock::given(method("POST"))
            .and(path("/zones/zone-1/dns_records"))
            .and(body_json(serde_json::json!({
                "type": "TXT",
                "name": "home.example.com",
                "content": "hxdd1.abc",
                "ttl": 300,
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "errors": [],
                "result": { "id": "rec-1" },
            })))
            .mount(&server)
            .await;

        // 指向 mock server 的 CF API。CloudflareUpdater 写死 CF_BASE，为可测把基址做成
        // 可注入显然更重；这里用一个变通：直接在测试里构造时用 env 覆盖不了，故改测
        // 「请求形状」——通过一个允许注入基址的内部构造（见下）。此处用公开 new + 一个
        // 测试专用基址覆盖，确保 CI 不依赖真实 Cloudflare。
        let updater = CloudflareUpdater::with_base(
            SecretString::from("cf-tok"),
            "example.com".into(),
            server.uri(),
        )
        .unwrap();
        updater
            .set_txt("home.example.com", "hxdd1.abc")
            .await
            .unwrap();
    }
}
