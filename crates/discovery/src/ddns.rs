//! 自托管 DDNS 会合（协议规范：docs/protocol/ddns.md、ADR-0011）。
//!
//! 会合兜底链第 ⑥ 层：用户自己的域名 + 注册商 API。本模块**不绑定任何注册商**——
//! 调用方给一个「更新 URL 模板」，`{address}` 占位符被替换成本机 IPv6 地址后经
//! HTTP(S) 发出；查询侧解析对端域名的 AAAA 记录。`ureq` 与系统 DNS 解析的类型
//! **不出本模块**，全部封装在 [`DdnsClient`] 后面（与 ADR-0005「mainline 类型不出
//! client 模块」同一条纪律），HTTP 与 DNS 边界抽象成 [`DdnsTransport`]，单测用 mock
//! 覆盖、绝不发真实请求、绝不依赖真实凭据。

use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6, ToSocketAddrs};

/// DDNS 传输边界：HTTP 更新 + AAAA 解析。
///
/// 抽象出来是为了让单元测试**不发真实网络请求、不需要真实凭据**——测试用一个
/// 记录型 mock 实现本 trait；生产用 [`HttpDdnsTransport`]。
pub trait DdnsTransport: Send + Sync {
    /// 对渲染好的 URL 发一次更新请求（URL 里已含本机地址与用户自己的 token/域名）。
    fn update(&self, url: &str) -> Result<(), String>;

    /// 解析 `host` 的 AAAA 记录，返回其全部 IPv6 地址。
    fn resolve_aaaa(&self, host: &str) -> Result<Vec<Ipv6Addr>, String>;
}

/// 生产传输：`ureq` 发 HTTP(S) 更新，`std::net::ToSocketAddrs` 走系统 DNS 解析 AAAA。
///
/// 更新是同步阻塞的——DDNS 只在低频周期（~10min）与地址变化时触发一次，且单次
/// 请求远小于 1s，这一路本来就是尽力而为的兜底，阻塞一个 worker 可接受。
#[derive(Debug, Default)]
pub struct HttpDdnsTransport;

impl DdnsTransport for HttpDdnsTransport {
    fn update(&self, url: &str) -> Result<(), String> {
        let resp = ureq::get(url)
            .call()
            .map_err(|e| format!("DDNS 更新请求失败: {e}"))?;
        let status = resp.status();
        if (200..300).contains(&status) {
            Ok(())
        } else {
            Err(format!("DDNS 更新返回非 2xx 状态码: {status}"))
        }
    }

    fn resolve_aaaa(&self, host: &str) -> Result<Vec<Ipv6Addr>, String> {
        let addrs = (host, 0)
            .to_socket_addrs()
            .map_err(|e| format!("解析 {host} 的 AAAA 记录失败: {e}"))?;
        Ok(addrs
            .filter_map(|a| match a {
                SocketAddr::V6(v6) => Some(*v6.ip()),
                // hextet 是 IPv6-only 的：AAAA 之外的记录直接丢弃
                SocketAddr::V4(_) => None,
            })
            .collect())
    }
}

/// 一次 DDNS 会合发布/查询的客户端。
///
/// 持有「更新 URL 模板」与一个 [`DdnsTransport`]。发布侧用模板，查询侧用域名——
/// 两端各自的配置决定各自的行为，客户端本身对任何注册商都无感。
pub struct DdnsClient {
    update_url: String,
    transport: Box<dyn DdnsTransport + Send + Sync>,
}

impl DdnsClient {
    /// 用给定传输构建客户端（单测注入 mock；生产用 [`HttpDdnsTransport`]）。
    pub fn new(update_url: String, transport: Box<dyn DdnsTransport + Send + Sync>) -> Self {
        Self {
            update_url,
            transport,
        }
    }

    /// 发布本机地址：对每个 endpoint 的地址各发一次更新。
    ///
    /// AAAA 记录只承载地址、不承载端口（ADR-0011），所以这里的 `port` 被忽略，
    /// 只把地址填进 `{address}`。地址变化时本机会有多个可用 GUA，逐一更新。
    pub fn publish(&self, endpoints: &[SocketAddrV6]) -> Result<(), String> {
        for ep in endpoints {
            let url = render_update_url(&self.update_url, *ep.ip())?;
            self.transport.update(&url)?;
        }
        Ok(())
    }

    /// 查询对端：解析 `host` 的 AAAA 记录，过滤出可用地址，配上固定 `port`。
    ///
    /// 解析失败或没有可用地址时返回空——与 DHT `lookup` 的「未找到返回空」同语义，
    /// 让调用方把「这一路没有东西」与「出错了」统一按空处理（会合层只提供候选，
    /// 真正的身份认证在 WireGuard 握手）。
    pub fn lookup(&self, host: &str, port: u16) -> Vec<SocketAddrV6> {
        match self.transport.resolve_aaaa(host) {
            Ok(addrs) => crate::record::usable_endpoints(&addrs, port),
            Err(_) => Vec::new(),
        }
    }
}

/// 把更新 URL 模板里的 `{address}` 占位符替换成裸 IPv6 地址（无方括号、无端口）。
///
/// 模板缺 `{address}` 时返回错误——缺了它更新就退化成「把空地址写进 DNS」，宁可
/// 在配置加载/首次发布时就报错，也不要静默写坏记录。`pub` 是为了让 engine 侧在
/// 启动前就能校验模板、让单测直接覆盖这条纯逻辑。
pub fn render_update_url(template: &str, address: Ipv6Addr) -> Result<String, String> {
    if !template.contains("{address}") {
        return Err("DDNS update_url 模板缺少 {address} 占位符".to_string());
    }
    Ok(template.replace("{address}", &address.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    /// 记录型 mock：不发网络请求、不需要凭据，只把「收到什么」记下来。
    struct MockTransport {
        updates: Arc<Mutex<Vec<String>>>,
        aaaa: Mutex<Result<Vec<Ipv6Addr>, String>>,
        update_err: Option<String>,
    }

    impl MockTransport {
        fn new(aaaa: Result<Vec<Ipv6Addr>, String>) -> (Self, Arc<Mutex<Vec<String>>>) {
            let updates = Arc::new(Mutex::new(Vec::new()));
            (
                Self {
                    updates: updates.clone(),
                    aaaa: Mutex::new(aaaa),
                    update_err: None,
                },
                updates,
            )
        }
    }

    impl DdnsTransport for MockTransport {
        fn update(&self, url: &str) -> Result<(), String> {
            if let Some(e) = &self.update_err {
                return Err(e.clone());
            }
            self.updates.lock().unwrap().push(url.to_string());
            Ok(())
        }

        fn resolve_aaaa(&self, _host: &str) -> Result<Vec<Ipv6Addr>, String> {
            self.aaaa.lock().unwrap().clone()
        }
    }

    const TEMPLATE: &str = "https://dynv6.com/api/update?hostname=MYHOST.dynv6.net&token=REPLACE_WITH_YOUR_TOKEN&ipv6={address}";

    #[test]
    fn render_substitutes_address_without_brackets_or_port() {
        let url = render_update_url(TEMPLATE, "2001:db8::1".parse().unwrap()).unwrap();
        assert!(url.contains("ipv6=2001:db8::1"), "got {url}");
        assert!(!url.contains("{address}"));
        // 裸地址：不该出现方括号（IPv6 URL 里的标准写法）
        assert!(!url.contains("[2001:db8::1]"));
    }

    #[test]
    fn render_missing_placeholder_errors() {
        let bad = "https://example.com/update?host=MYHOST&ipv6=1.2.3.4";
        let err = render_update_url(bad, "2001:db8::1".parse().unwrap()).unwrap_err();
        assert!(err.contains("{address}"), "got {err}");
    }

    #[test]
    fn publish_calls_transport_with_rendered_url_per_endpoint() {
        let (transport, updates) = MockTransport::new(Ok(vec![]));
        let client = DdnsClient::new(TEMPLATE.to_string(), Box::new(transport));
        let endpoints: Vec<SocketAddrV6> = vec![
            "[2001:db8::1]:4193".parse().unwrap(),
            "[2001:db8::2]:4193".parse().unwrap(),
        ];
        client.publish(&endpoints).unwrap();
        let seen = updates.lock().unwrap();
        assert_eq!(seen.len(), 2);
        assert!(seen[0].contains("ipv6=2001:db8::1"), "got {}", seen[0]);
        assert!(seen[1].contains("ipv6=2001:db8::2"), "got {}", seen[1]);
    }

    #[test]
    fn publish_propagates_transport_error() {
        let (mut transport, _) = MockTransport::new(Ok(vec![]));
        transport.update_err = Some("503 unavailable".into());
        let client = DdnsClient::new(TEMPLATE.to_string(), Box::new(transport));
        let endpoints = vec!["[2001:db8::1]:4193".parse::<SocketAddrV6>().unwrap()];
        let err = client.publish(&endpoints).unwrap_err();
        assert_eq!(err, "503 unavailable");
    }

    #[test]
    fn publish_empty_endpoints_is_noop() {
        let (transport, updates) = MockTransport::new(Ok(vec![]));
        let client = DdnsClient::new(TEMPLATE.to_string(), Box::new(transport));
        client.publish(&[]).unwrap();
        assert!(updates.lock().unwrap().is_empty());
    }

    #[test]
    fn lookup_attaches_port_and_filters_unusable() {
        // 只保留可用地址（GUA），ULA/链路本地/loopback 全被 `usable_endpoints` 过滤掉
        let addrs = vec![
            "2001:db8::a".parse().unwrap(),
            "fd00::1".parse().unwrap(),
            "fe80::1".parse().unwrap(),
            "::1".parse().unwrap(),
        ];
        let (transport, _) = MockTransport::new(Ok(addrs));
        let client = DdnsClient::new(TEMPLATE.to_string(), Box::new(transport));
        let got = client.lookup("nas.dynv6.net", 4193);
        assert_eq!(
            got,
            vec!["[2001:db8::a]:4193".parse::<SocketAddrV6>().unwrap()]
        );
    }

    #[test]
    fn lookup_empty_on_resolve_error() {
        let (transport, _) = MockTransport::new(Err("NXDOMAIN".into()));
        let client = DdnsClient::new(TEMPLATE.to_string(), Box::new(transport));
        assert!(client.lookup("nope.dynv6.net", 4193).is_empty());
    }

    #[test]
    fn lookup_empty_when_port_is_zero() {
        let addrs = vec!["2001:db8::a".parse().unwrap()];
        let (transport, _) = MockTransport::new(Ok(addrs));
        let client = DdnsClient::new(TEMPLATE.to_string(), Box::new(transport));
        assert!(client.lookup("nas.dynv6.net", 0).is_empty());
    }
}
