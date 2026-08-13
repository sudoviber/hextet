//! DDNS 会合的 DNS TXT 查询侧（会合兜底链第 ⑥ 层）。
//!
//! 用 `hickory-resolver` 做系统配置的异步 TXT 查询，把查到的字符串喂给
//! [`super::select_endpoints`] 择优解密。`hickory` 类型不出本模块——调用方只见
//! [`DdnsResolver`]，其 API 若 break 只需改这里（与 DHT 的 `DhtClient` 同一封装纪律）。

use std::net::{SocketAddr, SocketAddrV6};

use hickory_resolver::TokioResolver;
use hickory_resolver::config::{ConnectionConfig, NameServerConfig, ResolverConfig};

use super::select_endpoints;

/// 一个 DNS 解析器，负责按 FQDN 查 TXT 记录并解密出 endpoint。
pub struct DdnsResolver {
    inner: TokioResolver,
}

impl DdnsResolver {
    /// 从系统 DNS 配置构建（`/etc/resolv.conf` / macOS SystemConfiguration / Windows）。
    pub fn new() -> Result<Self, String> {
        let inner = TokioResolver::builder_tokio()
            .and_then(|b| b.build())
            .map_err(|e| format!("构建系统 DNS 解析器失败: {e}"))?;
        Ok(Self { inner })
    }

    /// 用指定的 DNS 服务器（`ip:port`）构建，覆盖系统配置。
    ///
    /// 生产可用它固定解析器；netns E2E 用它把查询指向本地 DDNS mock（
    /// `hextet ddns node`，见 `node` 模块），让「webhook 发布 → DNS TXT 查询」在
    /// 离线 netns 里走完真实 HTTP + 真实 DNS 的闭环，而不依赖公网注册商/DNS。
    pub fn with_nameserver(nameserver: SocketAddr) -> Result<Self, String> {
        let mut conn = ConnectionConfig::udp();
        conn.port = nameserver.port();
        let ns = NameServerConfig::new(nameserver.ip(), true, vec![conn]);
        let mut config = ResolverConfig::default();
        config.add_name_server(ns);
        let inner = TokioResolver::builder_with_config(config, Default::default())
            .build()
            .map_err(|e| format!("构建 DNS 解析器失败: {e}"))?;
        Ok(Self { inner })
    }

    /// 解析某 peer 的 DDNS 会合记录，返回其当前 endpoint（未找到/解析失败均返回空，
    /// 只有真正的 DNS 解析错误才返回 `Err`）。
    pub async fn lookup_peer(
        &self,
        fqdn: &str,
        ddns_key: &[u8; 32],
    ) -> Result<Vec<SocketAddrV6>, String> {
        match self.inner.txt_lookup(fqdn).await {
            Ok(lookup) => {
                let mut strings: Vec<String> = Vec::new();
                for record in lookup.answers() {
                    if let hickory_resolver::proto::rr::RData::TXT(txt) = &record.data {
                        for data in txt.txt_data.iter() {
                            strings.push(String::from_utf8_lossy(data.as_ref()).into_owned());
                        }
                    }
                }
                Ok(select_endpoints(&strings, ddns_key))
            }
            // NXDOMAIN / 该域名没有 TXT 记录 —— 对会合来说这不是错误，只是「对方还没发布」。
            Err(e) if e.is_no_records_found() => Ok(Vec::new()),
            Err(e) => Err(format!("DDNS TXT 查询失败: {e}")),
        }
    }
}
