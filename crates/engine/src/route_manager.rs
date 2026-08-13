//! 通告路由（site-to-site）的安装/移除跟踪。
//!
//! 决策逻辑与 netlink 无关：这里只负责「每个 peer 当前装了哪几条路由、要增删哪些」，
//! 实际的 rtnetlink 调用经 [`RouteBackend`] 注入——daemon 用平台实现（Linux rtnetlink），
//! 测试用记录调用的 Mock。这样 install/remove 的行为契约能在任何开发机上单测，
//! 而不需要 root 或真 netlink。

use std::collections::HashMap;
use std::future::Future;

use hextet_core::route::Ipv6Route;
use hextet_platform::PlatformError;

/// 把一条 IPv6 前缀装进/移出某个接口路由表的后端抽象。
pub trait RouteBackend {
    /// 添加一条到 `route` 的路由。
    fn add_route(
        &self,
        interface: &str,
        route: Ipv6Route,
    ) -> impl Future<Output = Result<(), PlatformError>> + Send;
    /// 移除一条到 `route` 的路由。
    fn remove_route(
        &self,
        interface: &str,
        route: Ipv6Route,
    ) -> impl Future<Output = Result<(), PlatformError>> + Send;
}

/// [`RouteManager::sync`] 的结果：这一轮实际增删了哪些路由。
#[derive(Default)]
pub struct SyncOutcome {
    /// 本轮新安装的路由。
    pub added: Vec<Ipv6Route>,
    /// 本轮移除的路由。
    pub removed: Vec<Ipv6Route>,
}

/// 跟踪每个 peer 已装的路由，保证安装/移除**精确**、不覆盖别的 peer 的路由。
///
/// 两个 peer 的通告路由在配置加载时就保证互不重叠（见
/// [`hextet_core::config::Config::load`]），但 OS 路由表里同一条前缀仍可能被别处
/// 复用；本结构只动它自己装过的那几条，移除时也逐条精确删除。
#[derive(Default)]
pub struct RouteManager {
    /// peer 公钥 base64 → 当前已为该 peer 安装的路由（保持插入序）。
    installed: HashMap<String, Vec<Ipv6Route>>,
}

impl RouteManager {
    /// 空管理器。
    pub fn new() -> Self {
        Self::default()
    }

    /// 把某个 peer 的期望路由集合同步到 `desired`，并通过 `backend` 增删。
    ///
    /// 幂等：已装且仍在 `desired` 里的不动；`desired` 里新出现的装上；已装但
    /// 不在 `desired` 里的移除。某一条操作失败时立即返回错误，跟踪状态只更新到
    /// 成功的那一步——下次 sync 会重试剩余的部分。
    pub async fn sync<B: RouteBackend + ?Sized>(
        &mut self,
        backend: &B,
        interface: &str,
        peer_key: &str,
        desired: &[Ipv6Route],
    ) -> Result<SyncOutcome, PlatformError> {
        let mut outcome = SyncOutcome::default();
        let current = self.installed.entry(peer_key.to_owned()).or_default();
        let mut keep = Vec::with_capacity(desired.len());
        // 先移除不再需要的（keep 之外的旧路由）
        for route in current.iter() {
            if desired.contains(route) {
                keep.push(*route);
            } else {
                backend.remove_route(interface, *route).await?;
                outcome.removed.push(*route);
            }
        }
        // 再补装新的（保持 desired 的顺序）
        for route in desired {
            if !keep.contains(route) {
                backend.add_route(interface, *route).await?;
                outcome.added.push(*route);
                keep.push(*route);
            }
        }
        *current = keep;
        Ok(outcome)
    }

    /// 移除某个 peer 的全部已装路由（peer 断开或被移除时调用）。幂等。
    pub async fn remove_peer<B: RouteBackend + ?Sized>(
        &mut self,
        backend: &B,
        interface: &str,
        peer_key: &str,
    ) -> Result<(), PlatformError> {
        if let Some(routes) = self.installed.remove(peer_key) {
            for route in routes {
                backend.remove_route(interface, route).await?;
            }
        }
        Ok(())
    }

    /// 移除全部已装路由（daemon 退出时调用）。
    pub async fn remove_all<B: RouteBackend + ?Sized>(
        &mut self,
        backend: &B,
        interface: &str,
    ) -> Result<(), PlatformError> {
        for (_, routes) in self.installed.drain() {
            for route in routes {
                backend.remove_route(interface, route).await?;
            }
        }
        Ok(())
    }

    /// 当前跟踪的已装路由总数（测试与观测用）。
    pub fn installed_count(&self) -> usize {
        self.installed.values().map(Vec::len).sum()
    }

    /// 某 peer 当前已装的路由（`state.json` 里展示用）。
    pub fn routes_of(&self, peer_key: &str) -> &[Ipv6Route] {
        self.installed
            .get(peer_key)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// 记录 add/remove 调用的 mock 后端（无真实 netlink）。
    #[derive(Default)]
    struct Mock {
        added: Mutex<Vec<(String, Ipv6Route)>>,
        removed: Mutex<Vec<(String, Ipv6Route)>>,
    }

    impl RouteBackend for Mock {
        async fn add_route(&self, interface: &str, route: Ipv6Route) -> Result<(), PlatformError> {
            self.added
                .lock()
                .unwrap()
                .push((interface.to_owned(), route));
            Ok(())
        }
        async fn remove_route(
            &self,
            interface: &str,
            route: Ipv6Route,
        ) -> Result<(), PlatformError> {
            self.removed
                .lock()
                .unwrap()
                .push((interface.to_owned(), route));
            Ok(())
        }
    }

    fn r(s: &str) -> Ipv6Route {
        s.parse().unwrap()
    }

    #[tokio::test]
    async fn sync_installs_then_keeps_then_replaces() {
        let mut mgr = RouteManager::new();
        let mock = Mock::default();
        let iface = "hextet0";

        // 首次：装 a 和 b
        let out = mgr
            .sync(
                &mock,
                iface,
                "k",
                &[r("2001:db8:dead::/64"), r("2001:db8:beef::/48")],
            )
            .await
            .unwrap();
        assert_eq!(out.added.len(), 2);
        assert!(out.removed.is_empty());
        assert_eq!(mgr.installed_count(), 2);
        assert_eq!(mock.added.lock().unwrap().len(), 2);

        // 再次同集合：幂等，什么都不动
        let out = mgr
            .sync(
                &mock,
                iface,
                "k",
                &[r("2001:db8:dead::/64"), r("2001:db8:beef::/48")],
            )
            .await
            .unwrap();
        assert!(out.added.is_empty() && out.removed.is_empty());
        assert_eq!(mock.added.lock().unwrap().len(), 2);
        assert_eq!(mock.removed.lock().unwrap().len(), 0);

        // 换集合：beef 移除、dead 保留、cafe 新增
        let out = mgr
            .sync(
                &mock,
                iface,
                "k",
                &[r("2001:db8:dead::/64"), r("2001:db8:cafe::/64")],
            )
            .await
            .unwrap();
        assert_eq!(out.added, vec![r("2001:db8:cafe::/64")]);
        assert_eq!(out.removed, vec![r("2001:db8:beef::/48")]);
        assert_eq!(mgr.installed_count(), 2);
        assert_eq!(mock.added.lock().unwrap().len(), 3);
        assert_eq!(mock.removed.lock().unwrap().len(), 1);
        assert_eq!(mock.removed.lock().unwrap()[0].1, r("2001:db8:beef::/48"));
    }

    #[tokio::test]
    async fn two_peers_are_tracked_independently() {
        let mut mgr = RouteManager::new();
        let mock = Mock::default();
        let iface = "hextet0";

        mgr.sync(&mock, iface, "a", &[r("2001:db8:dead::/64")])
            .await
            .unwrap();
        mgr.sync(&mock, iface, "b", &[r("2001:db8:beef::/64")])
            .await
            .unwrap();
        assert_eq!(mgr.installed_count(), 2);

        // 移除 a 只动 a 的路由，b 的保留
        mgr.remove_peer(&mock, iface, "a").await.unwrap();
        assert_eq!(mgr.installed_count(), 1);
        assert_eq!(mock.removed.lock().unwrap().len(), 1);
        assert_eq!(mock.removed.lock().unwrap()[0].1, r("2001:db8:dead::/64"));
    }

    #[tokio::test]
    async fn remove_peer_and_remove_all_are_idempotent() {
        let mut mgr = RouteManager::new();
        let mock = Mock::default();
        let iface = "hextet0";

        // 不存在的 peer：no-op
        mgr.remove_peer(&mock, iface, "nope").await.unwrap();
        assert_eq!(mock.removed.lock().unwrap().len(), 0);

        mgr.sync(&mock, iface, "k", &[r("2001:db8:dead::/64")])
            .await
            .unwrap();
        mgr.remove_peer(&mock, iface, "k").await.unwrap();
        mgr.remove_peer(&mock, iface, "k").await.unwrap(); // 幂等
        assert_eq!(mock.removed.lock().unwrap().len(), 1);

        mgr.sync(&mock, iface, "k", &[r("2001:db8:beef::/64")])
            .await
            .unwrap();
        mgr.remove_all(&mock, iface).await.unwrap();
        assert_eq!(mgr.installed_count(), 0);
        assert_eq!(mock.removed.lock().unwrap().len(), 2);
    }
}
