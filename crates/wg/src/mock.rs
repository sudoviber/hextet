//! 测试用 Mock 后端。

use std::net::SocketAddrV6;
use std::sync::Mutex;

use crate::WgBackend;
use crate::types::{DeviceSpec, PeerStatus, WgError};

/// 记录 apply / set_peer_endpoint 调用的 mock。
#[derive(Default)]
pub struct MockBackend {
    /// 已 apply 的 spec 序列。
    pub applied: Mutex<Vec<DeviceSpec>>,
    /// 已执行的 endpoint 更新序列：(接口名, peer WG 公钥, endpoint)。
    pub endpoint_updates: Mutex<Vec<(String, [u8; 32], SocketAddrV6)>>,
    /// `status()` 返回的 peer 状态（供 `status`/`build_report` 的无头测试注入）。
    pub statuses: Mutex<Vec<PeerStatus>>,
}

impl WgBackend for MockBackend {
    fn apply(&self, spec: &DeviceSpec) -> Result<String, WgError> {
        self.applied.lock().expect("mock lock").push(spec.clone());
        // mock 恒等返回配置名（与 Linux 内核后端一致，ADR-0009 决策 3）。
        Ok(spec.interface.clone())
    }

    fn status(&self, _interface: &str) -> Result<Vec<PeerStatus>, WgError> {
        Ok(self.statuses.lock().expect("mock lock").clone())
    }

    fn set_peer_endpoint(
        &self,
        interface: &str,
        wg_public: &[u8; 32],
        endpoint: SocketAddrV6,
    ) -> Result<(), WgError> {
        self.endpoint_updates.lock().expect("mock lock").push((
            interface.to_owned(),
            *wg_public,
            endpoint,
        ));
        Ok(())
    }

    fn add_peer(&self, _interface: &str, _spec: &crate::types::PeerSpec) -> Result<(), WgError> {
        Ok(())
    }

    fn remove_peer(&self, _interface: &str, _wg_public: &[u8; 32]) -> Result<(), WgError> {
        Ok(())
    }

    fn down(&self, _interface: &str) -> Result<(), WgError> {
        // mock 无设备可拆，幂等成功（与 mock 其余方法一致：只记录、不失败）。
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::types::*;
    use super::MockBackend;
    use crate::WgBackend as _;

    #[test]
    fn mock_records_applied_spec() {
        let mock = MockBackend::default();
        let spec = DeviceSpec {
            interface: "hextet0".into(),
            listen_port: 4193,
            wg_secret: [7u8; 32],
            peers: vec![],
        };
        let name = mock.apply(&spec).unwrap();
        assert_eq!(name, "hextet0");
        assert_eq!(mock.applied.lock().unwrap().len(), 1);
        assert_eq!(mock.applied.lock().unwrap()[0].listen_port, 4193);
    }

    #[test]
    fn mock_records_endpoint_updates() {
        let mock = MockBackend::default();
        let key = [3u8; 32];
        let ep: std::net::SocketAddrV6 = "[2001:db8::9]:4193".parse().unwrap();
        mock.set_peer_endpoint("hextet0", &key, ep).unwrap();
        let recorded = mock.endpoint_updates.lock().unwrap();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].0, "hextet0");
        assert_eq!(recorded[0].1, key);
        assert_eq!(recorded[0].2, ep);
    }

    // kernel 模块只在 Linux 上编译（wireguard-control 依赖为 cfg(target_os = "linux")）；
    // 本测试因此只在 Linux 上跑，macOS 开发机上按 brief step 4 预期跳过。
    #[cfg(target_os = "linux")]
    #[test]
    fn key_base64_bridge() {
        // wireguard-control 走 base64 构造 Key：验证桥接函数
        let bytes = [42u8; 32];
        let key = crate::kernel::key_from_bytes(&bytes);
        assert_eq!(key.as_bytes(), &bytes);
    }
}
