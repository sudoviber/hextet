//! 测试用 Mock 后端。

use std::sync::Mutex;

use crate::WgBackend;
use crate::types::{DeviceSpec, PeerStatus, WgError};

/// 记录 apply 调用的 mock。
#[derive(Default)]
pub struct MockBackend {
    /// 已 apply 的 spec 序列。
    pub applied: Mutex<Vec<DeviceSpec>>,
}

impl WgBackend for MockBackend {
    fn apply(&self, spec: &DeviceSpec) -> Result<(), WgError> {
        self.applied.lock().expect("mock lock").push(spec.clone());
        Ok(())
    }

    fn status(&self, _interface: &str) -> Result<Vec<PeerStatus>, WgError> {
        Ok(vec![])
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
        mock.apply(&spec).unwrap();
        assert_eq!(mock.applied.lock().unwrap().len(), 1);
        assert_eq!(mock.applied.lock().unwrap()[0].listen_port, 4193);
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
