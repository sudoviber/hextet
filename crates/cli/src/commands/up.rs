//! `hextet up`：建接口、配 WG、配地址、拉起（M1 Linux；M4 macOS；M6 Windows）。

use std::path::PathBuf;

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
use anyhow::Context as _;
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
use hextet_core::addr::derive_node_addr;
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
use hextet_core::network::NetworkPrefix;
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
use hextet_wg::WgBackend as _;

/// Arguments for the up command.
#[derive(clap::Args)]
pub struct Args {
    /// 配置文件
    #[arg(short, long, default_value = "hextet.toml")]
    pub config: PathBuf,
}

/// Run the up command.
pub fn run(args: Args) -> anyhow::Result<()> {
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let _ = args;
        anyhow::bail!("hextet up 仅支持 Linux、macOS 与 Windows（其他平台未实现）");
    }

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    {
        let (cfg, id) = super::load_config_and_identity(&args.config)?;
        let own = derive_node_addr(cfg.prefix, &id.public())?;
        let spec = hextet_engine::spec::build_device_spec(&cfg, &id);

        let backend = super::backend::platform_default();
        // `apply` 返回 OS 层真实设备名（ADR-0009 决策 3）：Linux 恒等于配置名；
        // macOS 经 hextet0→utun 映射读回真实 utunN；Windows 经 TunDevice 读回适配器名。
        let real_name = backend
            .apply(&spec)
            .context("配置 WireGuard 设备（需要 root/CAP_NET_ADMIN）")?;
        let rt = tokio::runtime::Runtime::new()?;
        rt.block_on(hextet_platform::setup_interface(
            &real_name,
            own.address,
            NetworkPrefix::PREFIX_LEN,
            cfg.node.mtu,
        ))
        .context("配置接口地址/MTU")?;

        // macOS/Windows：显式加 overlay /48 路由，与 Linux「内核配地址即自动下直连
        // /48 路由」的语义对齐（ADR-0009 决策 4）；Linux 无需显式 add_route。
        #[cfg(any(target_os = "macos", target_os = "windows"))]
        rt.block_on(hextet_platform::add_route(
            &real_name,
            cfg.prefix.network(),
            NetworkPrefix::PREFIX_LEN,
        ))
        .context("添加 overlay /48 路由")?;

        // 上报：Linux 打印配置名；macOS/Windows 上报真实设备名（hextet0 -> utunN/适配器）。
        #[cfg(target_os = "linux")]
        println!(
            "up: {} {} ({} peers)",
            cfg.node.interface,
            own.address,
            cfg.peers.len()
        );
        #[cfg(any(target_os = "macos", target_os = "windows"))]
        println!(
            "up: {} -> {} {} ({} peers)",
            cfg.node.interface,
            real_name,
            own.address,
            cfg.peers.len()
        );
        Ok(())
    }
}
