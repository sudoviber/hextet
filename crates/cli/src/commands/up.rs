//! `hextet up`：建接口、配 WG、配地址、拉起（M1 仅 Linux）。

use std::path::PathBuf;

#[cfg(target_os = "linux")]
use anyhow::Context as _;
#[cfg(target_os = "linux")]
use hextet_core::addr::derive_node_addr;
#[cfg(target_os = "linux")]
use hextet_core::network::NetworkPrefix;
#[cfg(target_os = "linux")]
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
    #[cfg(not(target_os = "linux"))]
    {
        let _ = args;
        anyhow::bail!("M1 仅支持 Linux（macOS 在 M4）");
    }

    #[cfg(target_os = "linux")]
    {
        let (cfg, id) = super::load_config_and_identity(&args.config)?;
        let own = derive_node_addr(cfg.prefix, &id.public())?;
        let spec = crate::spec::build_device_spec(&cfg, &id);

        let backend = hextet_wg::kernel::KernelBackend;
        backend
            .apply(&spec)
            .context("配置 WireGuard 设备（需要 root/CAP_NET_ADMIN）")?;
        let rt = tokio::runtime::Runtime::new()?;
        rt.block_on(hextet_platform::setup_interface(
            &cfg.node.interface,
            own.address,
            NetworkPrefix::PREFIX_LEN,
            cfg.node.mtu,
        ))
        .context("配置接口地址/MTU")?;
        println!(
            "up: {} {} ({} peers)",
            cfg.node.interface,
            own.address,
            cfg.peers.len()
        );
        Ok(())
    }
}
