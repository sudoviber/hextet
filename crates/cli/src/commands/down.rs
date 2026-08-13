//! `hextet down`：删除接口。

use std::path::PathBuf;

/// Arguments for the down command.
#[derive(clap::Args)]
pub struct Args {
    /// 配置文件
    #[arg(short, long, default_value = "hextet.toml")]
    pub config: PathBuf,
}

/// Run the down command.
///
/// 平台分派（ADR-0009 决策 5）：
/// - Linux：走 `hextet_platform::delete_interface`（rtnetlink `ip link del`）。
/// - macOS：utun 归 gotatun 后端所有、随持有它的进程销毁——one-shot `hextet down`
///   够不到另一个（长驻 daemon）进程持有的设备，如实 bail，不伪造拆除。
#[cfg(target_os = "linux")]
pub fn run(args: Args) -> anyhow::Result<()> {
    let (cfg, _id) = super::load_config_and_identity(&args.config)?;
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(hextet_platform::delete_interface(&cfg.node.interface))?;
    println!("down: {}", cfg.node.interface);
    Ok(())
}

/// 见模块级 doc：macOS 上设备随持有它的进程销毁，one-shot `hextet down` 无设备可拆。
#[cfg(target_os = "macos")]
pub fn run(args: Args) -> anyhow::Result<()> {
    let (cfg, _id) = super::load_config_and_identity(&args.config)?;
    anyhow::bail!(
        "macOS 上 utun 归持有它的进程所有、进程退出即销毁（ADR-0009 决策 5/6）：\
         一次性的 `hextet down` 无法触达由常驻进程（`hextet daemon` / launchd）持有的接口 \
         `{}`。请停止持有它的 daemon 进程让设备随进程销毁，或用 `hextet daemon` 长驻托管。",
        cfg.node.interface
    );
}

/// Windows：wintun 适配器归持有它的进程所有（同 macOS 的 utun），且 `tun` crate 的
/// Windows 分支不暴露 `WintunDeleteAdapter`（ADR-0011 的 `delete_interface` 缺口），
/// 一次性的 `hextet down` 既够不到常驻进程的设备、也没有删除 API——如实 bail，不伪造。
#[cfg(target_os = "windows")]
pub fn run(args: Args) -> anyhow::Result<()> {
    let (cfg, _id) = super::load_config_and_identity(&args.config)?;
    anyhow::bail!(
        "Windows 上 wintun 适配器归持有它的进程所有（ADR-0011）：一次性的 `hextet down` \
         无法触达由常驻进程（`hextet daemon` / Windows 服务）持有的接口 `{}`。\
         请停止持有它的 daemon 进程；彻底删除适配器（WintunDeleteAdapter）仍未实现 \
         （ADR-0011 的 delete_interface 缺口）。",
        cfg.node.interface
    );
}

/// 其他（非 Linux/macOS/Windows）平台：`delete_interface` 本就返回 `Unsupported`，直接说明。
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub fn run(args: Args) -> anyhow::Result<()> {
    let (cfg, _id) = super::load_config_and_identity(&args.config)?;
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(hextet_platform::delete_interface(&cfg.node.interface))?;
    println!("down: {}", cfg.node.interface);
    Ok(())
}
