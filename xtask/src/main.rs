use std::process::Command;

use anyhow::{Context, Result, bail};

fn main() -> Result<()> {
    let task = std::env::args().nth(1).unwrap_or_default();
    match task.as_str() {
        "ci" => ci(),
        "e2e" => e2e(),
        _ => bail!("usage: cargo xtask <ci|e2e>"),
    }
}

fn run(program: &str, args: &[&str]) -> Result<()> {
    eprintln!("$ {program} {}", args.join(" "));
    let status = Command::new(program)
        .args(args)
        .status()
        .with_context(|| format!("failed to spawn {program}"))?;
    if !status.success() {
        bail!("{program} {} failed", args.join(" "));
    }
    Ok(())
}

fn ci() -> Result<()> {
    run("cargo", &["fmt", "--all", "--check"])?;
    run(
        "cargo",
        &[
            "clippy",
            "--workspace",
            "--all-targets",
            "--",
            "-D",
            "warnings",
        ],
    )?;
    run("cargo", &["test", "--workspace"])?;
    // cargo-deny 本地未安装时跳过（CI 中由独立 action 保证）
    if Command::new("cargo-deny")
        .arg("--version")
        .status()
        .is_ok_and(|s| s.success())
    {
        run("cargo", &["deny", "check"])?;
    } else {
        eprintln!("skip: cargo-deny not installed");
    }
    Ok(())
}

fn e2e() -> Result<()> {
    run("cargo", &["build", "--workspace"])?;
    run("sudo", &["-E", "scripts/netns-e2e.sh"])
}
