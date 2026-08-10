use std::process::Command;

use anyhow::{Context, Result, bail};

fn main() -> Result<()> {
    let task = std::env::args().nth(1).unwrap_or_default();
    match task.as_str() {
        "ci" => ci(),
        "e2e" => e2e(&std::env::args().nth(2).unwrap_or_default()),
        _ => bail!("usage: cargo xtask <ci|e2e [static|dynamic|doctor|lan|relay|all]>"),
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

fn e2e(which: &str) -> Result<()> {
    run("cargo", &["build", "--workspace"])?;
    let scripts: Vec<&str> = match which {
        "" | "all" => vec![
            "scripts/netns-e2e.sh",
            "scripts/netns-e2e-dynamic.sh",
            "scripts/netns-e2e-doctor.sh",
            "scripts/netns-e2e-lan.sh",
            "scripts/netns-e2e-relay.sh",
        ],
        "static" => vec!["scripts/netns-e2e.sh"],
        "dynamic" => vec!["scripts/netns-e2e-dynamic.sh"],
        "doctor" => vec!["scripts/netns-e2e-doctor.sh"],
        "lan" => vec!["scripts/netns-e2e-lan.sh"],
        "relay" => vec!["scripts/netns-e2e-relay.sh"],
        other => bail!("unknown e2e scenario {other}; use static|dynamic|doctor|lan|relay|all"),
    };
    for script in scripts {
        // 阶段 B 的脚本在阶段 A 期间还不存在：跳过而不是报错
        if !std::path::Path::new(script).exists() {
            eprintln!("skip: {script} (not present)");
            continue;
        }
        run("sudo", &["-E", script])?;
    }
    Ok(())
}
