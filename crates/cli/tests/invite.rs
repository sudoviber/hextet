//! `hextet invite new` / `hextet join` / `hextet peer add` 的端到端 CLI 测试。

use assert_cmd::Command;
use predicates::prelude::*;

fn hextet() -> Command {
    Command::cargo_bin("hextet").unwrap()
}

/// 建一个可用的节点（密钥 + 配置），返回 (目录, 配置路径, 公钥)。
fn setup_node(
    dir: &std::path::Path,
    tag: &str,
    network_key: Option<&str>,
) -> (std::path::PathBuf, String) {
    let key = dir.join(format!("{tag}.key"));
    let cfg = dir.join(format!("{tag}.toml"));
    let out = hextet()
        .args(["keygen", "--out"])
        .arg(&key)
        .output()
        .unwrap();
    assert!(out.status.success());
    let pubkey = String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .find_map(|l| l.strip_prefix("public-key: ").map(str::to_owned))
        .unwrap();

    let mut cmd = hextet();
    cmd.args(["init", "--name", "t", "--key-file"])
        .arg(&key)
        .args(["--out"])
        .arg(&cfg);
    if let Some(nk) = network_key {
        cmd.args(["--network-key", nk]);
    }
    cmd.assert().success();
    (cfg, pubkey)
}

fn issue_token(cfg: &std::path::Path, extra: &[&str]) -> String {
    let mut cmd = hextet();
    cmd.args(["invite", "new", "-c"])
        .arg(cfg)
        .args(["--endpoint", "[2001:db8::1]:4193"])
        .args(extra);
    let out = cmd.output().unwrap();
    assert!(
        out.status.success(),
        "invite new 失败: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap().trim().to_owned()
}

#[test]
fn invite_new_prints_single_line_token() {
    let dir = tempfile::tempdir().unwrap();
    let (cfg, pubkey) = setup_node(dir.path(), "a", None);
    let token = issue_token(&cfg, &[]);
    assert!(token.starts_with("hxi1."), "token = {token}");
    assert_eq!(token.lines().count(), 1);
    // 签发者就是本机
    let json = hextet()
        .args(["invite", "new", "-c"])
        .arg(&cfg)
        .args(["--endpoint", "[2001:db8::1]:4193", "--json"])
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(v["issuer"].as_str().unwrap(), pubkey);
    assert_eq!(v["bootstrap"][0]["endpoints"][0], "[2001:db8::1]:4193");
    assert!(v["token"].as_str().unwrap().starts_with("hxi1."));
    assert!(v["expires_unix"].as_u64().unwrap() > v["issued_unix"].as_u64().unwrap());
}

#[test]
fn invite_new_warns_about_secret_on_stderr() {
    let dir = tempfile::tempdir().unwrap();
    let (cfg, _) = setup_node(dir.path(), "a", None);
    hextet()
        .args(["invite", "new", "-c"])
        .arg(&cfg)
        .args(["--endpoint", "[2001:db8::1]:4193"])
        .assert()
        .success()
        .stderr(predicate::str::contains("网络密钥"))
        .stderr(predicate::str::contains("hextet peer add"));
}

#[test]
fn invite_new_rejects_ipv4_endpoint() {
    let dir = tempfile::tempdir().unwrap();
    let (cfg, _) = setup_node(dir.path(), "a", None);
    hextet()
        .args(["invite", "new", "-c"])
        .arg(&cfg)
        .args(["--endpoint", "1.2.3.4:4193"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("IPv6-only"));
}

#[test]
fn invite_new_rejects_bad_ttl() {
    let dir = tempfile::tempdir().unwrap();
    let (cfg, _) = setup_node(dir.path(), "a", None);
    hextet()
        .args(["invite", "new", "-c"])
        .arg(&cfg)
        .args(["--endpoint", "[2001:db8::1]:4193", "--ttl", "400d"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("365d"));
}

/// 不给 `--endpoint` 时的行为取决于本机有没有公网 IPv6：
/// 有就该成功，没有（或平台不支持枚举，如 macOS）就必须报错并**指出解决办法**。
/// 两种环境下都要有确定的、可判定的行为——这正是这个测试要钉住的东西。
#[test]
fn invite_new_without_endpoint_either_works_or_says_how_to_fix() {
    let dir = tempfile::tempdir().unwrap();
    let (cfg, _) = setup_node(dir.path(), "a", None);
    let out = hextet()
        .args(["invite", "new", "-c"])
        .arg(&cfg)
        .output()
        .unwrap();
    if out.status.success() {
        assert!(String::from_utf8_lossy(&out.stdout).starts_with("hxi1."));
    } else {
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains("--endpoint"), "stderr = {stderr}");
    }
}
