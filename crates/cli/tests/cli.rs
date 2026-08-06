use assert_cmd::Command;
use predicates::prelude::*;

fn hextet() -> Command {
    Command::cargo_bin("hextet").unwrap()
}

#[test]
fn keygen_creates_key_and_prints_pubkey() {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("node.key");
    hextet()
        .args(["keygen", "--out"])
        .arg(&key)
        .assert()
        .success()
        .stdout(predicate::str::contains("public-key: "));
    assert!(key.exists());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&key).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    // 不加 --force 重复写入应失败
    hextet()
        .args(["keygen", "--out"])
        .arg(&key)
        .assert()
        .failure();
}

#[test]
fn init_then_inspect_shows_ula_prefix() {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("node.key");
    let cfg = dir.path().join("hextet.toml");
    hextet()
        .args(["keygen", "--out"])
        .arg(&key)
        .assert()
        .success();
    hextet()
        .args(["init", "--name", "testnet", "--key-file"])
        .arg(&key)
        .args(["--out"])
        .arg(&cfg)
        .assert()
        .success();
    hextet()
        .args(["inspect", "-c"])
        .arg(&cfg)
        .assert()
        .success()
        .stdout(predicate::str::contains("fd")); // ULA 前缀
}

/// hextet.toml 含网络密钥，落盘权限须与 keygen 的密钥文件一致（0600），
/// 且二次 init 到同一路径应报错而非静默覆盖（TOCTOU 修复：create_new）。
#[test]
fn init_writes_config_with_owner_only_permissions() {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("node.key");
    let cfg = dir.path().join("hextet.toml");
    hextet()
        .args(["keygen", "--out"])
        .arg(&key)
        .assert()
        .success();
    hextet()
        .args(["init", "--name", "testnet", "--key-file"])
        .arg(&key)
        .args(["--out"])
        .arg(&cfg)
        .assert()
        .success();
    assert!(cfg.exists());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&cfg).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    // 二次 init 到同一路径应失败（不覆盖已有配置）
    hextet()
        .args(["init", "--name", "testnet", "--key-file"])
        .arg(&key)
        .args(["--out"])
        .arg(&cfg)
        .assert()
        .failure();
}

/// M0 验收：两个身份 + 同一 network key → inspect 显示相同 /48 前缀。
#[test]
fn two_identities_share_network_prefix() {
    let dir = tempfile::tempdir().unwrap();
    let (key_a, key_b) = (dir.path().join("a.key"), dir.path().join("b.key"));
    let (cfg_a, cfg_b) = (dir.path().join("a.toml"), dir.path().join("b.toml"));
    hextet()
        .args(["keygen", "--out"])
        .arg(&key_a)
        .assert()
        .success();
    hextet()
        .args(["keygen", "--out"])
        .arg(&key_b)
        .assert()
        .success();

    hextet()
        .args(["init", "--name", "t", "--key-file"])
        .arg(&key_a)
        .args(["--out"])
        .arg(&cfg_a)
        .assert()
        .success();
    // 从 a 的配置里抠出 network key（简单 grep）
    let text = std::fs::read_to_string(&cfg_a).unwrap();
    let netkey = text
        .lines()
        .find(|l| l.starts_with("key = "))
        .unwrap()
        .trim_start_matches("key = ")
        .trim_matches('"')
        .to_owned();
    hextet()
        .args(["init", "--name", "t", "--key-file"])
        .arg(&key_b)
        .args(["--network-key", &netkey, "--out"])
        .arg(&cfg_b)
        .assert()
        .success();

    let prefix = |cfg: &std::path::Path| -> String {
        let out = hextet()
            .args(["inspect", "--json", "-c"])
            .arg(cfg)
            .output()
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        v["network"]["prefix"].as_str().unwrap().to_owned()
    };
    assert_eq!(prefix(&cfg_a), prefix(&cfg_b));
}
