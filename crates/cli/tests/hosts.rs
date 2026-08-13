//! `hextet hosts` 端到端 CLI 测试。

use assert_cmd::Command;

fn hextet() -> Command {
    Command::cargo_bin("hextet").unwrap()
}

/// 建一个可用节点（密钥 + 配置），返回配置路径。
fn setup_node(dir: &std::path::Path, tag: &str) -> std::path::PathBuf {
    let key = dir.join(format!("{tag}.key"));
    let cfg = dir.join(format!("{tag}.toml"));
    hextet()
        .args(["keygen", "--out"])
        .arg(&key)
        .assert()
        .success();
    hextet()
        .args(["init", "--name", "t", "--key-file"])
        .arg(&key)
        .args(["--out"])
        .arg(&cfg)
        .assert()
        .success();
    cfg
}

/// 生成一把密钥并返回其公钥（base64）。
fn gen_pubkey(dir: &std::path::Path, tag: &str) -> String {
    let key = dir.join(format!("{tag}.key"));
    let out = hextet()
        .args(["keygen", "--out"])
        .arg(&key)
        .output()
        .unwrap();
    assert!(out.status.success());
    String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .find_map(|l| l.strip_prefix("public-key: ").map(str::to_owned))
        .unwrap()
}

/// 两个 peer 的名字净化后撞名（"My NAS" / "My_NAS" → 都是 `my-nas`），
/// 断言 `hextet hosts` 输出净化的主机名 + 去重后缀 + overlay 地址。
#[test]
fn hosts_prints_sanitized_peer_names_and_overlay_addresses() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = setup_node(dir.path(), "a");

    let pubkey_b = gen_pubkey(dir.path(), "b");
    let pubkey_c = gen_pubkey(dir.path(), "c");
    hextet()
        .args(["peer", "add", "-c"])
        .arg(&cfg)
        .args(["--name", "My NAS", "--public-key", &pubkey_b])
        .assert()
        .success();
    hextet()
        .args(["peer", "add", "-c"])
        .arg(&cfg)
        .args(["--name", "My_NAS", "--public-key", &pubkey_c])
        .assert()
        .success();

    // 从 inspect 取 peer 的 overlay 地址（配置顺序 = 添加顺序）
    let inspect = hextet()
        .args(["inspect", "--json", "-c"])
        .arg(&cfg)
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&inspect.stdout).unwrap();
    let peers = v["peers"].as_array().unwrap();
    let addr_b = peers[0]["address"].as_str().unwrap();
    let addr_c = peers[1]["address"].as_str().unwrap();

    let out = hextet().args(["hosts", "-c"]).arg(&cfg).output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert_eq!(
        stdout,
        format!("{addr_b}  my-nas  my-nas.hextet\n{addr_c}  my-nas-2  my-nas-2.hextet\n")
    );
}

/// `--out` 原子写入 0644 文件，stdout 不输出。
#[test]
fn hosts_out_writes_file_with_0644_and_empty_stdout() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = setup_node(dir.path(), "a");
    let pubkey_b = gen_pubkey(dir.path(), "b");
    hextet()
        .args(["peer", "add", "-c"])
        .arg(&cfg)
        .args(["--name", "NAS Box", "--public-key", &pubkey_b])
        .assert()
        .success();

    let out_path = dir.path().join("my-hosts");
    let out = hextet()
        .args(["hosts", "-c"])
        .arg(&cfg)
        .args(["--out"])
        .arg(&out_path)
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(out.stdout.is_empty(), "--out 时不应打印到 stdout");

    let written = std::fs::read_to_string(&out_path).unwrap();
    assert!(written.contains("nas-box  nas-box.hextet"), "got {written}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&out_path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o644, "hosts 输出文件权限应为 0644");
    }
}
