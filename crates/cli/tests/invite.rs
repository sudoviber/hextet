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

/// M3-A 主验收：签发方与加入方派生出同一个 /48 前缀。
#[test]
fn join_gives_the_same_network_prefix_as_the_issuer() {
    let dir = tempfile::tempdir().unwrap();
    let (cfg_a, _) = setup_node(dir.path(), "a", None);
    let token = issue_token(&cfg_a, &[]);

    let key_b = dir.path().join("b.key");
    let cfg_b = dir.path().join("b.toml");
    hextet()
        .args(["join", &token, "--key-file"])
        .arg(&key_b)
        .args(["--out"])
        .arg(&cfg_b)
        .assert()
        .success()
        .stdout(predicate::str::contains("hextet peer add"));

    assert!(key_b.exists() && cfg_b.exists());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for p in [&key_b, &cfg_b] {
            let mode = std::fs::metadata(p).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "{} 权限应为 0600", p.display());
        }
    }

    let prefix_of = |cfg: &std::path::Path| -> String {
        let out = hextet()
            .args(["inspect", "--json", "-c"])
            .arg(cfg)
            .output()
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        v["network"]["prefix"].as_str().unwrap().to_owned()
    };
    assert_eq!(prefix_of(&cfg_a), prefix_of(&cfg_b));

    // 引导节点被写成了 b 的 peer，且带上了 token 里的 endpoint
    let out = hextet()
        .args(["inspect", "--json", "-c"])
        .arg(&cfg_b)
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["peers"][0]["name"], "bootstrap");
    assert_eq!(v["peers"][0]["endpoints"][0], "[2001:db8::1]:4193");
}

#[test]
fn join_reuses_an_existing_key_file() {
    let dir = tempfile::tempdir().unwrap();
    let (cfg_a, _) = setup_node(dir.path(), "a", None);
    let token = issue_token(&cfg_a, &[]);

    let key_b = dir.path().join("b.key");
    let out = hextet()
        .args(["keygen", "--out"])
        .arg(&key_b)
        .output()
        .unwrap();
    let pubkey_before = String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .find_map(|l| l.strip_prefix("public-key: ").map(str::to_owned))
        .unwrap();
    let bytes_before = std::fs::read(&key_b).unwrap();

    let join_out = hextet()
        .args(["join", &token, "--key-file"])
        .arg(&key_b)
        .args(["--out"])
        .arg(dir.path().join("b.toml"))
        .args(["--json"])
        .output()
        .unwrap();
    assert!(join_out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&join_out.stdout).unwrap();
    assert_eq!(v["public_key"].as_str().unwrap(), pubkey_before);
    assert_eq!(std::fs::read(&key_b).unwrap(), bytes_before);
}

#[test]
fn join_refuses_to_overwrite_an_existing_config() {
    let dir = tempfile::tempdir().unwrap();
    let (cfg_a, _) = setup_node(dir.path(), "a", None);
    let token = issue_token(&cfg_a, &[]);

    let existing = dir.path().join("taken.toml");
    std::fs::write(&existing, "# 我的配置，别动\n").unwrap();
    let key_b = dir.path().join("b.key");
    hextet()
        .args(["join", &token, "--key-file"])
        .arg(&key_b)
        .args(["--out"])
        .arg(&existing)
        .assert()
        .failure()
        .stderr(predicate::str::contains("已存在"));
    assert_eq!(
        std::fs::read_to_string(&existing).unwrap(),
        "# 我的配置，别动\n"
    );
    // 配置没写成，就不该留下一把孤儿密钥
    assert!(!key_b.exists(), "join 失败后不应留下新生成的密钥文件");
}

#[test]
fn join_rejects_tampered_and_expired_tokens() {
    let dir = tempfile::tempdir().unwrap();
    let (cfg_a, _) = setup_node(dir.path(), "a", None);
    let token = issue_token(&cfg_a, &[]);

    // 篡改载荷中间的一个字符
    let mut bytes = token.clone().into_bytes();
    let mid = bytes.len() / 2;
    bytes[mid] = if bytes[mid] == b'A' { b'B' } else { b'A' };
    let tampered = String::from_utf8(bytes).unwrap();
    hextet()
        .args(["join", &tampered, "--key-file"])
        .arg(dir.path().join("t.key"))
        .args(["--out"])
        .arg(dir.path().join("t.toml"))
        .assert()
        .failure()
        .stderr(predicate::str::contains("篡改"));

    // 1 秒有效期的 token：睡过它再用。
    //
    // 睡 2.1s 而不是 1.5s 是必须的：token 里的时间戳是**整秒**，
    // `expires = floor(签发时刻) + 1`，而 join 侧比较的是 `floor(使用时刻) > expires`。
    // 签发时刻的小数部分 f ∈ [0,1)：睡 1.5s 时 floor(T+1.5) 在 f < 0.5 时只等于
    // floor(T)+1，判定不出过期——一个约五成概率的假失败。睡 ≥2s 则对任意 f 都有
    // floor(T+2.1) ≥ floor(T)+2 > expires，恒定成立。
    let short = issue_token(&cfg_a, &["--ttl", "1s"]);
    std::thread::sleep(std::time::Duration::from_millis(2_100));
    hextet()
        .args(["join", &short, "--key-file"])
        .arg(dir.path().join("e.key"))
        .args(["--out"])
        .arg(dir.path().join("e.toml"))
        .assert()
        .failure()
        .stderr(predicate::str::contains("过期"));
}

/// 端到端闭环：A 签发 → B join → 双方 peer add → 两侧互相看到对方地址。
#[test]
fn invite_join_peer_add_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let (cfg_a, pubkey_a) = setup_node(dir.path(), "a", None);
    let token = issue_token(&cfg_a, &[]);

    let key_b = dir.path().join("b.key");
    let cfg_b = dir.path().join("b.toml");
    let join_out = hextet()
        .args(["join", &token, "--key-file"])
        .arg(&key_b)
        .args(["--out"])
        .arg(&cfg_b)
        .args(["--name", "laptop", "--json"])
        .output()
        .unwrap();
    assert!(join_out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&join_out.stdout).unwrap();
    let pubkey_b = v["public_key"].as_str().unwrap().to_owned();
    assert!(
        v["peer_add_command"].as_str().unwrap().contains(&pubkey_b),
        "peer_add_command 里应包含自己的公钥"
    );

    // 引导侧接纳 b
    hextet()
        .args(["peer", "add", "-c"])
        .arg(&cfg_a)
        .args([
            "--name",
            "laptop",
            "--public-key",
            &pubkey_b,
            "--endpoint",
            "[2001:db8::2]:4193",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("added peer laptop"));

    let peers_of = |cfg: &std::path::Path| -> serde_json::Value {
        let out = hextet()
            .args(["inspect", "--json", "-c"])
            .arg(cfg)
            .output()
            .unwrap();
        serde_json::from_slice::<serde_json::Value>(&out.stdout).unwrap()["peers"].clone()
    };
    let a_peers = peers_of(&cfg_a);
    assert_eq!(a_peers.as_array().unwrap().len(), 1);
    assert_eq!(a_peers[0]["public_key"].as_str().unwrap(), pubkey_b);
    let b_peers = peers_of(&cfg_b);
    assert_eq!(b_peers[0]["public_key"].as_str().unwrap(), pubkey_a);
    // 双方互相看到的地址一致（都由公钥派生）
    let a_view_of_b = a_peers[0]["address"].as_str().unwrap().to_owned();
    let b_self = {
        let out = hextet()
            .args(["inspect", "--json", "-c"])
            .arg(&cfg_b)
            .output()
            .unwrap();
        serde_json::from_slice::<serde_json::Value>(&out.stdout).unwrap()["node"]["address"]
            .as_str()
            .unwrap()
            .to_owned()
    };
    assert_eq!(a_view_of_b, b_self);
}

#[test]
fn peer_add_rejects_duplicates_and_keeps_config_intact() {
    let dir = tempfile::tempdir().unwrap();
    let (cfg_a, _) = setup_node(dir.path(), "a", None);
    let (_, pubkey_b) = setup_node(dir.path(), "b", None);

    hextet()
        .args(["peer", "add", "-c"])
        .arg(&cfg_a)
        .args(["--name", "b", "--public-key", &pubkey_b])
        .assert()
        .success();
    let after_first = std::fs::read_to_string(&cfg_a).unwrap();

    // 同公钥
    hextet()
        .args(["peer", "add", "-c"])
        .arg(&cfg_a)
        .args(["--name", "b2", "--public-key", &pubkey_b])
        .assert()
        .failure()
        .stderr(predicate::str::contains("已经是 peer"));
    // 同名（换一把公钥）
    let (_, pubkey_c) = setup_node(dir.path(), "c", None);
    hextet()
        .args(["peer", "add", "-c"])
        .arg(&cfg_a)
        .args(["--name", "b", "--public-key", &pubkey_c])
        .assert()
        .failure()
        .stderr(predicate::str::contains("已存在名为"));
    // 自己的公钥
    let out = hextet()
        .args(["inspect", "--json", "-c"])
        .arg(&cfg_a)
        .output()
        .unwrap();
    let own =
        serde_json::from_slice::<serde_json::Value>(&out.stdout).unwrap()["node"]["public_key"]
            .as_str()
            .unwrap()
            .to_owned();
    hextet()
        .args(["peer", "add", "-c"])
        .arg(&cfg_a)
        .args(["--name", "me", "--public-key", &own])
        .assert()
        .failure()
        .stderr(predicate::str::contains("本节点自己"));

    assert_eq!(
        std::fs::read_to_string(&cfg_a).unwrap(),
        after_first,
        "被拒绝的 peer add 不许改动配置文件"
    );
}

/// 追加式修改必须保留原有注释（这是"配置文件是用户的"的可验证承诺）。
#[test]
fn peer_add_preserves_user_comments() {
    let dir = tempfile::tempdir().unwrap();
    let (cfg_a, _) = setup_node(dir.path(), "a", None);
    let (_, pubkey_b) = setup_node(dir.path(), "b", None);
    let mut text = std::fs::read_to_string(&cfg_a).unwrap();
    text.push_str("\n# 我自己写的说明，不要被吃掉\n");
    std::fs::write(&cfg_a, &text).unwrap();

    hextet()
        .args(["peer", "add", "-c"])
        .arg(&cfg_a)
        .args(["--name", "b", "--public-key", &pubkey_b])
        .assert()
        .success();
    let after = std::fs::read_to_string(&cfg_a).unwrap();
    assert!(after.contains("# 我自己写的说明，不要被吃掉"));
    assert!(after.contains("# mtu = 1400"));
}

#[test]
fn peer_add_rejects_ipv4_endpoint_and_bad_key() {
    let dir = tempfile::tempdir().unwrap();
    let (cfg_a, _) = setup_node(dir.path(), "a", None);
    let (_, pubkey_b) = setup_node(dir.path(), "b", None);
    hextet()
        .args(["peer", "add", "-c"])
        .arg(&cfg_a)
        .args([
            "--name",
            "b",
            "--public-key",
            &pubkey_b,
            "--endpoint",
            "1.2.3.4:4193",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("IPv6-only"));
    hextet()
        .args(["peer", "add", "-c"])
        .arg(&cfg_a)
        .args(["--name", "b", "--public-key", "not-base64!!"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("public-key"));
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
