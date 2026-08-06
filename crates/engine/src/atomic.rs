//! JSON 文件的原子读写。
//!
//! daemon 每秒重写一次状态文件，而 `hextet status` 随时可能在读——直接
//! `File::create` + 写入会让读者看到半截 JSON。这里统一走"写临时文件 → fsync →
//! rename"：同目录内的 rename 在 POSIX 下是原子替换，读者要么看到旧的完整内容，
//! 要么看到新的完整内容。

use std::io;
use std::path::Path;

use serde::Serialize;
use serde::de::DeserializeOwned;

fn invalid_data(e: serde_json::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e)
}

/// 原子写入 JSON（Unix 下权限 0600）。
pub fn write_json<T: Serialize>(path: &Path, value: &T) -> io::Result<()> {
    use std::io::Write as _;

    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let stem = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "state".to_string());
    // 临时文件必须与目标同目录，否则 rename 可能跨文件系统而失败
    let tmp = dir.join(format!(".{stem}.tmp"));

    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let mut f = opts.open(&tmp)?;
    // 临时文件可能是上次崩溃留下的（权限已存在、mode() 不生效），显式再设一次
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    }
    serde_json::to_writer_pretty(&mut f, value).map_err(invalid_data)?;
    f.write_all(b"\n")?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(&tmp, path)
}

/// 读取并解析 JSON 文件。
pub fn read_json<T: DeserializeOwned>(path: &Path) -> io::Result<T> {
    let text = std::fs::read_to_string(path)?;
    serde_json::from_str(&text).map_err(invalid_data)
}
