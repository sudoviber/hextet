//! 秘密字符串：Debug 打码 + Drop 时 zeroize（ADR-0010 决策 6）。

use zeroize::Zeroize;

/// 一个需要保密、绝不应出现在任何日志/调试输出里的字符串。
///
/// `Debug` 恒输出 `"<redacted>"`（内容绝不外泄）；`Drop` 时内容被 `zeroize` 抹掉，
/// 尽量减小残留于内存的概率。配置里的 DDNS webhook token / Cloudflare API token
/// 都用它包装（ADR-0010 决策 6：与 network key 同处 0600 配置文件，不让任何
/// 日志/调试路径泄露）。
#[derive(Clone, PartialEq, Eq, serde::Deserialize)]
pub struct SecretString(String);

impl SecretString {
    /// 取原始值。**只有**真正需要明文的地方（如 HTTP 请求头）才调用；
    /// 不要用于日志或 `Debug` 输出。
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl From<String> for SecretString {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for SecretString {
    fn from(s: &str) -> Self {
        Self(s.to_owned())
    }
}

impl std::fmt::Debug for SecretString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // 与 String 的 Debug 同形（带引号），但内容永远是 `<redacted>`。
        write!(f, "\"<redacted>\"")
    }
}

impl Drop for SecretString {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_never_leaks_content() {
        assert_eq!(
            format!("{:?}", SecretString::from("topsecret")),
            "\"<redacted>\""
        );
        assert!(!format!("{:?}", SecretString::from("topsecret")).contains("topsecret"));
    }

    #[test]
    fn expose_returns_raw_value() {
        let s = SecretString::from("tok");
        assert_eq!(s.expose(), "tok");
    }
}
