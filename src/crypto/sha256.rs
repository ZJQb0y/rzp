//! 测试辅助：十六进制小写编码。
//!
//! SHA-256 / HMAC-SHA256 原实现已随 PBKDF2 升级为 Argon2id 而移除；
//! 本模块仅保留供各密码学子模块测试共用的 `hex` 工具函数。

/// 十六进制小写字符串（测试用）。
#[cfg(test)]
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
