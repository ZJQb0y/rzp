//! RZP 错误类型。

use std::fmt;

/// RZP 编解码过程中可能出现的错误。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// 输入不是合法的 RZP 流（魔数、版本、块头或位流损坏）。
    Corrupt(String),
    /// 完整性校验失败：数据被篡改或损坏。
    ChecksumMismatch,
    /// 长度/大小字段越界或不一致。
    InvalidSize(String),
    /// 底层 I/O 错误。
    Io(String),
    /// 遇到加密流但未提供密码。
    PasswordRequired,
    /// AEAD 认证失败（密码错误或数据被篡改）。
    AuthFailed,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Corrupt(s) => write!(f, "corrupt rzp stream: {s}"),
            Error::ChecksumMismatch => write!(f, "integrity check failed: crc32 mismatch"),
            Error::InvalidSize(s) => write!(f, "invalid size: {s}"),
            Error::Io(s) => write!(f, "io error: {s}"),
            Error::PasswordRequired => write!(f, "password required: encrypted archive"),
            Error::AuthFailed => {
                write!(f, "authentication failed: wrong password or corrupted data")
            }
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e.to_string())
    }
}

/// 便捷的 Result 别名。
pub type Result<T> = std::result::Result<T, Error>;

/// 将某种描述转换为 Corrupt 错误。
pub(crate) fn corrupt<T>(msg: impl Into<String>) -> Result<T> {
    Err(Error::Corrupt(msg.into()))
}

/// 将某种描述转换为 InvalidSize 错误。
pub(crate) fn invalid_size<T>(msg: impl Into<String>) -> Result<T> {
    Err(Error::InvalidSize(msg.into()))
}
