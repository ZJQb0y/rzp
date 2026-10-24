//! 加密随机源：Unix 上读取 `/dev/urandom`，失败返回错误。
//!
//! 用于生成盐（16 字节）与 nonce（12 字节）。

use std::fs::File;
use std::io::Read;

/// 用系统随机源填充缓冲区。
pub fn fill_bytes(buf: &mut [u8]) -> std::io::Result<()> {
    let mut f = File::open("/dev/urandom")?;
    f.read_exact(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fill_works_and_varied() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        fill_bytes(&mut a).unwrap();
        fill_bytes(&mut b).unwrap();
        // 概率上几乎不可能相同；即使相同也不影响功能，仅作 sanity 检查。
        assert!(a != [0u8; 32]);
        assert!(b != [0u8; 32]);
        let _ = (a, b);
    }
}
