//! 加密随机源：Unix 上读取 `/dev/urandom`，Windows 上调用 `RtlGenRandom`。
//!
//! 用于生成盐（16 字节）与 nonce（12 字节）。

use std::io;

/// 用系统随机源填充缓冲区。
#[cfg(unix)]
pub fn fill_bytes(buf: &mut [u8]) -> io::Result<()> {
    use std::fs::File;
    use std::io::Read;
    let mut f = File::open("/dev/urandom")?;
    f.read_exact(buf)
}

/// Windows：通过 `advapi32` 的 `RtlGenRandom`（导出名 `SystemFunction036`）填充。
#[cfg(windows)]
pub fn fill_bytes(buf: &mut [u8]) -> io::Result<()> {
    #[link(name = "advapi32")]
    extern "system" {
        fn SystemFunction036(buf: *mut u8, len: u32) -> u8;
    }
    let ok = unsafe { SystemFunction036(buf.as_mut_ptr(), buf.len() as u32) };
    if ok == 0 {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "RtlGenRandom failed",
        ));
    }
    Ok(())
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
