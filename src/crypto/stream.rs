//! 流式加密/解密：分块 AEAD，内存占用有界。
//!
//! 与 [`super::encrypt_envelope`] / [`super::decrypt_envelope`] 产出的信封布局
//! 完全一致，区别在于本模块按 [`AEAD_CHUNK_SIZE`](crate::format::AEAD_CHUNK_SIZE)
//! 逐块处理，无需把整个明文读入内存。由于信封头部（含明文总长）必须先于密文写出，
//! 加密端需在构造 [`Encryptor`] 时告知总长 `total`；调用方可通过「先流式压缩到临时
//! 文件再流式加密」的两趟方式在内存有界的前提下得知该总长。

use std::io::{self, Read, Write};

use super::aead;
use super::rand;
use super::{chunk_aad, chunk_nonce, ct_eq, derive_key, validate_params};
use crate::error::{Error, Result};
use crate::format::{
    AEAD_CHACHA20_POLY1305, AEAD_CHUNK_SIZE, ENC_HEADER_SIZE, ENVELOPE_VERSION, FLAG_ENCRYPTED,
    KDF_ARGON2ID, MAGIC, NONCE_LEN, SALT_LEN, TAG_LEN,
};

/// 把内部错误转为 `io::Error`（供 `Read`/`Write` trait 使用）。
fn err_to_io(e: Error) -> io::Error {
    io::Error::other(e.to_string())
}

/// 生成随机盐（或使用调用方给定值）。
fn salt_or_random(salt: Option<[u8; SALT_LEN]>) -> Result<[u8; SALT_LEN]> {
    match salt {
        Some(s) => Ok(s),
        None => {
            let mut s = [0u8; SALT_LEN];
            rand::fill_bytes(&mut s).map_err(|e| Error::Io(e.to_string()))?;
            Ok(s)
        }
    }
}

/// 流式加密器：实现 [`Write`]，把明文按 1 MiB 分块加密为信封。
pub struct Encryptor<W: Write> {
    inner: W,
    key: [u8; 32],
    base_nonce: [u8; NONCE_LEN],
    /// 每个分块 AAD 的公共前缀：头(28) + 盐(16) + nonce(12) + 总长(8)。
    aad_prefix: Vec<u8>,
    /// 尚未凑满一个分块的明文暂存区。
    buf: Vec<u8>,
    /// 下一个分块序号。
    index: u64,
    /// 已写入的明文字节数（用于收尾校验）。
    written: u64,
    /// 声明的明文总长。
    total: u64,
}

impl<W: Write> Encryptor<W> {
    /// 创建流式加密器，并立即写出信封头部（含 `total`）。
    ///
    /// `total` 为内层明文总字节数；调用方须在 `finish` 前恰好写入 `total` 字节，
    /// 否则报错。
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        mut inner: W,
        level: u8,
        password: &[u8],
        memory_kib: u32,
        iterations: u32,
        lanes: u32,
        salt: Option<[u8; SALT_LEN]>,
        total: u64,
    ) -> Result<Self> {
        validate_params(memory_kib, iterations, lanes)?;

        let salt = salt_or_random(salt)?;
        let mut base_nonce = [0u8; NONCE_LEN];
        rand::fill_bytes(&mut base_nonce).map_err(|e| Error::Io(e.to_string()))?;

        let (key, kcv) = derive_key(password, &salt, memory_kib, iterations, lanes);

        let mut header = [0u8; ENC_HEADER_SIZE];
        header[0..3].copy_from_slice(&MAGIC);
        header[3] = ENVELOPE_VERSION;
        header[4] = level;
        header[5] = FLAG_ENCRYPTED;
        header[6] = KDF_ARGON2ID;
        header[7] = AEAD_CHACHA20_POLY1305;
        header[8..12].copy_from_slice(&memory_kib.to_le_bytes());
        header[12..16].copy_from_slice(&iterations.to_le_bytes());
        header[16..20].copy_from_slice(&lanes.to_le_bytes());
        header[20..28].copy_from_slice(&kcv);

        let mut aad_prefix = Vec::with_capacity(ENC_HEADER_SIZE + SALT_LEN + NONCE_LEN + 8);
        aad_prefix.extend_from_slice(&header);
        aad_prefix.extend_from_slice(&salt);
        aad_prefix.extend_from_slice(&base_nonce);
        aad_prefix.extend_from_slice(&total.to_le_bytes());

        inner.write_all(&header).map_err(Error::from)?;
        inner.write_all(&salt).map_err(Error::from)?;
        inner.write_all(&base_nonce).map_err(Error::from)?;
        inner.write_all(&total.to_le_bytes()).map_err(Error::from)?;

        Ok(Encryptor {
            inner,
            key,
            base_nonce,
            aad_prefix,
            buf: Vec::with_capacity(AEAD_CHUNK_SIZE),
            index: 0,
            written: 0,
            total,
        })
    }

    /// 加密并写出一个分块（密文 + tag），并递增分块序号。
    fn emit_chunk(&mut self, plain: &[u8]) -> Result<()> {
        let nonce = chunk_nonce(&self.base_nonce, self.index);
        let aad = chunk_aad(&self.aad_prefix, self.index);
        let (ct, tag) = aead::encrypt(&self.key, &nonce, &aad, plain);
        self.inner.write_all(&ct).map_err(Error::from)?;
        self.inner.write_all(&tag).map_err(Error::from)?;
        self.index += 1;
        Ok(())
    }

    /// 结束加密：写出最后一个（可能不足 1 MiB 或为空的）分块并刷新底层写入器。
    pub fn finish(mut self) -> Result<W> {
        if !self.buf.is_empty() {
            let chunk = std::mem::take(&mut self.buf);
            self.emit_chunk(&chunk)?;
        } else if self.total == 0 {
            // 空明文对应一个零长度分块（保持与一次性路径一致）。
            self.emit_chunk(&[])?;
        }

        if self.written != self.total {
            return Err(Error::InvalidSize(format!(
                "wrote {} bytes but declared total {}",
                self.written, self.total
            )));
        }

        self.inner.flush().map_err(Error::from)?;
        Ok(self.inner)
    }
}

impl<W: Write> Write for Encryptor<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.written + buf.len() as u64 > self.total {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "wrote more than declared total length",
            ));
        }
        self.written += buf.len() as u64;

        let mut rest = buf;

        // 先用已有部分补齐一个完整分块。
        if !self.buf.is_empty() {
            let need = AEAD_CHUNK_SIZE - self.buf.len();
            let take = need.min(rest.len());
            self.buf.extend_from_slice(&rest[..take]);
            rest = &rest[take..];
            if self.buf.len() == AEAD_CHUNK_SIZE {
                let full = std::mem::take(&mut self.buf);
                self.emit_chunk(&full).map_err(err_to_io)?;
            }
        }

        // 完整分块直接从输入切片加密，避免拷贝。
        while rest.len() >= AEAD_CHUNK_SIZE {
            self.emit_chunk(&rest[..AEAD_CHUNK_SIZE])
                .map_err(err_to_io)?;
            rest = &rest[AEAD_CHUNK_SIZE..];
        }

        // 余下不足一个分块的部分暂存。
        self.buf.extend_from_slice(rest);

        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// 流式解密器：实现 [`Read`]，按 1 MiB 分块解密并认证。
pub struct Decryptor<R: Read> {
    inner: R,
    key: [u8; 32],
    base_nonce: [u8; NONCE_LEN],
    aad_prefix: Vec<u8>,
    /// 当前分块已解出的明文与读取位置。
    plain_buf: Vec<u8>,
    plain_pos: usize,
    /// 下一个分块序号。
    index: u64,
    /// 剩余待解密的分块数。
    chunks_left: u64,
    /// 剩余待解密的明文字节数（用于确定最后一块长度）。
    remaining: u64,
}

impl<R: Read> Decryptor<R> {
    /// 读取并校验信封头部，派生密钥并做 KCV 快速口令拒绝。
    pub fn new(mut inner: R, password: &[u8]) -> Result<Self> {
        let mut header = [0u8; ENC_HEADER_SIZE];
        inner.read_exact(&mut header)?;
        if header[0..3] != MAGIC[..] {
            return Err(Error::Corrupt("bad magic bytes".into()));
        }
        if header[3] != ENVELOPE_VERSION {
            return Err(Error::Corrupt(format!("unsupported version {}", header[3])));
        }
        if header[5] & FLAG_ENCRYPTED == 0 {
            return Err(Error::Corrupt("not an encrypted envelope".into()));
        }
        if header[6] != KDF_ARGON2ID {
            return Err(Error::Corrupt(format!("unsupported KDF id {}", header[6])));
        }
        if header[7] != AEAD_CHACHA20_POLY1305 {
            return Err(Error::Corrupt(format!("unsupported AEAD id {}", header[7])));
        }

        let memory_kib = u32::from_le_bytes(header[8..12].try_into().unwrap());
        let iterations = u32::from_le_bytes(header[12..16].try_into().unwrap());
        let lanes = u32::from_le_bytes(header[16..20].try_into().unwrap());
        validate_params(memory_kib, iterations, lanes)?;

        let mut salt = [0u8; SALT_LEN];
        inner.read_exact(&mut salt)?;
        let mut base_nonce = [0u8; NONCE_LEN];
        inner.read_exact(&mut base_nonce)?;
        let mut total_bytes = [0u8; 8];
        inner.read_exact(&mut total_bytes)?;
        let total = u64::from_le_bytes(total_bytes);

        let (key, kcv) = derive_key(password, &salt, memory_kib, iterations, lanes);
        if !ct_eq(&kcv, &header[20..28]) {
            return Err(Error::AuthFailed);
        }

        let mut aad_prefix = Vec::with_capacity(ENC_HEADER_SIZE + SALT_LEN + NONCE_LEN + 8);
        aad_prefix.extend_from_slice(&header);
        aad_prefix.extend_from_slice(&salt);
        aad_prefix.extend_from_slice(&base_nonce);
        aad_prefix.extend_from_slice(&total_bytes);

        let chunks_left = total.div_ceil(AEAD_CHUNK_SIZE as u64).max(1);

        Ok(Decryptor {
            inner,
            key,
            base_nonce,
            aad_prefix,
            plain_buf: Vec::new(),
            plain_pos: 0,
            index: 0,
            chunks_left,
            remaining: total,
        })
    }

    /// 读取并解密下一个分块，填充 `plain_buf`。
    fn load_chunk(&mut self) -> Result<()> {
        let chunk_len = (self.remaining as usize).min(AEAD_CHUNK_SIZE);
        let mut ct = vec![0u8; chunk_len];
        self.inner.read_exact(&mut ct)?;
        let mut tag = [0u8; TAG_LEN];
        self.inner.read_exact(&mut tag)?;

        let nonce = chunk_nonce(&self.base_nonce, self.index);
        let aad = chunk_aad(&self.aad_prefix, self.index);
        let plain =
            aead::decrypt(&self.key, &nonce, &aad, &ct, &tag).map_err(|_| Error::AuthFailed)?;

        self.plain_buf = plain;
        self.plain_pos = 0;
        self.remaining -= chunk_len as u64;
        self.index += 1;
        self.chunks_left -= 1;
        Ok(())
    }
}

impl<R: Read> Read for Decryptor<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        while self.plain_pos >= self.plain_buf.len() {
            if self.chunks_left == 0 {
                return Ok(0);
            }
            self.load_chunk().map_err(err_to_io)?;
        }
        let avail = self.plain_buf.len() - self.plain_pos;
        let n = avail.min(buf.len());
        buf[..n].copy_from_slice(&self.plain_buf[self.plain_pos..self.plain_pos + n]);
        self.plain_pos += n;
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    const FAST: (u32, u32, u32) = (32, 3, 4);

    fn roundtrip(inner: &[u8]) {
        let mut enc = Encryptor::new(
            Vec::new(),
            6,
            b"pw",
            FAST.0,
            FAST.1,
            FAST.2,
            None,
            inner.len() as u64,
        )
        .unwrap();
        enc.write_all(inner).unwrap();
        let packed = enc.finish().unwrap();

        // 与一次性路径的布局逐字节一致（相同盐/随机源不同，仅比对可解性）。
        let mut dec = Decryptor::new(Cursor::new(packed), b"pw").unwrap();
        let mut out = Vec::new();
        dec.read_to_end(&mut out).unwrap();
        assert_eq!(out, inner);
    }

    #[test]
    fn stream_roundtrip_small_and_multichunk() {
        for len in [
            0usize,
            1,
            100,
            AEAD_CHUNK_SIZE - 1,
            AEAD_CHUNK_SIZE,
            AEAD_CHUNK_SIZE + 1,
            AEAD_CHUNK_SIZE * 2 + 7,
        ] {
            let inner: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            roundtrip(&inner);
        }
    }

    #[test]
    fn stream_wrong_password_fails() {
        let mut enc =
            Encryptor::new(Vec::new(), 6, b"pw", FAST.0, FAST.1, FAST.2, None, 10).unwrap();
        enc.write_all(b"0123456789").unwrap();
        let packed = enc.finish().unwrap();
        // 错误密码应在构造阶段被 KCV 快速拒绝。
        assert!(matches!(
            Decryptor::new(Cursor::new(packed), b"wrong"),
            Err(Error::AuthFailed)
        ));
    }

    #[test]
    fn stream_declared_length_mismatch_fails() {
        // 声明 10 字节却写 0 字节，finish 应报错。
        let enc = Encryptor::new(Vec::new(), 6, b"pw", FAST.0, FAST.1, FAST.2, None, 10).unwrap();
        assert!(enc.finish().is_err());
    }
}
