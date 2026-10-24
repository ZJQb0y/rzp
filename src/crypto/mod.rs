//! 从零实现的密码学原语（无第三方依赖）。
//!
//! 本模块保持 crate 内部私有，仅通过 `src/lib.rs` 中的加密/解密公共 API
//! 暴露给外部使用。实现均对照 RFC / NIST 标准测试向量验证，见各子模块。

pub mod aead;
pub mod argon2;
pub mod blake2b;
pub mod chacha20;
pub mod poly1305;
pub mod rand;
pub mod sha256;
pub mod stream;

use crate::error::{Error, Result};
use crate::format::{
    AEAD_CHACHA20_POLY1305, AEAD_CHUNK_SIZE, ARGON2_MAX_ITERATIONS, ARGON2_MAX_LANES,
    ARGON2_MAX_MEMORY_KIB, ENC_HEADER_SIZE, FLAG_ENCRYPTED, KCV_LEN, KDF_ARGON2ID, MAGIC,
    NONCE_LEN, SALT_LEN, TAG_LEN, VERSION,
};

/// Argon2 类型标识：Argon2id。
const ARGON2ID_TYPE: u32 = 2;
/// Argon2id 派生输出长度：前 32 字节作加密密钥，后 8 字节作 KCV。
const ARGON2_OUT_LEN: u32 = 40;

/// 校验 Argon2id 参数范围，防止恶意归档导致过度的内存/CPU 消耗。
fn validate_params(memory_kib: u32, iterations: u32, lanes: u32) -> Result<()> {
    if memory_kib == 0 || memory_kib > ARGON2_MAX_MEMORY_KIB {
        return Err(Error::InvalidSize(format!(
            "Argon2id memory cost out of range: {memory_kib} KiB"
        )));
    }
    if iterations == 0 || iterations > ARGON2_MAX_ITERATIONS {
        return Err(Error::InvalidSize(format!(
            "Argon2id iterations out of range: {iterations}"
        )));
    }
    if lanes == 0 || lanes > ARGON2_MAX_LANES {
        return Err(Error::InvalidSize(format!(
            "Argon2id lanes out of range: {lanes}"
        )));
    }
    Ok(())
}

/// 派生主密钥与 KCV：一次 Argon2id 调用输出 40 字节。
fn derive_key(
    password: &[u8],
    salt: &[u8],
    memory_kib: u32,
    iterations: u32,
    lanes: u32,
) -> ([u8; 32], [u8; KCV_LEN]) {
    let out = argon2::argon2(
        password,
        salt,
        lanes,
        ARGON2_OUT_LEN,
        memory_kib,
        iterations,
        ARGON2ID_TYPE,
        &[],
        &[],
    );
    let mut key = [0u8; 32];
    key.copy_from_slice(&out[..32]);
    let mut kcv = [0u8; KCV_LEN];
    kcv.copy_from_slice(&out[32..40]);
    (key, kcv)
}

/// 由基础 nonce 与分块序号派生该块 nonce：低 8 字节与 `LE64(index)` 异或。
fn chunk_nonce(base: &[u8; NONCE_LEN], index: u64) -> [u8; NONCE_LEN] {
    let mut n = *base;
    let idx = index.to_le_bytes();
    for i in 0..8 {
        n[4 + i] ^= idx[i];
    }
    n
}

/// 组装某个分块的 AAD：公共前缀（头 + 盐 + nonce + 总长）+ 分块序号。
fn chunk_aad(prefix: &[u8], index: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(prefix.len() + 8);
    aad.extend_from_slice(prefix);
    aad.extend_from_slice(&index.to_le_bytes());
    aad
}

/// 常量时间字节串比较。
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// 用密码把一段内层明文 RZP 流加密为 v4 信封（Argon2id + 分块 AEAD）。
///
/// 信封布局见 `FORMAT.md`：外层头(28) + salt(16) + nonce(12) + 总长(8) +
/// 分块密文流（每块后跟 16 字节 tag）。
pub fn encrypt_envelope(
    inner: &[u8],
    level: u8,
    password: &[u8],
    memory_kib: u32,
    iterations: u32,
    lanes: u32,
    salt: Option<[u8; SALT_LEN]>,
) -> Result<Vec<u8>> {
    validate_params(memory_kib, iterations, lanes)?;

    let salt = match salt {
        Some(s) => s,
        None => {
            let mut s = [0u8; SALT_LEN];
            rand::fill_bytes(&mut s).map_err(|e| Error::Io(e.to_string()))?;
            s
        }
    };

    let mut base_nonce = [0u8; NONCE_LEN];
    rand::fill_bytes(&mut base_nonce).map_err(|e| Error::Io(e.to_string()))?;

    let (key, kcv) = derive_key(password, &salt, memory_kib, iterations, lanes);

    // 外层头。
    let mut header = [0u8; ENC_HEADER_SIZE];
    header[0..3].copy_from_slice(&MAGIC);
    header[3] = VERSION;
    header[4] = level;
    header[5] = FLAG_ENCRYPTED;
    header[6] = KDF_ARGON2ID;
    header[7] = AEAD_CHACHA20_POLY1305;
    header[8..12].copy_from_slice(&memory_kib.to_le_bytes());
    header[12..16].copy_from_slice(&iterations.to_le_bytes());
    header[16..20].copy_from_slice(&lanes.to_le_bytes());
    header[20..28].copy_from_slice(&kcv);

    let total = inner.len() as u64;

    // 公共前缀：头 + 盐 + nonce + 总长，也是每个分块 AAD 的公共部分。
    let mut out =
        Vec::with_capacity(ENC_HEADER_SIZE + SALT_LEN + NONCE_LEN + 8 + inner.len() + TAG_LEN);
    out.extend_from_slice(&header);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&base_nonce);
    out.extend_from_slice(&total.to_le_bytes());
    let prefix = out.clone();

    let num_chunks = inner.len().div_ceil(AEAD_CHUNK_SIZE).max(1);
    for i in 0..num_chunks {
        let start = i * AEAD_CHUNK_SIZE;
        let end = (start + AEAD_CHUNK_SIZE).min(inner.len());
        let plain = &inner[start..end];
        let nonce = chunk_nonce(&base_nonce, i as u64);
        let aad = chunk_aad(&prefix, i as u64);
        let (ct, tag) = aead::encrypt(&key, &nonce, &aad, plain);
        out.extend_from_slice(&ct);
        out.extend_from_slice(&tag);
    }

    Ok(out)
}

/// 校验信封外层头并解密，返回内层明文 RZP 流。
///
/// 先用 KCV 快速拒绝错误密码（避免错误密码跑完整分块 AEAD 认证），
/// 再逐块解密并认证。
pub fn decrypt_envelope(data: &[u8], password: &[u8]) -> Result<Vec<u8>> {
    // 头 + 盐 + nonce + 总长 + 至少一个空块 tag。
    let min = ENC_HEADER_SIZE + SALT_LEN + NONCE_LEN + 8 + TAG_LEN;
    if data.len() < min {
        return Err(Error::Corrupt("encrypted envelope too short".into()));
    }

    let header = &data[..ENC_HEADER_SIZE];
    if header[0..3] != MAGIC[..] {
        return Err(Error::Corrupt("bad magic bytes".into()));
    }
    if header[3] != VERSION {
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

    let kcv_stored = &header[20..28];
    let salt = &data[ENC_HEADER_SIZE..ENC_HEADER_SIZE + SALT_LEN];
    let nonce_off = ENC_HEADER_SIZE + SALT_LEN;
    let base_nonce: [u8; NONCE_LEN] = data[nonce_off..nonce_off + NONCE_LEN].try_into().unwrap();
    let total_off = nonce_off + NONCE_LEN;
    let total = u64::from_le_bytes(data[total_off..total_off + 8].try_into().unwrap());
    let ct_start = total_off + 8;

    let (key, kcv) = derive_key(password, salt, memory_kib, iterations, lanes);

    // 快速错误密码拒绝（KCV）。
    if !ct_eq(&kcv, kcv_stored) {
        return Err(Error::AuthFailed);
    }

    let num_chunks = (total as usize).div_ceil(AEAD_CHUNK_SIZE).max(1);
    let mut plain = Vec::with_capacity(total as usize);
    let mut off = ct_start;
    for i in 0..num_chunks {
        let start = i * AEAD_CHUNK_SIZE;
        let chunk_len = AEAD_CHUNK_SIZE.min(total as usize - start);
        if off + chunk_len + TAG_LEN > data.len() {
            return Err(Error::Corrupt("truncated encrypted envelope".into()));
        }
        let ct = &data[off..off + chunk_len];
        let tag: [u8; TAG_LEN] = data[off + chunk_len..off + chunk_len + TAG_LEN]
            .try_into()
            .unwrap();
        off += chunk_len + TAG_LEN;

        let nonce = chunk_nonce(&base_nonce, i as u64);
        let aad = chunk_aad(&data[..ct_start], i as u64);
        let chunk_plain =
            aead::decrypt(&key, &nonce, &aad, ct, &tag).map_err(|_| Error::AuthFailed)?;
        plain.extend_from_slice(&chunk_plain);
    }

    Ok(plain)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAST: (u32, u32, u32) = (32, 3, 4); // 快速测试用 Argon2id 参数。

    #[test]
    fn envelope_roundtrip() {
        let inner = b"the inner plain rzp stream";
        let packed = encrypt_envelope(inner, 6, b"secret", FAST.0, FAST.1, FAST.2, None).unwrap();
        let out = decrypt_envelope(&packed, b"secret").unwrap();
        assert_eq!(out, inner);
    }

    #[test]
    fn envelope_roundtrip_empty() {
        let packed = encrypt_envelope(b"", 6, b"secret", FAST.0, FAST.1, FAST.2, None).unwrap();
        assert_eq!(decrypt_envelope(&packed, b"secret").unwrap(), b"");
    }

    #[test]
    fn envelope_roundtrip_multichunk() {
        // 超过一个分块（1 MiB），验证分块流式 AEAD 的拼接。
        let inner: Vec<u8> = (0..AEAD_CHUNK_SIZE + 1234)
            .map(|i| (i % 251) as u8)
            .collect();
        let packed = encrypt_envelope(&inner, 6, b"secret", FAST.0, FAST.1, FAST.2, None).unwrap();
        assert_eq!(decrypt_envelope(&packed, b"secret").unwrap(), inner);
    }

    #[test]
    fn envelope_wrong_password_fails() {
        let packed = encrypt_envelope(b"data", 6, b"secret", FAST.0, FAST.1, FAST.2, None).unwrap();
        assert!(matches!(
            decrypt_envelope(&packed, b"wrong"),
            Err(Error::AuthFailed)
        ));
    }

    #[test]
    fn envelope_tamper_fails() {
        let mut packed =
            encrypt_envelope(b"data", 6, b"secret", FAST.0, FAST.1, FAST.2, None).unwrap();
        let n = packed.len();
        packed[n - 3] ^= 0x01;
        assert!(matches!(
            decrypt_envelope(&packed, b"secret"),
            Err(Error::AuthFailed)
        ));
    }

    #[test]
    fn envelope_tampered_kcv_fails() {
        // 篡改 KCV 应被快速拒绝（不依赖分块 AEAD 认证）。
        let mut packed =
            encrypt_envelope(b"data", 6, b"secret", FAST.0, FAST.1, FAST.2, None).unwrap();
        packed[20] ^= 0x01;
        assert!(matches!(
            decrypt_envelope(&packed, b"secret"),
            Err(Error::AuthFailed)
        ));
    }

    #[test]
    fn envelope_rejects_bad_params() {
        assert!(encrypt_envelope(b"data", 6, b"secret", 0, 3, 4, None).is_err());
        assert!(encrypt_envelope(b"data", 6, b"secret", 32, 0, 4, None).is_err());
        assert!(encrypt_envelope(b"data", 6, b"secret", 32, 3, 0, None).is_err());
        assert!(
            encrypt_envelope(b"data", 6, b"secret", ARGON2_MAX_MEMORY_KIB + 1, 3, 4, None).is_err()
        );
    }
}
