//! IETF ChaCha20-Poly1305 AEAD（RFC 8439 §2.8）。
//!
//! 一次性密钥取自 ChaCha20 counter=0 块的前 32 字节；加密从 counter=1 开始。
//! Poly1305 认证覆盖 `AAD || pad16(aad) || 密文 || pad16(密文) || aad_len || ct_len`
//! （长度字段为小端 64 位）。

use super::chacha20::{apply_keystream, keystream_block};
use super::poly1305::Poly1305;

/// 认证标签长度（字节）。
pub const TAG_LEN: usize = 16;

/// 加密，返回 `(密文, 标签)`。
pub fn encrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> (Vec<u8>, [u8; TAG_LEN]) {
    let mut poly_key = [0u8; 32];
    poly_key.copy_from_slice(&keystream_block(key, nonce, 0)[..32]);

    let mut ciphertext = plaintext.to_vec();
    apply_keystream(key, nonce, 1, &mut ciphertext);

    let tag = mac(&poly_key, aad, &ciphertext);
    (ciphertext, tag)
}

/// 解密并认证，认证失败返回 `Err(())`。
pub fn decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; TAG_LEN],
) -> Result<Vec<u8>, ()> {
    let mut poly_key = [0u8; 32];
    poly_key.copy_from_slice(&keystream_block(key, nonce, 0)[..32]);

    let computed = mac(&poly_key, aad, ciphertext);
    if !ct_eq(&computed, tag) {
        return Err(());
    }

    let mut plaintext = ciphertext.to_vec();
    apply_keystream(key, nonce, 1, &mut plaintext);
    Ok(plaintext)
}

/// 计算 Poly1305 标签。
fn mac(key: &[u8; 32], aad: &[u8], ciphertext: &[u8]) -> [u8; TAG_LEN] {
    const ZEROS: [u8; 16] = [0u8; 16];
    let mut p = Poly1305::new(key);
    p.update(aad);
    p.update(&ZEROS[..pad_len(aad.len())]);
    p.update(ciphertext);
    p.update(&ZEROS[..pad_len(ciphertext.len())]);
    p.update(&(aad.len() as u64).to_le_bytes());
    p.update(&(ciphertext.len() as u64).to_le_bytes());
    p.finalize()
}

/// 需要填充到 16 字节对齐的零字节数。
fn pad_len(len: usize) -> usize {
    (16 - len % 16) % 16
}

/// 常量时间比较。
fn ct_eq(a: &[u8; TAG_LEN], b: &[u8; TAG_LEN]) -> bool {
    let mut diff = 0u8;
    for i in 0..TAG_LEN {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::super::sha256::hex;
    use super::*;

    #[test]
    fn rfc8439_section2_8_2() {
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let aad: &[u8] = &[
            0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
        ];
        let key: [u8; 32] = [
            0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d,
            0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b,
            0x9c, 0x9d, 0x9e, 0x9f,
        ];
        let nonce: [u8; 12] = [
            0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        ];

        let (ciphertext, tag) = encrypt(&key, &nonce, aad, plaintext);

        let expected_ct = "\
d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6\
3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36\
92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc\
3ff4def08e4b7a9de576d26586cec64b6116";
        assert_eq!(hex(&ciphertext), expected_ct);
        assert_eq!(hex(&tag), "1ae10b594f09e26a7e902ecbd0600691");

        // 解密往返。
        let dec = decrypt(&key, &nonce, aad, &ciphertext, &tag).unwrap();
        assert_eq!(dec, plaintext);
    }

    #[test]
    fn tamper_detected() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];
        let aad = b"header";
        let pt = b"the quick brown fox";
        let (mut ct, tag) = encrypt(&key, &nonce, aad, pt);

        ct[0] ^= 0x01;
        assert!(decrypt(&key, &nonce, aad, &ct, &tag).is_err());
    }

    #[test]
    fn empty_roundtrip() {
        let key = [0x11u8; 32];
        let nonce = [0x22u8; 12];
        let (ct, tag) = encrypt(&key, &nonce, b"", b"");
        assert!(ct.is_empty());
        assert_eq!(decrypt(&key, &nonce, b"", &ct, &tag).unwrap(), b"");
    }
}
