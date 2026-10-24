//! BLAKE2b（RFC 7693）：64 位字、128 字节块、12 轮、可变输出长度（1..=64）。
//!
//! 既为 Argon2 的 H0 / H'（可变长度哈希）提供一次性服务，也为流式完整性校验
//! 提供增量 [`Blake2b`] 累加器；二者均无密钥输入。

const IV: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

/// 消息置换 SIGMA（10 行 × 16 列）。
const SIGMA: [[usize; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

/// BLAKE2b 的 G 混合函数（带消息字）。
#[inline]
fn g(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

/// 一轮 BLAKE2b 压缩（12 次 G 调用，按 SIGMA 取消息字）。
fn round(v: &mut [u64; 16], m: &[u64; 16], s: &[usize; 16]) {
    g(v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
    g(v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
    g(v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
    g(v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
    g(v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
    g(v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
    g(v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
    g(v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
}

/// 压缩一个 128 字节消息块，就地更新 8 字状态。
fn compress(h: &mut [u64; 8], block: &[u8; 128], t: u128, final_block: bool) {
    let mut m = [0u64; 16];
    for i in 0..16 {
        let mut b = [0u8; 8];
        b.copy_from_slice(&block[i * 8..i * 8 + 8]);
        m[i] = u64::from_le_bytes(b);
    }

    let mut v = [0u64; 16];
    v[..8].copy_from_slice(h);
    v[8..].copy_from_slice(&IV);
    v[12] ^= (t & 0xffff_ffff_ffff_ffff) as u64;
    v[13] ^= (t >> 64) as u64;
    if final_block {
        v[14] = !v[14];
    }

    for r in 0..12 {
        round(&mut v, &m, &SIGMA[r % 10]);
    }

    for i in 0..8 {
        h[i] ^= v[i] ^ v[i + 8];
    }
}

/// BLAKE2b 增量累加器（无密钥），用于流式场景的完整性校验。
pub struct Blake2b {
    h: [u64; 8],
    buf: [u8; 128],
    buf_len: usize,
    t: u128,
    out_len: usize,
}

impl Blake2b {
    /// 新建累加器，输出 `out_len`（1..=64）字节。
    pub fn new(out_len: usize) -> Self {
        debug_assert!(
            (1..=64).contains(&out_len),
            "blake2b out_len must be 1..=64"
        );
        let mut h = IV;
        // 参数块：h[0] ^= 0x01010000 ^ (key_len << 8) ^ out_len；key_len = 0。
        h[0] ^= 0x0101_0000 ^ (out_len as u64);
        Blake2b {
            h,
            buf: [0u8; 128],
            buf_len: 0,
            t: 0,
            out_len,
        }
    }

    /// 喂入一段数据。
    pub fn update(&mut self, mut data: &[u8]) {
        // 先补齐缓冲区中已有数据。
        if self.buf_len > 0 {
            let need = 128 - self.buf_len;
            let take = need.min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len == 128 {
                self.t = self.t.wrapping_add(128);
                compress(&mut self.h, &self.buf, self.t, false);
                self.buf_len = 0;
            }
        }
        // 完整块（保留最后一个块给 finalize 处理）。
        while data.len() > 128 {
            let mut block = [0u8; 128];
            block.copy_from_slice(&data[..128]);
            self.t = self.t.wrapping_add(128);
            compress(&mut self.h, &block, self.t, false);
            data = &data[128..];
        }
        // 尾部暂存。
        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
        }
    }

    /// 输出最终摘要（`out_len` 字节）。
    pub fn finalize(&mut self) -> Vec<u8> {
        // 最后一个块（可能是空块），补零到 128 字节。
        let mut block = [0u8; 128];
        block[..self.buf_len].copy_from_slice(&self.buf[..self.buf_len]);
        self.t = self.t.wrapping_add(self.buf_len as u128);
        compress(&mut self.h, &block, self.t, true);
        self.buf_len = 0;

        let mut out = Vec::with_capacity(self.out_len);
        for w in &self.h {
            out.extend_from_slice(&w.to_le_bytes());
        }
        out.truncate(self.out_len);
        out
    }
}

/// 一次性 BLAKE2b（无密钥），输出 `out_len`（1..=64）字节。
pub fn blake2b(data: &[u8], out_len: usize) -> Vec<u8> {
    let mut b = Blake2b::new(out_len);
    b.update(data);
    b.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::sha256::hex;

    #[test]
    fn rfc7693_vectors() {
        // RFC 7693 附录 A：BLAKE2b-512。
        assert_eq!(
            hex(&blake2b(b"abc", 64)),
            "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1\
             7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
        );
        assert_eq!(
            hex(&blake2b(b"", 64)),
            "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419\
             d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
        );
    }

    #[test]
    fn variable_output() {
        // 输出长度参与参数块，因此不同 out_len 的摘要并不互为前缀。
        // 用 RFC 7693 的 BLAKE2b-256 空串测试向量验证非 64 字节输出。
        assert_eq!(
            hex(&blake2b(b"", 32)),
            "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8"
        );
    }

    #[test]
    fn incremental_matches_oneshot() {
        let data = b"The quick brown fox jumps over the lazy dog 0123456789".repeat(1000);
        for out_len in [16usize, 32, 64] {
            let expected = blake2b(&data, out_len);
            for step in [1usize, 3, 128, 129, 1024, data.len()] {
                let mut acc = Blake2b::new(out_len);
                for chunk in data.chunks(step) {
                    acc.update(chunk);
                }
                assert_eq!(acc.finalize(), expected, "out_len={out_len} step={step}");
            }
        }
    }
}
