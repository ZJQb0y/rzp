//! Poly1305（RFC 8439 §2.5）：一次性认证器，输出 16 字节标签。
//!
//! 采用 RFC 8439 附录中的 26 位分片参考实现（`poly1305-donna`），
//! 乘加与进位均用 `u64` 完成，避免中间结果溢出。

const TAG_LEN: usize = 16;
const BLOCK_SIZE: usize = 16;

/// Poly1305 一次性认证器状态。
pub struct Poly1305 {
    r: [u32; 5],
    h: [u32; 5],
    pad: [u32; 4],
    buf: [u8; BLOCK_SIZE],
    buf_len: usize,
}

impl Poly1305 {
    /// 由 32 字节一次性密钥构造（前 16 字节为 r，后 16 字节为 s）。
    pub fn new(key: &[u8; 32]) -> Self {
        // r 低 16 字节，按 RFC 8439 §2.5 夹位后拆成 5 个 26 位分片。
        let mut r = [0u32; 5];
        r[0] = u32::from_le_bytes([key[0], key[1], key[2], key[3]]) & 0x3ffffff;
        r[1] = (u32::from_le_bytes([key[3], key[4], key[5], key[6]]) >> 2) & 0x3ffff03;
        r[2] = (u32::from_le_bytes([key[6], key[7], key[8], key[9]]) >> 4) & 0x3ffc0ff;
        r[3] = (u32::from_le_bytes([key[9], key[10], key[11], key[12]]) >> 6) & 0x3f03fff;
        r[4] = (u32::from_le_bytes([key[12], key[13], key[14], key[15]]) >> 8) & 0x00fffff;

        let mut pad = [0u32; 4];
        for i in 0..4 {
            pad[i] = u32::from_le_bytes([
                key[16 + i * 4],
                key[16 + i * 4 + 1],
                key[16 + i * 4 + 2],
                key[16 + i * 4 + 3],
            ]);
        }

        Poly1305 {
            r,
            h: [0u32; 5],
            pad,
            buf: [0u8; BLOCK_SIZE],
            buf_len: 0,
        }
    }

    /// 追加待认证数据（内部缓存至 16 字节块再处理）。
    pub fn update(&mut self, data: &[u8]) {
        let mut i = 0;

        // 先补齐已有的部分块。
        if self.buf_len > 0 {
            let need = BLOCK_SIZE - self.buf_len;
            let take = need.min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            i = take;
            if self.buf_len == BLOCK_SIZE {
                let block = self.buf;
                self.process_block(&block, true);
                self.buf_len = 0;
            }
        }

        // 直接处理完整块，避免把整个输入缓存进内存。
        while i + BLOCK_SIZE <= data.len() {
            let block: [u8; BLOCK_SIZE] = data[i..i + BLOCK_SIZE].try_into().unwrap();
            self.process_block(&block, true);
            i += BLOCK_SIZE;
        }

        // 缓存剩余不足一块的数据。
        if i < data.len() {
            let remain = data.len() - i;
            self.buf[..remain].copy_from_slice(&data[i..]);
            self.buf_len = remain;
        }
    }

    /// 处理一个 16 字节块；`hibit` 为 true 时设置第 129 位（2^128）。
    fn process_block(&mut self, block: &[u8; BLOCK_SIZE], hibit: bool) {
        let t0 = u32::from_le_bytes([block[0], block[1], block[2], block[3]]);
        let t1 = u32::from_le_bytes([block[4], block[5], block[6], block[7]]);
        let t2 = u32::from_le_bytes([block[8], block[9], block[10], block[11]]);
        let t3 = u32::from_le_bytes([block[12], block[13], block[14], block[15]]);

        let r = self.r;
        let s1 = r[1].wrapping_mul(5);
        let s2 = r[2].wrapping_mul(5);
        let s3 = r[3].wrapping_mul(5);
        let s4 = r[4].wrapping_mul(5);

        // h += m
        self.h[0] = self.h[0].wrapping_add(t0 & 0x03ff_ffff);
        self.h[1] =
            self.h[1].wrapping_add(((((t1 as u64) << 32) | t0 as u64) >> 26) as u32 & 0x03ff_ffff);
        self.h[2] =
            self.h[2].wrapping_add(((((t2 as u64) << 32) | t1 as u64) >> 20) as u32 & 0x03ff_ffff);
        self.h[3] =
            self.h[3].wrapping_add(((((t3 as u64) << 32) | t2 as u64) >> 14) as u32 & 0x03ff_ffff);
        self.h[4] = self.h[4].wrapping_add((t3 >> 8) | ((hibit as u32) << 24));

        let h = self.h;
        // h *= r
        let d0 = (h[0] as u64) * (r[0] as u64)
            + (h[1] as u64) * (s4 as u64)
            + (h[2] as u64) * (s3 as u64)
            + (h[3] as u64) * (s2 as u64)
            + (h[4] as u64) * (s1 as u64);
        let d1 = (h[0] as u64) * (r[1] as u64)
            + (h[1] as u64) * (r[0] as u64)
            + (h[2] as u64) * (s4 as u64)
            + (h[3] as u64) * (s3 as u64)
            + (h[4] as u64) * (s2 as u64);
        let d2 = (h[0] as u64) * (r[2] as u64)
            + (h[1] as u64) * (r[1] as u64)
            + (h[2] as u64) * (r[0] as u64)
            + (h[3] as u64) * (s4 as u64)
            + (h[4] as u64) * (s3 as u64);
        let d3 = (h[0] as u64) * (r[3] as u64)
            + (h[1] as u64) * (r[2] as u64)
            + (h[2] as u64) * (r[1] as u64)
            + (h[3] as u64) * (r[0] as u64)
            + (h[4] as u64) * (s4 as u64);
        let d4 = (h[0] as u64) * (r[4] as u64)
            + (h[1] as u64) * (r[3] as u64)
            + (h[2] as u64) * (r[2] as u64)
            + (h[3] as u64) * (r[1] as u64)
            + (h[4] as u64) * (r[0] as u64);

        // (partial) h %= p
        let mut c = (d0 >> 26) as u32;
        self.h[0] = (d0 & 0x03ff_ffff) as u32;
        let d1 = d1 + c as u64;
        c = (d1 >> 26) as u32;
        self.h[1] = (d1 & 0x03ff_ffff) as u32;
        let d2 = d2 + c as u64;
        c = (d2 >> 26) as u32;
        self.h[2] = (d2 & 0x03ff_ffff) as u32;
        let d3 = d3 + c as u64;
        c = (d3 >> 26) as u32;
        self.h[3] = (d3 & 0x03ff_ffff) as u32;
        let d4 = d4 + c as u64;
        c = (d4 >> 26) as u32;
        self.h[4] = (d4 & 0x03ff_ffff) as u32;
        let h0 = self.h[0].wrapping_add(c.wrapping_mul(5));
        c = h0 >> 26;
        self.h[0] = h0 & 0x03ff_ffff;
        self.h[1] = self.h[1].wrapping_add(c);
    }

    /// 结束并输出 16 字节标签。
    pub fn finalize(mut self) -> [u8; TAG_LEN] {
        // 处理剩余不足 16 字节的块：追加 0x01 后补零，hibit 为 false。
        if self.buf_len > 0 {
            let mut block = [0u8; BLOCK_SIZE];
            block[..self.buf_len].copy_from_slice(&self.buf[..self.buf_len]);
            block[self.buf_len] = 0x01;
            self.process_block(&block, false);
        }

        let mut h = self.h;

        // 完全进位。
        let mut c = h[1] >> 26;
        h[1] &= 0x03ff_ffff;
        h[2] = h[2].wrapping_add(c);
        c = h[2] >> 26;
        h[2] &= 0x03ff_ffff;
        h[3] = h[3].wrapping_add(c);
        c = h[3] >> 26;
        h[3] &= 0x03ff_ffff;
        h[4] = h[4].wrapping_add(c);
        c = h[4] >> 26;
        h[4] &= 0x03ff_ffff;
        let h0 = h[0].wrapping_add(c.wrapping_mul(5));
        c = h0 >> 26;
        h[0] = h0 & 0x03ff_ffff;
        h[1] = h[1].wrapping_add(c);

        // 计算 h + (-p)（即 h - p），用于 h >= p 时做模 p 归约。
        let mut g0 = h[0].wrapping_add(5);
        c = g0 >> 26;
        g0 &= 0x03ff_ffff;
        let mut g1 = h[1].wrapping_add(c);
        c = g1 >> 26;
        g1 &= 0x03ff_ffff;
        let mut g2 = h[2].wrapping_add(c);
        c = g2 >> 26;
        g2 &= 0x03ff_ffff;
        let mut g3 = h[3].wrapping_add(c);
        c = g3 >> 26;
        g3 &= 0x03ff_ffff;
        let g4 = h[4].wrapping_add(c).wrapping_sub(1 << 26);

        // 若 h < p（g4 借位为负）选 h，否则选 g。
        let mask = (g4 >> 31).wrapping_sub(1);
        let g0 = g0 & mask;
        let g1 = g1 & mask;
        let g2 = g2 & mask;
        let g3 = g3 & mask;
        let g4 = g4 & mask;
        let nmask = !mask;
        h[0] = (h[0] & nmask) | g0;
        h[1] = (h[1] & nmask) | g1;
        h[2] = (h[2] & nmask) | g2;
        h[3] = (h[3] & nmask) | g3;
        h[4] = (h[4] & nmask) | g4;

        // h = h mod 2^128（重组为 4 个 32 位小端字）。
        let h0 = (h[0] as u64) | ((h[1] as u64) << 26);
        let h1 = ((h[1] as u64) >> 6) | ((h[2] as u64) << 20);
        let h2 = ((h[2] as u64) >> 12) | ((h[3] as u64) << 14);
        let h3 = ((h[3] as u64) >> 18) | ((h[4] as u64) << 8);
        let hw = [h0 as u32, h1 as u32, h2 as u32, h3 as u32];

        // mac = (h + pad) mod 2^128，小端输出。
        let mut out = [0u8; 16];
        let mut carry = 0u64;
        for i in 0..4 {
            let sum = hw[i] as u64 + self.pad[i] as u64 + carry;
            let v = (sum & 0xffff_ffff) as u32;
            out[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
            carry = sum >> 32;
        }
        out
    }
}

/// 一次性计算 Poly1305 标签。
#[cfg(test)]
pub fn poly1305(key: &[u8; 32], data: &[u8]) -> [u8; 16] {
    let mut p = Poly1305::new(key);
    p.update(data);
    p.finalize()
}

#[cfg(test)]
mod tests {
    use super::super::sha256::hex;
    use super::*;

    #[test]
    fn rfc8439_section2_6() {
        let key: [u8; 32] = [
            0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5,
            0x06, 0xa8, 0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd, 0x4a, 0xbf, 0xf6, 0xaf,
            0x41, 0x49, 0xf5, 0x1b,
        ];
        let tag = poly1305(&key, b"Cryptographic Forum Research Group");
        assert_eq!(hex(&tag), "a8061dc1305136c6c22b8baf0c0127a9");
    }

    #[test]
    fn zero_key_empty_message() {
        // 空消息、零密钥 → 标签为全零（自洽性）。
        let tag = poly1305(&[0u8; 32], b"");
        assert_eq!(tag, [0u8; 16]);
    }

    #[test]
    fn incremental_equals_oneshot() {
        let key: [u8; 32] = [
            0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5,
            0x06, 0xa8, 0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd, 0x4a, 0xbf, 0xf6, 0xaf,
            0x41, 0x49, 0xf5, 0x1b,
        ];
        let data = b"Cryptographic Forum Research Group";
        let mut p = Poly1305::new(&key);
        for chunk in data.chunks(3) {
            p.update(chunk);
        }
        assert_eq!(p.finalize(), poly1305(&key, data));
    }
}
