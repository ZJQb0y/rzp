//! ChaCha20（RFC 8439 §2.3）：256 位密钥 / 96 位 nonce / 32 位计数器。

/// 常量 "expand 32-byte k"（小端字序）。
const CONSTANTS: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

/// ChaCha20 状态（16 个 32 位字）。
#[derive(Clone, Copy)]
pub struct State(pub [u32; 16]);

impl State {
    /// 由 32 字节密钥、12 字节 nonce 与 32 位计数器构造初始状态。
    pub fn new(key: &[u8; 32], nonce: &[u8; 12], counter: u32) -> Self {
        let mut s = [0u32; 16];
        s[0..4].copy_from_slice(&CONSTANTS);
        for i in 0..8 {
            s[4 + i] =
                u32::from_le_bytes([key[i * 4], key[i * 4 + 1], key[i * 4 + 2], key[i * 4 + 3]]);
        }
        s[12] = counter;
        for i in 0..3 {
            s[13 + i] = u32::from_le_bytes([
                nonce[i * 4],
                nonce[i * 4 + 1],
                nonce[i * 4 + 2],
                nonce[i * 4 + 3],
            ]);
        }
        State(s)
    }

    /// 执行 20 轮 quarter round（10 次双轮）。
    pub fn rounds(mut self) -> Self {
        for _ in 0..10 {
            // 列轮。
            quarter_round(&mut self.0, 0, 4, 8, 12);
            quarter_round(&mut self.0, 1, 5, 9, 13);
            quarter_round(&mut self.0, 2, 6, 10, 14);
            quarter_round(&mut self.0, 3, 7, 11, 15);
            // 对角轮。
            quarter_round(&mut self.0, 0, 5, 10, 15);
            quarter_round(&mut self.0, 1, 6, 11, 12);
            quarter_round(&mut self.0, 2, 7, 8, 13);
            quarter_round(&mut self.0, 3, 4, 9, 14);
        }
        self
    }

    /// 输出密钥流块：`state + rounds(state)`（小端序列化）。
    pub fn keystream(&self) -> [u8; 64] {
        let worked = self.rounds();
        let mut out = [0u8; 64];
        for i in 0..16 {
            let v = self.0[i].wrapping_add(worked.0[i]);
            out[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
        }
        out
    }
}

/// ChaCha20 quarter round。
#[inline]
fn quarter_round(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(7);
}

/// 生成第 `counter` 个密钥流块（64 字节）。
pub fn keystream_block(key: &[u8; 32], nonce: &[u8; 12], counter: u32) -> [u8; 64] {
    State::new(key, nonce, counter).keystream()
}

/// 就地加解密（ChaCha20 为对称 XOR，加解密同一函数）。
///
/// 数据足够大且 CPU 支持 AVX2 时走 8 块并行的 SIMD 路径，否则回退到标量。
pub fn apply_keystream(key: &[u8; 32], nonce: &[u8; 12], counter: u32, data: &mut [u8]) {
    #[cfg(target_arch = "x86_64")]
    {
        if data.len() >= 512 && std::arch::is_x86_feature_detected!("avx2") {
            // SAFETY: 已通过 `is_x86_feature_detected!` 确认 CPU 支持 AVX2，
            // 满足 `simd::apply_avx2` 的 target_feature 前置条件。
            let (counter, rest) = unsafe { simd::apply_avx2(key, nonce, counter, data) };
            return apply_keystream_scalar(key, nonce, counter, rest);
        }
    }
    apply_keystream_scalar(key, nonce, counter, data)
}

/// 标量实现：逐 64 字节块生成密钥流并 XOR。
fn apply_keystream_scalar(key: &[u8; 32], nonce: &[u8; 12], counter: u32, data: &mut [u8]) {
    let mut c = counter;
    for chunk in data.chunks_mut(64) {
        let block = keystream_block(key, nonce, c);
        for (i, b) in chunk.iter_mut().enumerate() {
            *b ^= block[i];
        }
        c = c.wrapping_add(1);
    }
}

/// AVX2 并行处理 8 个 ChaCha20 块的实现（仅 x86_64）。
///
/// 每个状态字用一个 `__m256i` 的 8 条 32 位 lane 分别对应 8 个连续的计数器，
/// 因而一次双轮即可并行推进 8 个块，吞吐量约为标量路径的数倍。
#[cfg(target_arch = "x86_64")]
mod simd {
    use super::CONSTANTS;
    use std::arch::x86_64::*;

    #[inline]
    fn le32(b: &[u8]) -> u32 {
        u32::from_le_bytes([b[0], b[1], b[2], b[3]])
    }

    #[target_feature(enable = "avx2")]
    #[inline]
    fn rotl16(x: __m256i) -> __m256i {
        _mm256_or_si256(_mm256_slli_epi32(x, 16), _mm256_srli_epi32(x, 16))
    }

    #[target_feature(enable = "avx2")]
    #[inline]
    fn rotl12(x: __m256i) -> __m256i {
        _mm256_or_si256(_mm256_slli_epi32(x, 12), _mm256_srli_epi32(x, 20))
    }

    #[target_feature(enable = "avx2")]
    #[inline]
    fn rotl8(x: __m256i) -> __m256i {
        _mm256_or_si256(_mm256_slli_epi32(x, 8), _mm256_srli_epi32(x, 24))
    }

    #[target_feature(enable = "avx2")]
    #[inline]
    fn rotl7(x: __m256i) -> __m256i {
        _mm256_or_si256(_mm256_slli_epi32(x, 7), _mm256_srli_epi32(x, 25))
    }

    /// 对寄存器数组中的 4 个元素执行一次 quarter round。
    macro_rules! qr {
        ($s:ident, $a:expr, $b:expr, $c:expr, $d:expr) => {
            $s[$a] = _mm256_add_epi32($s[$a], $s[$b]);
            $s[$d] = rotl16(_mm256_xor_si256($s[$d], $s[$a]));
            $s[$c] = _mm256_add_epi32($s[$c], $s[$d]);
            $s[$b] = rotl12(_mm256_xor_si256($s[$b], $s[$c]));
            $s[$a] = _mm256_add_epi32($s[$a], $s[$b]);
            $s[$d] = rotl8(_mm256_xor_si256($s[$d], $s[$a]));
            $s[$c] = _mm256_add_epi32($s[$c], $s[$d]);
            $s[$b] = rotl7(_mm256_xor_si256($s[$b], $s[$c]));
        };
    }

    /// 一次性生成 8 个连续块的密钥流（512 字节）。
    #[target_feature(enable = "avx2")]
    fn keystream8(key: &[u8; 32], nonce: &[u8; 12], counter: u32) -> [u8; 512] {
        let k = [
            le32(&key[0..4]),
            le32(&key[4..8]),
            le32(&key[8..12]),
            le32(&key[12..16]),
            le32(&key[16..20]),
            le32(&key[20..24]),
            le32(&key[24..28]),
            le32(&key[28..32]),
        ];
        let n = [le32(&nonce[0..4]), le32(&nonce[4..8]), le32(&nonce[8..12])];

        let init = [
            _mm256_set1_epi32(CONSTANTS[0] as i32),
            _mm256_set1_epi32(CONSTANTS[1] as i32),
            _mm256_set1_epi32(CONSTANTS[2] as i32),
            _mm256_set1_epi32(CONSTANTS[3] as i32),
            _mm256_set1_epi32(k[0] as i32),
            _mm256_set1_epi32(k[1] as i32),
            _mm256_set1_epi32(k[2] as i32),
            _mm256_set1_epi32(k[3] as i32),
            _mm256_set1_epi32(k[4] as i32),
            _mm256_set1_epi32(k[5] as i32),
            _mm256_set1_epi32(k[6] as i32),
            _mm256_set1_epi32(k[7] as i32),
            _mm256_setr_epi32(
                counter as i32,
                counter.wrapping_add(1) as i32,
                counter.wrapping_add(2) as i32,
                counter.wrapping_add(3) as i32,
                counter.wrapping_add(4) as i32,
                counter.wrapping_add(5) as i32,
                counter.wrapping_add(6) as i32,
                counter.wrapping_add(7) as i32,
            ),
            _mm256_set1_epi32(n[0] as i32),
            _mm256_set1_epi32(n[1] as i32),
            _mm256_set1_epi32(n[2] as i32),
        ];

        let mut work = init;
        for _ in 0..10 {
            // 列轮。
            qr!(work, 0, 4, 8, 12);
            qr!(work, 1, 5, 9, 13);
            qr!(work, 2, 6, 10, 14);
            qr!(work, 3, 7, 11, 15);
            // 对角轮。
            qr!(work, 0, 5, 10, 15);
            qr!(work, 1, 6, 11, 12);
            qr!(work, 2, 7, 8, 13);
            qr!(work, 3, 4, 9, 14);
        }
        for j in 0..16 {
            work[j] = _mm256_add_epi32(work[j], init[j]);
        }

        // 每个寄存器保存 8 个块的同一字，需转置成 8 段连续的 64 字节密钥流。
        let mut lanes = [0u8; 512];
        for (j, w) in work.iter().enumerate() {
            unsafe {
                _mm256_storeu_si256(lanes.as_mut_ptr().add(j * 32) as *mut __m256i, *w);
            }
        }
        let mut out = [0u8; 512];
        for i in 0..8 {
            for j in 0..16 {
                let src = j * 32 + i * 4;
                out[i * 64 + j * 4..i * 64 + j * 4 + 4].copy_from_slice(&lanes[src..src + 4]);
            }
        }
        out
    }

    /// 就地 XOR，处理尽可能多的完整 512 字节块，返回剩余数据与更新后的计数器。
    #[target_feature(enable = "avx2")]
    pub(super) fn apply_avx2<'a>(
        key: &[u8; 32],
        nonce: &[u8; 12],
        mut counter: u32,
        mut data: &'a mut [u8],
    ) -> (u32, &'a mut [u8]) {
        while data.len() >= 512 {
            let block = keystream8(key, nonce, counter);
            for (d, k) in data[..512].iter_mut().zip(block) {
                *d ^= k;
            }
            counter = counter.wrapping_add(8);
            data = &mut data[512..];
        }
        (counter, data)
    }
}

#[cfg(test)]
mod tests {
    use super::super::sha256::hex;
    use super::*;

    fn key32(bytes: &[u8]) -> [u8; 32] {
        bytes.try_into().unwrap()
    }

    fn nonce12(bytes: &[u8]) -> [u8; 12] {
        bytes.try_into().unwrap()
    }

    #[test]
    fn rfc8439_keystream_block() {
        // RFC 8439 §2.4.2：单块密钥流。
        let key = key32(&(0x00u8..=0x1f).collect::<Vec<_>>());
        let nonce = nonce12(&[
            0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
        ]);
        let block = keystream_block(&key, &nonce, 1);
        let expected = "\
10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e\
d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e";
        assert_eq!(hex(&block), expected);
    }

    #[test]
    fn roundtrip() {
        let key = key32(&(0x42u8..0x42 + 32).collect::<Vec<_>>());
        let nonce = nonce12(&[7u8; 12]);
        let mut data = b"some arbitrary data to encrypt and decrypt".to_vec();
        let orig = data.clone();
        apply_keystream(&key, &nonce, 0, &mut data);
        assert_ne!(data, orig);
        apply_keystream(&key, &nonce, 0, &mut data);
        assert_eq!(data, orig);
    }

    #[test]
    fn simd_matches_scalar() {
        // 覆盖 AVX2 路径（数据足够大、非零计数器、余数不足一个 512 字节块）。
        let key = key32(&(0x10u8..0x10 + 32).collect::<Vec<_>>());
        let nonce = nonce12(&[3u8; 12]);
        let data: Vec<u8> = (0..2000usize).map(|i| (i % 256) as u8).collect();

        for counter in [0u32, 5, 0xFFFF_FFFC] {
            let mut reference = data.clone();
            let mut c = counter;
            for chunk in reference.chunks_mut(64) {
                let block = keystream_block(&key, &nonce, c);
                for (b, k) in chunk.iter_mut().zip(block) {
                    *b ^= k;
                }
                c = c.wrapping_add(1);
            }

            let mut got = data.clone();
            apply_keystream(&key, &nonce, counter, &mut got);
            assert_eq!(got, reference, "counter={counter}");
        }
    }
}
