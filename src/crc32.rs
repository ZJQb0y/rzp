//! CRC-32（IEEE 802.3，多项式 0xEDB88320）完整性校验。
//!
//! 这是从多项式定义出发、自己实现的表驱动 CRC-32，与 gzip/zlib 使用的
//! 标准 CRC-32 完全一致，便于跨实现校验。

/// 反射多项式 `0xEDB88320`（即 `0x04C11DB7` 的位反转形式）。
const POLY: u32 = 0xEDB8_8320;

/// 惰性构建 256 项查找表。
fn table() -> &'static [u32; 256] {
    use std::sync::OnceLock;
    static TABLE: OnceLock<[u32; 256]> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut t = [0u32; 256];
        for (i, slot) in t.iter_mut().enumerate() {
            let mut c = i as u32;
            for _ in 0..8 {
                c = if c & 1 != 0 { (c >> 1) ^ POLY } else { c >> 1 };
            }
            *slot = c;
        }
        t
    })
}

/// 惰性构建 slicing-by-8 的 8 张 256 项查找表。
fn slicing_tables() -> &'static [[u32; 256]; 8] {
    use std::sync::OnceLock;
    static TABLES: OnceLock<[[u32; 256]; 8]> = OnceLock::new();
    TABLES.get_or_init(|| {
        let base = *table();
        let mut t = [[0u32; 256]; 8];
        t[0] = base;
        for k in 1..8 {
            let (lower, upper) = t.split_at_mut(k);
            let prev_row = &lower[k - 1];
            for (b, slot) in upper[0].iter_mut().enumerate() {
                let prev = prev_row[b];
                *slot = base[(prev & 0xff) as usize] ^ (prev >> 8);
            }
        }
        t
    })
}

/// 增量更新 CRC-32 状态。
///
/// 数据足够大且 CPU 支持 PCLMULQDQ 时走硬件折叠路径，否则回退到 slicing-by-8。
#[inline]
pub fn update(crc: u32, data: &[u8]) -> u32 {
    #[cfg(target_arch = "x86_64")]
    {
        if data.len() >= 64 && std::arch::is_x86_feature_detected!("pclmulqdq") {
            // SAFETY: 已通过 `is_x86_feature_detected!` 确认 CPU 支持 pclmulqdq
            //（Westmere 及以后，必然也支持 ssse3/sse4.1），满足 `crc32_fold` 的
            // target_feature 前置条件。
            return unsafe { simd::crc32_fold(crc, data) };
        }
    }
    update_scalar(crc, data)
}

/// slicing-by-8 标量实现，一次处理 8 字节。
#[inline]
fn update_scalar(crc: u32, data: &[u8]) -> u32 {
    let t = slicing_tables();
    let mut c = crc;

    let (chunks, remainder) = data.as_chunks::<8>();
    for chunk in chunks {
        let b0 = chunk[0] as u32;
        let b1 = chunk[1] as u32;
        let b2 = chunk[2] as u32;
        let b3 = chunk[3] as u32;
        c = t[7][((c ^ b0) & 0xff) as usize]
            ^ t[6][(((c >> 8) ^ b1) & 0xff) as usize]
            ^ t[5][(((c >> 16) ^ b2) & 0xff) as usize]
            ^ t[4][(((c >> 24) ^ b3) & 0xff) as usize]
            ^ t[3][chunk[4] as usize]
            ^ t[2][chunk[5] as usize]
            ^ t[1][chunk[6] as usize]
            ^ t[0][chunk[7] as usize];
    }
    for &b in remainder {
        c = (c >> 8) ^ t[0][((c ^ b as u32) & 0xff) as usize];
    }
    c
}

/// 计算一整块数据的 CRC-32。
pub fn crc32(data: &[u8]) -> u32 {
    update(!0u32, data) ^ !0u32
}

/// CRC-32 累加器，用于流式场景。
#[derive(Clone, Debug, Default)]
pub struct Crc32 {
    state: u32,
}

impl Crc32 {
    /// 新建累加器（初值 `0xFFFFFFFF`）。
    pub fn new() -> Self {
        Crc32 { state: !0u32 }
    }

    /// 喂入一段数据。
    pub fn update(&mut self, data: &[u8]) {
        self.state = update(self.state, data);
    }

    /// 输出最终校验值。
    pub fn finalize(&self) -> u32 {
        self.state ^ !0u32
    }
}

/// PCLMULQDQ 硬件折叠的 CRC-32 实现（仅 x86_64）。
///
/// 算法源自 Intel《Fast CRC Computation for Generic Polynomials Using
/// PCLMULQDQ》的位反射（gzip）变体：用 4 个 128 位寄存器并行折叠，
/// 最后用 Barrett 归约得到 32 位余数。
#[cfg(target_arch = "x86_64")]
mod simd {
    use std::arch::x86_64::*;

    const CRC32_INITIAL: u32 = !0u32;

    /// 折叠常数 `x^{128+64} mod P` 与 `x^{128} mod P`（位反射形式）。
    const FOLD4: [u32; 4] = [0xc6e4_1596, 0x0000_0001, 0x5444_2bd4, 0x0000_0001];

    /// 初始折叠状态，对应 crc 初值 `0xFFFFFFFF`。
    const INIT_CRC0: [u32; 4] = [0x9db4_2487, 0, 0, 0];

    /// Barrett 归约常数与掩码。
    const CRC_MASK1: [u32; 4] = [0xFFFF_FFFF, 0xFFFF_FFFF, 0, 0];
    const CRC_MASK2: [u32; 4] = [0, 0xFFFF_FFFF, 0xFFFF_FFFF, 0xFFFF_FFFF];
    const RK1_RK2: [u32; 4] = [0xccaa_009e, 0, 0x7519_97d0, 0x0000_0001];
    const RK5_RK6: [u32; 4] = [0xccaa_009e, 0, 0x63cd_6124, 0x0000_0001];
    const RK7_RK8: [u32; 4] = [0xf701_1640, 0x0000_0001, 0xdb71_0640, 0x0000_0001];

    /// 尾部 partial fold 的 `pshufb` 移位掩码（15 种，对应 1..=15 字节）。
    const PSHUFB_SHF: [[u32; 4]; 15] = [
        [0x8483_8281, 0x8887_8685, 0x8c8b_8a89, 0x008f_8e8d],
        [0x8584_8382, 0x8988_8786, 0x8d8c_8b8a, 0x0100_8f8e],
        [0x8685_8483, 0x8a89_8887, 0x8e8d_8c8b, 0x0201_008f],
        [0x8786_8584, 0x8b8a_8988, 0x8f8e_8d8c, 0x0302_0100],
        [0x8887_8685, 0x8c8b_8a89, 0x008f_8e8d, 0x0403_0201],
        [0x8988_8786, 0x8d8c_8b8a, 0x0100_8f8e, 0x0504_0302],
        [0x8a89_8887, 0x8e8d_8c8b, 0x0201_008f, 0x0605_0403],
        [0x8b8a_8988, 0x8f8e_8d8c, 0x0302_0100, 0x0706_0504],
        [0x8c8b_8a89, 0x008f_8e8d, 0x0403_0201, 0x0807_0605],
        [0x8d8c_8b8a, 0x0100_8f8e, 0x0504_0302, 0x0908_0706],
        [0x8e8d_8c8b, 0x0201_008f, 0x0605_0403, 0x0a09_0807],
        [0x8f8e_8d8c, 0x0302_0100, 0x0706_0504, 0x0b0a_0908],
        [0x008f_8e8d, 0x0403_0201, 0x0807_0605, 0x0c0b_0a09],
        [0x0100_8f8e, 0x0504_0302, 0x0908_0706, 0x0d0c_0b0a],
        [0x0201_008f, 0x0605_0403, 0x0a09_0807, 0x0e0d_0c0b],
    ];

    #[target_feature(
        enable = "pclmulqdq",
        enable = "sse2",
        enable = "ssse3",
        enable = "sse4.1"
    )]
    #[inline]
    fn setr(v: [u32; 4]) -> __m128i {
        _mm_setr_epi32(v[0] as i32, v[1] as i32, v[2] as i32, v[3] as i32)
    }

    #[target_feature(
        enable = "pclmulqdq",
        enable = "sse2",
        enable = "ssse3",
        enable = "sse4.1"
    )]
    #[inline]
    fn zero() -> __m128i {
        _mm_setzero_si128()
    }

    /// 对单个 128 位块执行一次折叠。
    #[target_feature(
        enable = "pclmulqdq",
        enable = "sse2",
        enable = "ssse3",
        enable = "sse4.1"
    )]
    #[inline]
    fn step(input: __m128i) -> __m128i {
        let k = setr(FOLD4);
        _mm_xor_si128(
            _mm_clmulepi64_si128(input, k, 0x01),
            _mm_clmulepi64_si128(input, k, 0x10),
        )
    }

    /// 把 4 寄存器折叠状态「左移」N 位（一次进入 N 个 16 字节块）。
    #[target_feature(
        enable = "pclmulqdq",
        enable = "sse2",
        enable = "ssse3",
        enable = "sse4.1"
    )]
    #[inline]
    fn fold_step<const N: usize>(fold: &mut [__m128i; 4]) {
        let mut next = [zero(); 4];
        for i in 0..4 {
            next[i] = if i + N < 4 {
                fold[i + N]
            } else {
                step(fold[i + N - 4])
            };
        }
        *fold = next;
    }

    /// 处理不足一个完整 16 字节块的尾部数据。
    #[target_feature(
        enable = "pclmulqdq",
        enable = "sse2",
        enable = "ssse3",
        enable = "sse4.1"
    )]
    #[inline]
    fn partial_fold(fold: &mut [__m128i; 4], part: __m128i, len: usize) {
        let xmm_shl = setr(PSHUFB_SHF[len - 1]);
        let xmm_shr = _mm_xor_si128(xmm_shl, setr([0x8080_8080; 4]));

        let xmm_a0 = step(_mm_shuffle_epi8(fold[0], xmm_shl));

        fold[0] = _mm_shuffle_epi8(fold[0], xmm_shr);
        let t1 = _mm_shuffle_epi8(fold[1], xmm_shl);
        fold[0] = _mm_or_si128(fold[0], t1);

        fold[1] = _mm_shuffle_epi8(fold[1], xmm_shr);
        let t2 = _mm_shuffle_epi8(fold[2], xmm_shl);
        fold[1] = _mm_or_si128(fold[1], t2);

        fold[2] = _mm_shuffle_epi8(fold[2], xmm_shr);
        let t3 = _mm_shuffle_epi8(fold[3], xmm_shl);
        fold[2] = _mm_or_si128(fold[2], t3);

        fold[3] = _mm_shuffle_epi8(fold[3], xmm_shr);
        let crc_part = _mm_shuffle_epi8(part, xmm_shl);
        fold[3] = _mm_or_si128(fold[3], crc_part);

        fold[3] = _mm_xor_si128(fold[3], xmm_a0);
    }

    /// 折叠 N 个 16 字节块（N ∈ 1..=4）。
    #[target_feature(
        enable = "pclmulqdq",
        enable = "sse2",
        enable = "ssse3",
        enable = "sse4.1"
    )]
    #[inline]
    fn progress<const N: usize>(fold: &mut [__m128i; 4], src: &mut &[u8], init_crc: &mut u32) {
        let mut input = [zero(); N];
        let (chunks, _) = src.as_chunks::<16>();
        for (i, chunk) in chunks.iter().take(N).enumerate() {
            input[i] = unsafe { _mm_loadu_si128(chunk.as_ptr() as *const __m128i) };
        }
        *src = &src[N * 16..];

        if *init_crc != CRC32_INITIAL {
            input[0] = _mm_xor_si128(input[0], setr([*init_crc ^ CRC32_INITIAL, 0, 0, 0]));
            *init_crc = CRC32_INITIAL;
        }

        fold_step::<N>(fold);
        for i in 0..N {
            fold[i + (4 - N)] = _mm_xor_si128(fold[i + (4 - N)], input[i]);
        }
    }

    /// Barrett 归约，返回增量 CRC 状态（未做最终取反）。
    #[target_feature(
        enable = "pclmulqdq",
        enable = "sse2",
        enable = "ssse3",
        enable = "sse4.1"
    )]
    #[inline]
    fn finish(fold: &mut [__m128i; 4]) -> u32 {
        let [mut x0, mut x1, mut x2, mut x3] = *fold;

        // k1
        let mut crc_fold = setr(RK1_RK2);
        let t0 = _mm_clmulepi64_si128(x0, crc_fold, 0x10);
        x0 = _mm_clmulepi64_si128(x0, crc_fold, 0x01);
        x1 = _mm_xor_si128(x1, t0);
        x1 = _mm_xor_si128(x1, x0);

        let t1 = _mm_clmulepi64_si128(x1, crc_fold, 0x10);
        x1 = _mm_clmulepi64_si128(x1, crc_fold, 0x01);
        x2 = _mm_xor_si128(x2, t1);
        x2 = _mm_xor_si128(x2, x1);

        let t2 = _mm_clmulepi64_si128(x2, crc_fold, 0x10);
        x2 = _mm_clmulepi64_si128(x2, crc_fold, 0x01);
        x3 = _mm_xor_si128(x3, t2);
        x3 = _mm_xor_si128(x3, x2);

        // k5
        crc_fold = setr(RK5_RK6);
        x0 = x3;
        x3 = _mm_clmulepi64_si128(x3, crc_fold, 0);
        x0 = _mm_srli_si128(x0, 8);
        x3 = _mm_xor_si128(x3, x0);

        x0 = x3;
        x3 = _mm_slli_si128(x3, 4);
        x3 = _mm_clmulepi64_si128(x3, crc_fold, 0x10);
        x3 = _mm_xor_si128(x3, x0);
        x3 = _mm_and_si128(x3, setr(CRC_MASK2));

        // k7
        x1 = x3;
        x2 = x3;
        crc_fold = setr(RK7_RK8);

        x3 = _mm_clmulepi64_si128(x3, crc_fold, 0);
        x3 = _mm_xor_si128(x3, x2);
        x3 = _mm_and_si128(x3, setr(CRC_MASK1));

        x2 = x3;
        x3 = _mm_clmulepi64_si128(x3, crc_fold, 0x10);
        x3 = _mm_xor_si128(x3, x2);
        x3 = _mm_xor_si128(x3, x1);

        _mm_extract_epi32(x3, 2) as u32
    }

    /// PCLMULQDQ 增量 CRC-32：返回把 `data` 喂入当前 `crc` 后的新状态。
    ///
    /// # Safety
    ///
    /// 调用方需保证 CPU 支持 `pclmulqdq`/`ssse3`/`sse4.1`，且 `data.len() >= 64`。
    #[target_feature(
        enable = "pclmulqdq",
        enable = "sse2",
        enable = "ssse3",
        enable = "sse4.1"
    )]
    pub(super) fn crc32_fold(mut crc: u32, mut src: &[u8]) -> u32 {
        let mut fold: [__m128i; 4] = [setr(INIT_CRC0), zero(), zero(), zero()];
        let mut part: __m128i;

        // 前导未对齐到 16 字节的部分。
        let (before, _, _) = unsafe { src.align_to::<__m128i>() };
        if !before.is_empty() {
            unsafe {
                part = _mm_loadu_si128(src.as_ptr() as *const __m128i);
                let is_initial = crc == CRC32_INITIAL;
                if !is_initial {
                    part = _mm_xor_si128(part, setr([crc ^ CRC32_INITIAL, 0, 0, 0]));
                    crc = CRC32_INITIAL;
                }
                if before.len() < 4 && !is_initial {
                    let t0 = part;
                    part = _mm_loadu_si128(src.as_ptr().add(16) as *const __m128i);
                    fold_step::<1>(&mut fold);
                    fold[3] = _mm_xor_si128(fold[3], t0);
                    src = &src[16..];
                }
            }
            partial_fold(&mut fold, part, before.len());
            src = &src[before.len()..];
        }

        // 主循环：每次折叠 4 个 16 字节块。
        while src.len() >= 64 {
            progress::<4>(&mut fold, &mut src, &mut crc);
        }
        if src.len() >= 48 {
            progress::<3>(&mut fold, &mut src, &mut crc);
        } else if src.len() >= 32 {
            progress::<2>(&mut fold, &mut src, &mut crc);
        } else if src.len() >= 16 {
            progress::<1>(&mut fold, &mut src, &mut crc);
        }

        // 剩余不足 16 字节。
        if !src.is_empty() {
            part = zero();
            unsafe {
                std::ptr::copy_nonoverlapping(
                    src.as_ptr(),
                    &mut part as *mut _ as *mut u8,
                    src.len(),
                );
            }
            partial_fold(&mut fold, part, src.len());
        }

        finish(&mut fold)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vectors() {
        // 标准 CRC-32 测试向量（与 gzip/zlib 一致）。
        assert_eq!(crc32(b""), 0x0000_0000);
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b"a"), 0xE8B7_BE43);
        assert_eq!(crc32(b"hello world"), 0x0D4A_1185);
    }

    #[test]
    fn incremental_matches_oneshot() {
        let data = b"The quick brown fox jumps over the lazy dog 0123456789";
        let mut acc = Crc32::new();
        // 分多段喂入。
        for chunk in data.chunks(3) {
            acc.update(chunk);
        }
        assert_eq!(acc.finalize(), crc32(data));
    }

    #[test]
    fn slicing_matches_bytewise() {
        // 以逐字节 reference 校验 slicing-by-8 主循环与余数处理。
        fn update_ref(crc: u32, data: &[u8]) -> u32 {
            let t = table();
            let mut c = crc;
            for &b in data {
                c = (c >> 8) ^ t[((c ^ b as u32) & 0xff) as usize];
            }
            c
        }

        let mut seed = 0x1234_5678u32;
        for len in [0usize, 1, 7, 8, 9, 15, 16, 31, 100, 1000] {
            let mut data = vec![0u8; len];
            for b in data.iter_mut() {
                seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                *b = (seed >> 24) as u8;
            }
            for start in [0x0000_0000u32, 0xFFFF_FFFFu32, 0xDEAD_BEEFu32] {
                assert_eq!(
                    update(start, &data),
                    update_ref(start, &data),
                    "len={len} start={start:#x}"
                );
            }
        }
    }

    #[test]
    fn matches_bytewise_unaligned() {
        // 覆盖前导未对齐到 16 字节的 SIMD 折叠路径。
        fn update_ref(crc: u32, data: &[u8]) -> u32 {
            let t = table();
            let mut c = crc;
            for &b in data {
                c = (c >> 8) ^ t[((c ^ b as u32) & 0xff) as usize];
            }
            c
        }

        let mut seed = 0x9e37_79b9u32;
        let mut buf = vec![0u8; 4096 + 16];
        for b in buf.iter_mut() {
            seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            *b = (seed >> 24) as u8;
        }
        for offset in 0..16 {
            for len in [64usize, 65, 80, 127, 128, 1000] {
                let data = &buf[offset..offset + len];
                for start in [0x0000_0000u32, 0xFFFF_FFFFu32, 0xDEAD_BEEFu32] {
                    assert_eq!(
                        update(start, data),
                        update_ref(start, data),
                        "offset={offset} len={len} start={start:#x}"
                    );
                }
            }
        }
    }
}
