//! 限长规范 Huffman 编解码。
//!
//! 面向任意字母表大小（如 286 符号的字面量/长度表或 40 符号的距离表），
//! MSB-first 规范码。码长超过 [`MAX_BITS`] 时用 package-merge 求最优限长码，
//! 保证码长不超过上限。码长序列用类 DEFLATE 的 RLE（符号 16/17/18）编码，
//! 每个 RLE 符号固定 5 位。

use std::cmp::Reverse;
use std::collections::BinaryHeap;

use crate::bitio::{BitReader, BitWriter};
use crate::error::{corrupt, Result};
use crate::format::MAX_BITS;

/// 由频率计算每个符号的码长（0 表示该符号未出现）。
///
/// 使用最小堆构建 Huffman 树；若出现码长超过 [`MAX_BITS`]，则退化为定长码。
/// 对任意字母表大小（如字面量/长度表或距离表）均适用。
pub fn compute_lengths(freqs: &[u32]) -> Vec<u8> {
    // 收集出现过的符号。
    let present: Vec<usize> = freqs
        .iter()
        .enumerate()
        .filter(|(_, &f)| f > 0)
        .map(|(i, _)| i)
        .collect();

    let n = present.len();
    let mut lengths = vec![0u8; freqs.len()];

    if n == 0 {
        return lengths;
    }
    if n == 1 {
        lengths[present[0]] = 1;
        return lengths;
    }

    // 构建 Huffman 树。
    let unlimited = build_unlimited_lengths(freqs, &present);

    let max_len = *unlimited.iter().max().unwrap();
    if max_len <= MAX_BITS as u8 {
        for &sym in &present {
            lengths[sym] = unlimited[sym];
        }
        return lengths;
    }

    // 超长时用 package-merge 求最优限长码（码长仍不超过 MAX_BITS）。
    package_merge(freqs, MAX_BITS as u8)
}

/// 用 package-merge 算法计算最优限长 Huffman 码长（Larmore & Hirschberg, 1990）。
///
/// 在「码长不超过 `max_len`」的约束下最小化 `Σ freq·len`；未出现符号码长为 0。
/// 当无限制 Huffman 树的深度超过 [`MAX_BITS`] 时调用，以逼近最优熵而无需放宽码长上限。
fn package_merge(freqs: &[u32], max_len: u8) -> Vec<u8> {
    let max_len = max_len as usize;
    let mut depths = vec![0u8; freqs.len()];

    // 每个「硬币」为 (权重, 所含符号索引)，初始硬币即出现过的符号本身。
    let mut symbols: Vec<(u64, Vec<usize>)> = freqs
        .iter()
        .enumerate()
        .filter(|(_, &f)| f > 0)
        .map(|(i, &f)| (f as u64, vec![i]))
        .collect();

    let n = symbols.len();
    if n == 0 {
        return depths;
    }
    if n == 1 {
        depths[symbols[0].1[0]] = 1;
        return depths;
    }

    symbols.sort_by_key(|x| x.0);
    let mut prev = symbols.clone();

    for _ in 1..max_len {
        // 下一层 = 原始硬币 + 上一层相邻两两打包的包。
        let mut cur = symbols.clone();
        for p in 0..(prev.len() / 2) {
            let left = &prev[p * 2];
            let right = &prev[p * 2 + 1];
            let mut idx = Vec::with_capacity(left.1.len() + right.1.len());
            idx.extend_from_slice(&left.1);
            idx.extend_from_slice(&right.1);
            cur.push((left.0 + right.0, idx));
        }
        // 稳定排序：等权时原始硬币排在包之前（正确的平局约定）。
        cur.sort_by_key(|x| x.0);
        prev = cur;
    }

    // 取最终列表里最小的 2n-2 个硬币；每个符号的码长即其出现的次数。
    let take = (2 * n - 2).min(prev.len());
    for item in prev.iter().take(take) {
        for &sym in &item.1 {
            depths[sym] += 1;
        }
    }
    depths
}

/// 构建无限制 Huffman 树，返回每个出现符号的深度（未出现符号为 0）。
fn build_unlimited_lengths(freqs: &[u32], present: &[usize]) -> Vec<u8> {
    #[derive(Clone, Copy)]
    struct Node {
        left: i32,
        right: i32,
        symbol: i32,
    }

    let mut nodes: Vec<Node> = Vec::with_capacity(present.len() * 2 - 1);
    let mut heap: BinaryHeap<Reverse<(u64, usize)>> = BinaryHeap::new();

    for &sym in present {
        nodes.push(Node {
            left: -1,
            right: -1,
            symbol: sym as i32,
        });
        heap.push(Reverse((freqs[sym] as u64, nodes.len() - 1)));
    }

    while heap.len() > 1 {
        let Reverse((w1, a)) = heap.pop().unwrap();
        let Reverse((w2, b)) = heap.pop().unwrap();
        nodes.push(Node {
            left: a as i32,
            right: b as i32,
            symbol: -1,
        });
        heap.push(Reverse((w1 + w2, nodes.len() - 1)));
    }

    let root = heap.pop().unwrap().0 .1;
    let mut depths = vec![0u8; freqs.len()];

    // 迭代式后序遍历为叶子分配深度。
    let mut stack: Vec<(usize, u8)> = vec![(root, 0)];
    while let Some((idx, depth)) = stack.pop() {
        let node = nodes[idx];
        if node.symbol >= 0 {
            depths[node.symbol as usize] = depth;
        } else {
            stack.push((node.left as usize, depth + 1));
            stack.push((node.right as usize, depth + 1));
        }
    }

    depths
}

/// 根据码长生成 MSB-first 规范码。返回每个符号的码值（未出现符号的码值无效）。
pub fn build_canonical(lengths: &[u8]) -> Vec<u32> {
    let mut count = [0usize; MAX_BITS + 1];
    for &l in lengths {
        if l > 0 && (l as usize) <= MAX_BITS {
            count[l as usize] += 1;
        }
    }

    let mut first_code = [0u32; MAX_BITS + 1];
    let mut code = 0u32;
    for d in 1..=MAX_BITS {
        code = (code + count[d - 1] as u32) << 1;
        first_code[d] = code;
    }

    let mut next = first_code;
    let mut codes = vec![0u32; lengths.len()];
    for (sym, &l) in lengths.iter().enumerate() {
        if l > 0 {
            let d = l as usize;
            codes[sym] = next[d];
            next[d] += 1;
        }
    }
    codes
}

/// 写入码长序列（RLE 编码，固定 5 位 RLE 符号）。
pub fn write_lengths(w: &mut BitWriter, lengths: &[u8]) {
    let mut i = 0;
    let n = lengths.len();
    while i < n {
        let val = lengths[i];
        if val == 0 {
            let start = i;
            while i < n && lengths[i] == 0 {
                i += 1;
            }
            let mut run = i - start;
            while run >= 11 {
                let take = run.min(138);
                w.write_bits(18, 5);
                w.write_bits((take - 11) as u32, 7);
                run -= take;
            }
            if run >= 3 {
                w.write_bits(17, 5);
                w.write_bits((run - 3) as u32, 3);
                run = 0;
            }
            for _ in 0..run {
                w.write_bits(0, 5);
            }
        } else {
            let start = i;
            while i < n && lengths[i] == val {
                i += 1;
            }
            let mut run = i - start;
            // 先写一个字面量，再写重复。
            w.write_bits(val as u32, 5);
            run -= 1;
            while run >= 3 {
                let take = run.min(6);
                w.write_bits(16, 5);
                w.write_bits((take - 3) as u32, 2);
                run -= take;
            }
            for _ in 0..run {
                w.write_bits(val as u32, 5);
            }
        }
    }
}

/// 读取码长序列（RLE 解码）。
pub fn read_lengths(r: &mut BitReader, n: usize) -> Result<Vec<u8>> {
    let mut lengths = vec![0u8; n];
    let mut prev = 0u8;
    let mut i = 0usize;
    while i < n {
        let sym = r.read_bits(5)?;
        match sym {
            0..=15 => {
                lengths[i] = sym as u8;
                prev = sym as u8;
                i += 1;
            }
            16 => {
                let rep = r.read_bits(2)? as usize + 3;
                if i == 0 {
                    return corrupt("repeat of previous code length with no previous");
                }
                if i + rep > n {
                    return corrupt("code length run overflows alphabet");
                }
                for _ in 0..rep {
                    lengths[i] = prev;
                    i += 1;
                }
            }
            17 => {
                let rep = r.read_bits(3)? as usize + 3;
                if i + rep > n {
                    return corrupt("code length run overflows alphabet");
                }
                for _ in 0..rep {
                    lengths[i] = 0;
                    i += 1;
                }
                prev = 0;
            }
            18 => {
                let rep = r.read_bits(7)? as usize + 11;
                if i + rep > n {
                    return corrupt("code length run overflows alphabet");
                }
                for _ in 0..rep {
                    lengths[i] = 0;
                    i += 1;
                }
                prev = 0;
            }
            _ => return corrupt("invalid code length symbol"),
        }
    }
    Ok(lengths)
}

/// 规范 Huffman 解码器（单级查表）。
pub struct Decoder {
    /// 以 `MAX_BITS` 位码为索引的查找表，值为 `(码长 << 9) | 符号`；码长 0 表示无效。
    table: Vec<u16>,
}

impl Decoder {
    /// 由码长构建查表解码器，并校验其构成合法前缀码。
    pub fn new(lengths: &[u8]) -> Result<Self> {
        for &l in lengths {
            if l as usize > MAX_BITS {
                return corrupt("code length exceeds maximum");
            }
        }

        // 校验 Kraft 和 <= 1（否则不是合法前缀码）。
        let mut kraft = 0u64;
        for &l in lengths {
            if l > 0 {
                kraft += 1u64 << (MAX_BITS - l as usize);
            }
        }
        if kraft > (1u64 << MAX_BITS) {
            return corrupt("code lengths violate kraft inequality");
        }

        let codes = build_canonical(lengths);

        // 符号占低 9 位（符号 < 512），码长占其上的 4 位（<= 15）。
        let mut table = vec![0u16; 1 << MAX_BITS];
        for (sym, &l) in lengths.iter().enumerate() {
            if l == 0 {
                continue;
            }
            let len = l as usize;
            let start = (codes[sym] as usize) << (MAX_BITS - len);
            let count = 1usize << (MAX_BITS - len);
            let entry = ((len as u16) << 9) | sym as u16;
            for slot in &mut table[start..start + count] {
                *slot = entry;
            }
        }

        Ok(Decoder { table })
    }

    /// 解码一个符号：一次窥视 `MAX_BITS` 位查表，再按实际码长跳过。
    pub fn decode_symbol(&self, r: &mut BitReader) -> Result<u16> {
        let peek = r.peek_bits_padded(MAX_BITS) as usize;
        let entry = self.table[peek];
        let len = (entry >> 9) as usize;
        if len == 0 {
            return corrupt("invalid huffman code in stream");
        }
        r.skip_bits(len)?;
        Ok(entry & 0x1FF)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::LITLEN_SYMBOLS;

    #[test]
    fn lengths_build_valid_codes() {
        // 各种频率分布都应产生 <= MAX_BITS 的码长且 Kraft 和合法。
        let cases: Vec<Vec<u32>> = vec![
            vec![1; LITLEN_SYMBOLS],
            {
                let mut f = vec![0; LITLEN_SYMBOLS];
                f[0] = 65535;
                f[1] = 1;
                f
            },
            {
                let mut f = vec![0; LITLEN_SYMBOLS];
                for (i, x) in f.iter_mut().enumerate() {
                    *x = (i as u32 + 1).pow(3);
                }
                f
            },
            {
                let mut f = vec![0; LITLEN_SYMBOLS];
                for (i, x) in f.iter_mut().enumerate() {
                    *x = 1 << (i % 17);
                }
                f
            },
        ];
        for f in cases {
            let lens = compute_lengths(&f);
            assert!(lens.iter().all(|&l| l as usize <= MAX_BITS));
            // Kraft 和 <= 1。
            let mut kraft = 0u64;
            for &l in &lens {
                if l > 0 {
                    kraft += 1u64 << (MAX_BITS - l as usize);
                }
            }
            assert!(kraft <= 1u64 << MAX_BITS, "kraft overflow: {kraft}");
        }
    }

    #[test]
    fn rle_roundtrip() {
        let mut lens = vec![0u8; LITLEN_SYMBOLS];
        // 混合模式：长零区、重复非零区。
        for (i, l) in lens.iter_mut().enumerate() {
            if i < 10 {
                *l = 0;
            } else if i < 20 {
                *l = 5;
            } else if i < 200 {
                *l = 0;
            } else {
                *l = (i % 15) as u8;
            }
        }
        let mut w = BitWriter::new();
        write_lengths(&mut w, &lens);
        let bytes = w.finish();
        let mut r = BitReader::new(&bytes);
        let out = read_lengths(&mut r, LITLEN_SYMBOLS).unwrap();
        assert_eq!(out, lens);
    }

    #[test]
    fn decode_symbols_match_encode() {
        let freqs: Vec<u32> = (0..LITLEN_SYMBOLS as u32)
            .map(|i| (i * 7) % 23 + 1)
            .collect();
        let lens = compute_lengths(&freqs);
        let codes = build_canonical(&lens);

        let dec = Decoder::new(&lens).unwrap();

        let symbols: Vec<u16> = (0..LITLEN_SYMBOLS as u16)
            .filter(|&s| lens[s as usize] > 0)
            .collect();

        let mut w = BitWriter::new();
        for &s in &symbols {
            w.write_bits(codes[s as usize], lens[s as usize] as u32);
        }
        let bytes = w.finish();
        let mut r = BitReader::new(&bytes);
        for &s in &symbols {
            assert_eq!(dec.decode_symbol(&mut r).unwrap(), s);
        }
    }

    /// 穷举所有合法限长码，求最小 Σ freq·len（仅用于小规模校验 package-merge 最优性）。
    fn brute_force_optimal(freqs: &[u32], max_len: u8) -> u64 {
        let n = freqs.len();
        let max_len = max_len as usize;
        let mut best = u64::MAX;

        fn rec(freqs: &[u32], max_len: usize, lens: &mut [u8], pos: usize, best: &mut u64) {
            if pos == lens.len() {
                // 只考虑完整前缀码：所有符号都有码，且 Kraft 和 <= 1。
                if lens.contains(&0) {
                    return;
                }
                let mut kraft = 0u64;
                let mut cost = 0u64;
                for (i, &l) in lens.iter().enumerate() {
                    kraft += 1u64 << (max_len - l as usize);
                    cost += freqs[i] as u64 * l as u64;
                }
                if kraft <= (1u64 << max_len) && cost < *best {
                    *best = cost;
                }
                return;
            }
            for l in 1..=max_len {
                lens[pos] = l as u8;
                rec(freqs, max_len, lens, pos + 1, best);
            }
        }

        let mut lens = vec![0u8; n];
        rec(freqs, max_len, &mut lens, 0, &mut best);
        best
    }

    #[test]
    fn package_merge_is_optimal() {
        let cases: Vec<Vec<u32>> = vec![
            vec![1, 1, 1, 1, 1, 1],
            vec![1, 2, 4, 8, 16, 32],
            vec![100, 50, 25, 12, 6, 3],
            vec![1, 1, 2, 3, 5, 8],
            vec![9, 7, 7, 1, 1, 0, 0, 0],
        ];
        for f in cases {
            let depths = package_merge(&f, 5);
            let cost = depths
                .iter()
                .enumerate()
                .filter(|(_, &d)| d > 0)
                .map(|(i, &d)| f[i] as u64 * d as u64)
                .sum::<u64>();
            let active: Vec<u32> = f.iter().copied().filter(|&x| x > 0).collect();
            assert_eq!(
                cost,
                brute_force_optimal(&active, 5),
                "package-merge 应达到最优代价 for {f:?}"
            );
        }
    }

    #[test]
    fn package_merge_respects_limit_and_kraft() {
        // 几何分布会令无限制 Huffman 深度远超 MAX_BITS。
        let mut f = vec![0u32; LITLEN_SYMBOLS];
        for (i, x) in f.iter_mut().enumerate() {
            *x = 1u32 << (i % 17);
        }
        let depths = package_merge(&f, MAX_BITS as u8);
        assert!(depths.iter().all(|&d| d as usize <= MAX_BITS));
        let mut kraft = 0u64;
        for &d in &depths {
            if d > 0 {
                kraft += 1u64 << (MAX_BITS - d as usize);
            }
        }
        assert!(kraft <= 1u64 << MAX_BITS, "kraft overflow: {kraft}");
    }

    /// 属性/模糊测试：随机码流喂给 `read_lengths`，任何输入都不得 panic（可报错）。
    #[test]
    fn read_lengths_never_panics_on_random_input() {
        let mut seed = 0x1234_5678_9ABC_DEF0u64;
        for _ in 0..5000 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let len = (seed % 64) as usize;
            let mut data = vec![0u8; len];
            for b in &mut data {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                *b = (seed & 0xff) as u8;
            }
            let n = (seed % 400) as usize;
            let mut r = BitReader::new(&data);
            let _ = read_lengths(&mut r, n);
        }
    }

    /// 属性/模糊测试：随机码长表 + 随机码流喂给 `decode_symbol`，不得 panic。
    #[test]
    fn decode_symbol_never_panics_on_random_input() {
        let mut seed = 0xDEAD_BEEF_1234_5678u64;
        for _ in 0..5000 {
            seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);

            let mut lens = vec![0u8; 300];
            for l in lens.iter_mut() {
                seed = seed
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                let r = (seed % 20) as u32;
                *l = if r < 16 { r as u8 } else { 0 };
            }
            let dec = match Decoder::new(&lens) {
                Ok(d) => d,
                Err(_) => continue,
            };

            let len = (seed % 64) as usize;
            let mut data = vec![0u8; len];
            for b in &mut data {
                seed = seed
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                *b = (seed & 0xff) as u8;
            }
            let mut r = BitReader::new(&data);
            for _ in 0..64 {
                if dec.decode_symbol(&mut r).is_err() {
                    break;
                }
            }
        }
    }
}
