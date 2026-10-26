//! FSE（Finite State Entropy，tANS）熵编解码。
//!
//! 对标 zstd 的 FSE：把符号频率归一化到 `2^k` 的总和，构建 spread 表与解码状态
//! 转移表；解码为单级查表（每状态一次读出 `(symbol, nb_bits, new_state)`）。编码用
//! 反向状态机（从终态逆序遍历符号，据每符号的 `new_state` 二分定位）。位序为
//! **LSB-first**。
//!
//! 由于 tANS 编码是「反向遍历符号、初始状态最后写出」，而解码是正向读取，这里在
//! 编码端把每个写位预反转、整体再反转一次，使解码端可用正向 [`LsbReader`] 读取。
//!
//! 归一化计数用类 zstd `FSE_readNCount` 的 RLE 格式写入/读取。

use crate::bitio::{LsbReader, LsbWriter};
use crate::error::{corrupt, Result};

/// 归一化计数的最大表对数值（表大小 `1 << FSE_MAX_TABLELOG`）。
pub const FSE_MAX_TABLELOG: u8 = 15;
/// 最小表对数值：保证 spread 步长（`5/8 * tableSize`）为奇数、与表大小互质。
pub const FSE_MIN_TABLELOG: u8 = 5;

/// 返回 `x` 的最高位位置（0-based，等价于 `floor(log2(x))`）；`x` 必须非零。
#[inline]
fn highbit(x: u32) -> u8 {
    debug_assert!(x > 0);
    (31 - x.leading_zeros()) as u8
}

/// 反转 `v` 的低 `count` 位。
#[inline]
fn reverse_bits(mut v: u32, count: u32) -> u32 {
    let mut out = 0u32;
    for _ in 0..count {
        out = (out << 1) | (v & 1);
        v >>= 1;
    }
    out
}

/// 把原始频率归一化到总和 `1 << k`，每个出现符号至少计数 1。
pub fn normalize_counts(freqs: &[u32], k: u8) -> Result<Vec<u32>> {
    let n = 1u32 << k;
    let total: u32 = freqs.iter().sum();
    if total == 0 {
        return corrupt("cannot normalize empty frequencies");
    }
    let nonzero: Vec<usize> = (0..freqs.len()).filter(|&s| freqs[s] > 0).collect();
    if nonzero.len() > n as usize {
        return corrupt("too many symbols for the chosen table log");
    }

    let mut counts = vec![0u32; freqs.len()];

    if total <= n {
        let scale = n / total;
        let mut sum = 0u32;
        for &s in &nonzero {
            counts[s] = freqs[s] * scale;
            sum += counts[s];
        }
        let mut order = nonzero.clone();
        order.sort_by_key(|&s| std::cmp::Reverse(freqs[s]));
        let mut i = 0usize;
        while sum < n {
            counts[order[i % order.len()]] += 1;
            sum += 1;
            i += 1;
        }
    } else {
        let mut sum = 0u32;
        for &s in &nonzero {
            let c = ((freqs[s] as u64 * n as u64) / total as u64).max(1) as u32;
            counts[s] = c;
            sum += c;
        }
        while sum > n {
            let mut best = nonzero[0];
            for &s in &nonzero {
                if counts[s] > counts[best] {
                    best = s;
                }
            }
            if counts[best] <= 1 {
                return corrupt("normalization failed to reduce counts");
            }
            counts[best] -= 1;
            sum -= 1;
        }
        while sum < n {
            let mut best = nonzero[0];
            for &s in &nonzero {
                if counts[best] == 0 || counts[s] < counts[best] {
                    best = s;
                }
            }
            counts[best] += 1;
            sum += 1;
        }
    }

    Ok(counts)
}

/// FSE 编/解码表。
pub struct FSETable {
    table_log: u8,
    table_size: usize,
    /// 解码表：`sym[state]`、`nb_bits[state]`、`new_state[state]`。
    sym: Vec<u16>,
    nb_bits: Vec<u8>,
    new_state: Vec<u16>,
    /// 编码用：每个符号的 `(new_state, nb_bits, state)` 列表（按 `new_state` 升序）。
    enc_states: Vec<Vec<(u32, u8, u32)>>,
}

impl FSETable {
    /// 由归一化计数（总和 `1 << table_log`）构建编解码表。
    pub fn build(counts: &[u32], table_log: u8) -> Result<Self> {
        let n = 1usize << table_log;
        let max_sym = counts.len() - 1;
        let sum: u32 = counts.iter().sum();
        if sum as usize != n {
            return corrupt(format!("normalized counts sum {sum} != table size {n}"));
        }
        if !(FSE_MIN_TABLELOG..=FSE_MAX_TABLELOG).contains(&table_log) {
            return corrupt("table log out of range");
        }

        let step = (n >> 1) + (n >> 3) + 3;
        let mask = n - 1;

        // spread：把符号按步长均匀分布到状态槽位。
        let mut spread_sym = vec![0u16; n];
        let mut position = 0usize;
        for (s, &count) in counts.iter().enumerate() {
            for _ in 0..count as usize {
                spread_sym[position] = s as u16;
                position = (position + step) & mask;
            }
        }

        // 解码表：symbolNext 初始为计数本身（zstd 语义）。
        let mut symbol_next = vec![0u32; max_sym + 1];
        symbol_next[..=max_sym].copy_from_slice(&counts[..=max_sym]);
        let mut sym = vec![0u16; n];
        let mut nb_bits = vec![0u8; n];
        let mut new_state = vec![0u16; n];
        for state in 0..n {
            let s = spread_sym[state] as usize;
            let next_state = symbol_next[s];
            symbol_next[s] += 1;
            let nbb = table_log - highbit(next_state);
            let nsv = (next_state << nbb) - n as u32;
            sym[state] = s as u16;
            nb_bits[state] = nbb;
            new_state[state] = nsv as u16;
        }

        // 编码用状态列表。
        let mut enc_states: Vec<Vec<(u32, u8, u32)>> = vec![Vec::new(); max_sym + 1];
        for state in 0..n {
            let s = sym[state] as usize;
            enc_states[s].push((new_state[state] as u32, nb_bits[state], state as u32));
        }
        for list in enc_states.iter_mut() {
            list.sort_by_key(|&(ns, _, _)| ns);
        }

        Ok(FSETable {
            table_log,
            table_size: n,
            sym,
            nb_bits,
            new_state,
            enc_states,
        })
    }

    /// 表对数值。
    pub fn table_log(&self) -> u8 {
        self.table_log
    }

    /// 编码整个符号序列（反向状态机），返回正向可读的字节流。
    pub fn encode_all(&self, symbols: &[u16]) -> Vec<u8> {
        let mut w = LsbWriter::new();
        let mut state = (self.table_size - 1) as u32; // 终态。
        for &s in symbols.iter().rev() {
            let list = &self.enc_states[s as usize];
            debug_assert!(!list.is_empty());
            let pos = list.partition_point(|&(ns, _, _)| ns <= state);
            let (ns, nb, prev_state) = list[pos - 1];
            let read = state - ns;
            // 预反转 + finish_reversed 整体反转 = 恢复原始位序。
            w.write_bits(reverse_bits(read, nb as u32), nb as u32);
            state = prev_state;
        }
        // flush 初始状态（同样预反转）。
        w.write_bits(
            reverse_bits(state, self.table_log as u32),
            self.table_log as u32,
        );
        w.finish_reversed()
    }

    /// 解码一个符号：读位流并更新状态。
    #[inline]
    pub fn decode_symbol(&self, state: &mut u32, r: &mut LsbReader) -> Result<u16> {
        let st = *state as usize;
        if st >= self.table_size {
            return corrupt("fse state out of range");
        }
        let s = self.sym[st];
        let nb = self.nb_bits[st];
        let read = r.read_bits(nb as usize)?;
        *state = self.new_state[st] as u32 + read;
        Ok(s)
    }
}

/// 写出归一化计数（RLE）：`table_log(4) + last_symbol(9) + 计数序列`。
pub fn write_counts(w: &mut LsbWriter, counts: &[u32], table_log: u8) {
    let last = counts.len() - 1;
    w.write_bits(table_log as u32, 4);
    w.write_bits(last as u32, 9);

    let mut s = 0usize;
    while s <= last {
        if counts[s] == 0 {
            let start = s;
            while s <= last && counts[s] == 0 {
                s += 1;
            }
            let run = s - start;
            w.write_bits(1, 1);
            w.write_bits((run - 1) as u32, 9);
        } else {
            w.write_bits(0, 1);
            w.write_bits(counts[s] - 1, table_log as u32);
            s += 1;
        }
    }
}

/// 读取归一化计数，返回 `(table_log, counts)`。
pub fn read_counts(r: &mut LsbReader) -> Result<(u8, Vec<u32>)> {
    let table_log = r.read_bits(4)? as u8;
    if !(FSE_MIN_TABLELOG..=FSE_MAX_TABLELOG).contains(&table_log) {
        return corrupt("invalid fse table log");
    }
    let last = r.read_bits(9)? as usize;
    if last >= 4096 {
        return corrupt("fse alphabet too large");
    }
    let mut counts = vec![0u32; last + 1];
    let mut s = 0usize;
    while s <= last {
        let bit = r.read_bits(1)?;
        if bit == 1 {
            let run = r.read_bits(9)? as usize + 1;
            if s + run > last + 1 {
                return corrupt("fse zero run overflows alphabet");
            }
            s += run;
        } else {
            counts[s] = r.read_bits(table_log as usize)? + 1;
            s += 1;
        }
    }
    let sum: u32 = counts.iter().sum();
    if sum != (1u32 << table_log) {
        return corrupt("fse normalized counts sum mismatch");
    }
    Ok((table_log, counts))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip_symbols(counts: &[u32], table_log: u8, symbols: &[u16]) {
        let table = FSETable::build(counts, table_log).unwrap();
        let bytes = table.encode_all(symbols);

        let mut r = LsbReader::new(&bytes);
        let mut state = r.read_bits(table_log as usize).unwrap();
        let mut out = Vec::with_capacity(symbols.len());
        for _ in 0..symbols.len() {
            out.push(table.decode_symbol(&mut state, &mut r).unwrap());
        }
        assert_eq!(out, symbols, "FSE symbols must roundtrip");
    }

    #[test]
    fn single_symbol_roundtrip() {
        let counts = vec![0u32, 0, 0, 32, 0];
        let symbols = vec![3u16; 1000];
        roundtrip_symbols(&counts, 5, &symbols);
    }

    #[test]
    fn skewed_roundtrip() {
        let counts = vec![2, 2, 4, 8, 16];
        let mut symbols = Vec::new();
        let mut seed = 0x1234_5678u32;
        for _ in 0..10_000 {
            seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            symbols.push((seed % 5) as u16);
        }
        roundtrip_symbols(&counts, 5, &symbols);
    }

    #[test]
    fn non_power_of_two_roundtrip() {
        let counts = vec![3, 5, 6, 7, 11];
        let mut symbols = Vec::new();
        let mut seed = 0xdead_beefu32;
        for _ in 0..20_000 {
            seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            symbols.push((seed % 5) as u16);
        }
        roundtrip_symbols(&counts, 5, &symbols);
    }

    #[test]
    fn counts_rle_roundtrip() {
        let mut counts = vec![0u32; 300];
        let mut s = 0u32;
        for (i, c) in counts.iter_mut().enumerate() {
            if i % 17 == 3 {
                *c = 1;
                s += 1;
            } else if i % 17 == 7 {
                *c = 3;
                s += 3;
            }
        }
        let n = 1024u32;
        let diff = n - s;
        counts[1] += diff;

        let mut w = LsbWriter::new();
        write_counts(&mut w, &counts, 10);
        let bytes = w.finish();

        let mut r = LsbReader::new(&bytes);
        let (k, out) = read_counts(&mut r).unwrap();
        assert_eq!(k, 10);
        assert_eq!(out, counts);
    }

    #[test]
    fn normalize_roundtrip() {
        let mut freqs = vec![0u32; 256];
        let mut seed = 0x9e37_79b9u32;
        for f in freqs.iter_mut() {
            seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            *f = seed % 1000;
        }
        let counts = normalize_counts(&freqs, 9).unwrap();
        let table = FSETable::build(&counts, 9).unwrap();

        let symbols: Vec<u16> = (0..5000u16).map(|i| i % 256).collect();
        let bytes = table.encode_all(&symbols);

        let mut r = LsbReader::new(&bytes);
        let mut state = r.read_bits(9).unwrap();
        let mut out = Vec::new();
        for _ in 0..symbols.len() {
            out.push(table.decode_symbol(&mut state, &mut r).unwrap());
        }
        assert_eq!(out, symbols);
    }

    #[test]
    fn decode_symbol_never_panics_on_random_input() {
        let counts = vec![2, 4, 6, 8, 12];
        let table = FSETable::build(&counts, 5).unwrap();
        let mut seed = 0xcafe_babeu32;
        for _ in 0..5000 {
            seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let len = (seed % 64) as usize;
            let mut data = vec![0u8; len];
            for b in &mut data {
                seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                *b = (seed & 0xff) as u8;
            }
            let mut r = LsbReader::new(&data);
            let st = match r.read_bits(5) {
                Ok(s) => s,
                Err(_) => continue,
            };
            let mut state = st;
            for _ in 0..64 {
                if table.decode_symbol(&mut state, &mut r).is_err() {
                    break;
                }
            }
        }
    }

    #[test]
    fn read_counts_never_panics_on_random_input() {
        let mut seed = 0x0123_4567u64;
        for _ in 0..5000 {
            seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let len = (seed % 64) as usize;
            let mut data = vec![0u8; len];
            for b in &mut data {
                seed = seed
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                *b = (seed & 0xff) as u8;
            }
            let mut r = LsbReader::new(&data);
            let _ = read_counts(&mut r);
        }
    }
}
