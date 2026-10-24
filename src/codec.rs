//! 块级编解码：将 LZ77 令牌流经 Huffman 编码为压缩块，或反向解码。

use crate::bitio::{BitReader, BitWriter};
use crate::error::{corrupt, invalid_size, Result};
use crate::format::{
    dist_code, length_code, BTYPE_COMPRESSED, BTYPE_FIXED, BTYPE_STORED, DIST_BASE,
    DIST_EXTRA_BITS, DIST_SYMBOLS, EOB_SYMBOL, LENGTH_BASE, LENGTH_EXTRA_BITS, LEN_SYMBOL_BASE,
    LITLEN_SYMBOLS,
};
use crate::huffman;
use crate::lz77::{self, MatchConfig, Token};

/// 一条待编码的符号记录。
struct Entry {
    /// 0 = 字面量/长度表，1 = 距离表。
    table: u8,
    sym: u16,
    extra: u32,
    extra_bits: u32,
}

/// 静态（固定）字面量/长度码长表：DEFLATE 风格的固定码长。
///
/// 字面量 0..143 用 8 位、144..255 用 9 位、长度码 256..279 用 7 位、
/// 280..285 用 8 位。
fn fixed_litlen_lengths() -> Vec<u8> {
    let mut lengths = vec![0u8; LITLEN_SYMBOLS];
    for (sym, l) in lengths.iter_mut().enumerate() {
        *l = match sym {
            0..=143 => 8,
            144..=255 => 9,
            256..=279 => 7,
            _ => 8, // 280..=285
        };
    }
    lengths
}

/// 静态（固定）距离码长表：40 个距离码各 6 位。
fn fixed_dist_lengths() -> Vec<u8> {
    vec![6; DIST_SYMBOLS]
}

/// 将符号序列（含 EOB）按给定码表写入位流。
fn write_symbol_stream(
    w: &mut BitWriter,
    entries: &[Entry],
    litlen_codes: &[u32],
    litlen_lengths: &[u8],
    dist_codes: &[u32],
    dist_lengths: &[u8],
) {
    for e in entries {
        let (codes, lengths) = if e.table == 0 {
            (litlen_codes, litlen_lengths)
        } else {
            (dist_codes, dist_lengths)
        };
        w.write_bits(codes[e.sym as usize], lengths[e.sym as usize] as u32);
        if e.extra_bits > 0 {
            w.write_bits(e.extra, e.extra_bits);
        }
    }
    w.write_bits(
        litlen_codes[EOB_SYMBOL as usize],
        litlen_lengths[EOB_SYMBOL as usize] as u32,
    );
}

/// 由令牌序列构建符号记录与两表频率统计。
///
/// 频率表尚未计入 EOB，调用方按需在字面量/长度表中补加一次 EOB。
fn build_entries_and_freqs(tokens: &[Token]) -> (Vec<Entry>, Vec<u32>, Vec<u32>) {
    let mut entries: Vec<Entry> = Vec::with_capacity(tokens.len() * 2);
    let mut litlen_freqs = vec![0u32; LITLEN_SYMBOLS];
    let mut dist_freqs = vec![0u32; DIST_SYMBOLS];

    for token in tokens {
        match token {
            Token::Literal(b) => {
                let sym = *b as u16;
                litlen_freqs[sym as usize] += 1;
                entries.push(Entry {
                    table: 0,
                    sym,
                    extra: 0,
                    extra_bits: 0,
                });
            }
            Token::Match { length, distance } => {
                let lc = length_code(*length);
                let lsym = LEN_SYMBOL_BASE + lc;
                litlen_freqs[lsym as usize] += 1;
                entries.push(Entry {
                    table: 0,
                    sym: lsym,
                    extra: (*length - LENGTH_BASE[lc as usize] as usize) as u32,
                    extra_bits: LENGTH_EXTRA_BITS[lc as usize] as u32,
                });

                let dc = dist_code(*distance);
                dist_freqs[dc as usize] += 1;
                entries.push(Entry {
                    table: 1,
                    sym: dc,
                    extra: (*distance - DIST_BASE[dc as usize] as usize) as u32,
                    extra_bits: DIST_EXTRA_BITS[dc as usize] as u32,
                });
            }
        }
    }

    (entries, litlen_freqs, dist_freqs)
}

/// 压缩一个块，返回 `(块类型, 块数据)`。
///
/// 依次尝试动态 Huffman 与静态 Huffman，取较小者；若均不小于原始数据，
/// 则退化为存储块（`BTYPE_STORED`）。
pub fn compress_block(dict: &[u8], data: &[u8], cfg: &MatchConfig) -> (u8, Vec<u8>) {
    if data.is_empty() {
        return (BTYPE_STORED, Vec::new());
    }

    // 最优解析：先用快速路径得到码长、构建代价模型，再用动态规划求最优令牌序列。
    let tokens = if cfg.optimal {
        let first = lz77::compress_block(dict, data, cfg);
        let (_, litlen_freqs, dist_freqs) = build_entries_and_freqs(&first);
        let cm = lz77::CostModel::new(
            &huffman::compute_lengths(&litlen_freqs),
            &huffman::compute_lengths(&dist_freqs),
        );
        lz77::compress_block_optimal(dict, data, cfg, &cm)
    } else {
        lz77::compress_block(dict, data, cfg)
    };

    // 拆分字母表：字面量/长度与距离各自独立统计频率与构建 Huffman 表。
    let (entries, mut litlen_freqs, dist_freqs) = build_entries_and_freqs(&tokens);
    litlen_freqs[EOB_SYMBOL as usize] += 1;

    // 动态 Huffman：写入两段码长序列 + 码流。
    let litlen_lengths = huffman::compute_lengths(&litlen_freqs);
    let dist_lengths = huffman::compute_lengths(&dist_freqs);
    let litlen_codes = huffman::build_canonical(&litlen_lengths);
    let dist_codes = huffman::build_canonical(&dist_lengths);

    let mut dyn_w = BitWriter::new();
    huffman::write_lengths(&mut dyn_w, &litlen_lengths);
    huffman::write_lengths(&mut dyn_w, &dist_lengths);
    write_symbol_stream(
        &mut dyn_w,
        &entries,
        &litlen_codes,
        &litlen_lengths,
        &dist_codes,
        &dist_lengths,
    );
    let dynamic = dyn_w.finish();

    // 静态 Huffman：固定码表，块内不发送码长。
    let fl = fixed_litlen_lengths();
    let fd = fixed_dist_lengths();
    let fl_codes = huffman::build_canonical(&fl);
    let fd_codes = huffman::build_canonical(&fd);

    let mut fix_w = BitWriter::new();
    write_symbol_stream(&mut fix_w, &entries, &fl_codes, &fl, &fd_codes, &fd);
    let fixed = fix_w.finish();

    // 选择最优：固定 ≤ 动态 则用固定，否则用动态；均不小于原始则存储。
    let (btype, compressed) = if fixed.len() <= dynamic.len() {
        (BTYPE_FIXED, fixed)
    } else {
        (BTYPE_COMPRESSED, dynamic)
    };
    if compressed.len() < data.len() {
        (btype, compressed)
    } else {
        (BTYPE_STORED, data.to_vec())
    }
}

/// 解压一个块，产出恰好 `raw_len` 字节。
///
/// `dict` 作为解码时的前置历史参与匹配（与编码端一致），其内容不计入输出。
pub fn decompress_block(btype: u8, data: &[u8], raw_len: usize, dict: &[u8]) -> Result<Vec<u8>> {
    match btype {
        BTYPE_STORED => {
            if data.len() != raw_len {
                return invalid_size(format!(
                    "stored block size mismatch: {} != {raw_len}",
                    data.len()
                ));
            }
            Ok(data.to_vec())
        }
        BTYPE_COMPRESSED | BTYPE_FIXED => {
            let mut r = BitReader::new(data);
            // 静态块用固定码表（块内无码长序列）；动态块先读两段码长序列。
            let (litlen_dec, dist_dec) = if btype == BTYPE_FIXED {
                (
                    huffman::Decoder::new(&fixed_litlen_lengths())?,
                    huffman::Decoder::new(&fixed_dist_lengths())?,
                )
            } else {
                let litlen_lengths = huffman::read_lengths(&mut r, LITLEN_SYMBOLS)?;
                let dist_lengths = huffman::read_lengths(&mut r, DIST_SYMBOLS)?;
                (
                    huffman::Decoder::new(&litlen_lengths)?,
                    huffman::Decoder::new(&dist_lengths)?,
                )
            };

            let dict_len = dict.len();
            let mut out = Vec::with_capacity(dict_len + raw_len);
            out.extend_from_slice(dict);

            loop {
                let sym = litlen_dec.decode_symbol(&mut r)?;
                if sym < 256 {
                    out.push(sym as u8);
                    if out.len() - dict_len > raw_len {
                        return corrupt("block produced more data than declared");
                    }
                } else if sym == EOB_SYMBOL {
                    break;
                } else if sym < LITLEN_SYMBOLS as u16 {
                    // 长度码。
                    let lc = sym - LEN_SYMBOL_BASE;
                    let extra = r.read_bits(LENGTH_EXTRA_BITS[lc as usize] as usize)?;
                    let length = LENGTH_BASE[lc as usize] as usize + extra as usize;

                    // 其后必须是距离码（来自独立的距离表）。
                    let dc = dist_dec.decode_symbol(&mut r)?;
                    let dextra = r.read_bits(DIST_EXTRA_BITS[dc as usize] as usize)?;
                    let distance = DIST_BASE[dc as usize] as usize + dextra as usize;

                    if distance == 0 || distance > out.len() {
                        return corrupt("match distance out of range");
                    }
                    let start = out.len() - distance;
                    for k in 0..length {
                        let b = out[start + k];
                        out.push(b);
                    }
                    if out.len() - dict_len > raw_len {
                        return corrupt("block produced more data than declared");
                    }
                } else {
                    return corrupt("unexpected symbol in literal/length table");
                }
            }

            if out.len() - dict_len != raw_len {
                return corrupt(format!(
                    "decoded block size mismatch: {} != {raw_len}",
                    out.len() - dict_len
                ));
            }
            Ok(out.split_off(dict_len))
        }
        _ => corrupt(format!("unknown block type {btype}")),
    }
}

/// 并行压缩多个互不依赖的块，结果按输入顺序返回。
///
/// 每个块独立压缩（只共享只读的预设字典 `dict`），因此可安全并行。使用
/// [`std::thread::scope`] 手工切分工作，不引入任何第三方依赖。块数较少或
/// `threads <= 1` 时退化为顺序压缩，避免无谓的线程开销。
pub fn compress_blocks_parallel(
    dict: &[u8],
    blocks: &[Vec<u8>],
    cfg: &MatchConfig,
    threads: usize,
) -> Vec<(u8, Vec<u8>)> {
    let n = blocks.len();
    if n == 0 {
        return Vec::new();
    }
    if n == 1 || threads <= 1 {
        return blocks
            .iter()
            .map(|b| compress_block(dict, b, cfg))
            .collect();
    }

    let threads = threads.min(n);
    let chunk_size = n.div_ceil(threads);

    let mut out = Vec::with_capacity(n);
    std::thread::scope(|scope| {
        let mut handles = Vec::with_capacity(threads);
        for chunk in blocks.chunks(chunk_size) {
            handles.push(scope.spawn(move || {
                chunk
                    .iter()
                    .map(|b| compress_block(dict, b, cfg))
                    .collect::<Vec<_>>()
            }));
        }
        for h in handles {
            out.extend(h.join().expect("compress worker panicked"));
        }
    });
    out
}

/// 并行解压多个互不依赖的块，结果按输入顺序返回。
///
/// `blocks` 为 `(块类型, 块数据, 原始长度)` 三元组；`dict` 为共享的预设字典。
/// 与 [`compress_blocks_parallel`] 一样使用 [`std::thread::scope`] 自实现并行，
/// 块数较少或 `threads <= 1` 时退化为顺序解压。
pub fn decompress_blocks_parallel(
    dict: &[u8],
    blocks: &[(u8, Vec<u8>, usize)],
    threads: usize,
) -> Result<Vec<Vec<u8>>> {
    let n = blocks.len();
    if n == 0 {
        return Ok(Vec::new());
    }
    if n == 1 || threads <= 1 {
        return blocks
            .iter()
            .map(|(btype, data, raw_len)| decompress_block(*btype, data, *raw_len, dict))
            .collect();
    }

    let threads = threads.min(n);
    let chunk_size = n.div_ceil(threads);

    let mut out = Vec::with_capacity(n);
    std::thread::scope(|scope| -> Result<()> {
        let mut handles = Vec::with_capacity(threads);
        for chunk in blocks.chunks(chunk_size) {
            handles.push(scope.spawn(move || {
                chunk
                    .iter()
                    .map(|(btype, data, raw_len)| decompress_block(*btype, data, *raw_len, dict))
                    .collect::<Result<Vec<_>>>()
            }));
        }
        for h in handles {
            out.extend(h.join().expect("decompress worker panicked")?);
        }
        Ok(())
    })?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(data: &[u8], cfg: &MatchConfig) {
        let (btype, block) = compress_block(&[], data, cfg);
        let out = decompress_block(btype, &block, data.len(), &[]).unwrap();
        assert_eq!(out, data);
    }

    fn roundtrip_with_dict(dict: &[u8], data: &[u8], cfg: &MatchConfig) {
        let (btype, block) = compress_block(dict, data, cfg);
        let out = decompress_block(btype, &block, data.len(), dict).unwrap();
        assert_eq!(out, data);
    }

    #[test]
    fn roundtrip_repetitive() {
        let mut data = Vec::new();
        for _ in 0..500 {
            data.extend_from_slice(b"the quick brown fox jumps over the lazy dog. ");
        }
        roundtrip(&data, &MatchConfig::default());
    }

    #[test]
    fn roundtrip_random_and_small() {
        let mut seed = 0xdead_beefu32;
        for len in [0usize, 1, 2, 3, 4, 5, 100, 1000, 20000] {
            let mut data = vec![0u8; len];
            for b in data.iter_mut() {
                seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                *b = (seed >> 16) as u8;
            }
            roundtrip(&data, &MatchConfig::default());
        }
    }

    #[test]
    fn roundtrip_highly_skewed() {
        // 单字节大量重复，触发长度码边界与 258 特殊分支。
        let data = vec![0xABu8; 100_000];
        roundtrip(&data, &MatchConfig::default());
    }

    #[test]
    fn roundtrip_large_distance_match() {
        // 让同一段独特数据在超过旧窗口（32768）的距离处再次出现，
        // 验证扩大后的距离码表能正确编码/解码大距离匹配。
        let unit: Vec<u8> = (0..50_000u32).map(|i| (i % 251) as u8).collect();
        let mut data = unit.clone();
        data.extend_from_slice(&[0xEEu8; 20_000]);
        data.extend_from_slice(&unit); // 距离 = 50_000 + 20_000 = 70_000 > 32768

        let cfg = MatchConfig::default();
        let (btype, block) = compress_block(&[], &data, &cfg);
        let out = decompress_block(btype, &block, data.len(), &[]).unwrap();
        assert_eq!(out, data);
        // 大距离匹配应带来可观的压缩收益（而非整块存储）。
        assert!(
            block.len() < data.len(),
            "expected compression from long-range match"
        );
    }

    #[test]
    fn roundtrip_with_dictionary() {
        // 字典为数据的前缀历史，数据跨边界引用字典。
        let dict: Vec<u8> = (0..200u32).map(|i| (i % 251) as u8).collect();
        let data: Vec<u8> = dict[50..].to_vec();
        roundtrip_with_dict(&dict, &data, &MatchConfig::default());
    }

    #[test]
    fn fixed_block_roundtrip() {
        // 手工构造一个静态 Huffman 块：字面量 'a' + 匹配(len=3, dist=1)，
        // 覆盖 BTYPE_FIXED 的字面量/长度表与距离表解码路径（块内无码长序列）。
        let entries = vec![
            Entry {
                table: 0,
                sym: b'a' as u16,
                extra: 0,
                extra_bits: 0,
            },
            Entry {
                table: 0,
                sym: LEN_SYMBOL_BASE,
                extra: 0,
                extra_bits: 0,
            },
            Entry {
                table: 1,
                sym: 0,
                extra: 0,
                extra_bits: 0,
            },
        ];

        let fl = fixed_litlen_lengths();
        let fd = fixed_dist_lengths();
        let fl_codes = huffman::build_canonical(&fl);
        let fd_codes = huffman::build_canonical(&fd);
        let mut w = BitWriter::new();
        write_symbol_stream(&mut w, &entries, &fl_codes, &fl, &fd_codes, &fd);
        let block = w.finish();

        let data = b"aaaa".to_vec();
        let out = decompress_block(BTYPE_FIXED, &block, data.len(), &[]).unwrap();
        assert_eq!(out, data);
    }

    #[test]
    fn parallel_matches_sequential() {
        let cfg = MatchConfig::default();
        let mut blocks = Vec::new();
        let mut seed = 0x1234_5678u32;
        for _ in 0..16 {
            let mut b = vec![0u8; 10_000];
            for x in b.iter_mut() {
                seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                *x = (seed >> 24) as u8;
            }
            blocks.push(b);
        }

        let seq: Vec<_> = blocks
            .iter()
            .map(|b| compress_block(&[], b, &cfg))
            .collect();
        let par = compress_blocks_parallel(&[], &blocks, &cfg, 4);
        assert_eq!(seq, par, "并行压缩必须与顺序压缩逐字节一致");

        let specs: Vec<_> = seq
            .iter()
            .map(|(t, d)| (*t, d.clone(), 10_000usize))
            .collect();
        let seq_out = decompress_blocks_parallel(&[], &specs, 1).unwrap();
        let par_out = decompress_blocks_parallel(&[], &specs, 4).unwrap();
        assert_eq!(seq_out, par_out, "并行解压必须与顺序解压一致");
        for (out, block) in par_out.iter().zip(&blocks) {
            assert_eq!(out, block);
        }
    }
}
