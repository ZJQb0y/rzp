//! 块级编解码：将 LZ77 令牌流经 Huffman 编码为压缩块，或反向解码。
//!
//! V4 与 V5 的块结构在此分派：V4 距离字母表为 40 个字面量距离码；V5 距离字母表为
//! `REP_SYMBOLS`（3 个重复偏移）+ 50 个字面量距离码（32 MiB 窗口），编码/解码端
//! 对称维护「最近 3 个距离」以实现 repcode 复用。

use crate::bitio::{BitReader, BitWriter};
use crate::error::{corrupt, invalid_size, Result};
use crate::format::{
    dist_code, dist_code_v5, length_code, FormatVersion, BTYPE_COMPRESSED, BTYPE_FIXED,
    BTYPE_FSE_DYNAMIC, BTYPE_FSE_FIXED, BTYPE_STORED, DIST_BASE, DIST_EXTRA_BITS, DIST_SYMBOLS,
    EOB_SYMBOL, LENGTH_BASE, LENGTH_EXTRA_BITS, LEN_SYMBOL_BASE, LITLEN_SYMBOLS, MAX_DIST,
    MAX_WINDOW_SIZE, REP_SYMBOLS, V5_DIST_ALPHABET, V5_DIST_BASE, V5_DIST_EXTRA_BITS,
};
use crate::fse;
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

/// 静态（固定）距离码长表：每个距离符号 6 位。
fn fixed_dist_lengths(fv: FormatVersion) -> Vec<u8> {
    vec![6; dist_symbols(fv)]
}

/// 距离字母表大小（按格式版本）。
fn dist_symbols(fv: FormatVersion) -> usize {
    match fv {
        FormatVersion::V4 => DIST_SYMBOLS,
        FormatVersion::V5 => V5_DIST_ALPHABET,
    }
}

/// 编码端 repcode 判定：命中最近 3 个距离时返回对应的 repcode 符号（0/1/2），
/// 并按 zstd 语义更新最近距离数组（被引用者提到 rep0 首位）；未命中返回 `None`
/// （此时最近距离数组保持不变，由调用方插入新距离）。
fn encode_rep_symbol(reps: &mut [usize; 3], distance: usize) -> Option<u16> {
    if distance == reps[0] {
        Some(0)
    } else if distance == reps[1] {
        reps.swap(0, 1);
        Some(1)
    } else if distance == reps[2] {
        let r = reps[2];
        reps[2] = reps[1];
        reps[1] = reps[0];
        reps[0] = r;
        Some(2)
    } else {
        None
    }
}

/// 解码端 repcode 还原：按符号还原真实距离并更新最近距离数组。
fn decode_rep_symbol(reps: &mut [usize; 3], sym: u16) -> usize {
    match sym {
        0 => reps[0],
        1 => {
            reps.swap(0, 1);
            reps[0]
        }
        2 => {
            let r = reps[2];
            reps[2] = reps[1];
            reps[1] = reps[0];
            reps[0] = r;
            r
        }
        _ => unreachable!("repcode symbol must be < REP_SYMBOLS"),
    }
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
/// 频率表尚未计入 EOB，调用方按需在字面量/长度表中补加一次 EOB。V5 距离符号
/// 含 repcode（0/1/2）与扩展字面量距离码（3..=52），编码端对称维护最近距离。
fn build_entries_and_freqs(
    tokens: &[Token],
    fv: FormatVersion,
) -> (Vec<Entry>, Vec<u32>, Vec<u32>) {
    let mut entries: Vec<Entry> = Vec::with_capacity(tokens.len() * 2);
    let mut litlen_freqs = vec![0u32; LITLEN_SYMBOLS];
    let mut dist_freqs = vec![0u32; dist_symbols(fv)];
    let mut reps = [1usize, 1, 1];

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

                let (dsym, dextra, dextra_bits) = match fv {
                    FormatVersion::V4 => {
                        let dc = dist_code(*distance);
                        (
                            dc,
                            (*distance - DIST_BASE[dc as usize] as usize) as u32,
                            DIST_EXTRA_BITS[dc as usize] as u32,
                        )
                    }
                    FormatVersion::V5 => {
                        if let Some(rep) = encode_rep_symbol(&mut reps, *distance) {
                            (rep, 0, 0)
                        } else {
                            reps = [*distance, reps[0], reps[1]];
                            let dc = dist_code_v5(*distance);
                            (
                                dc + REP_SYMBOLS as u16,
                                (*distance - V5_DIST_BASE[dc as usize] as usize) as u32,
                                V5_DIST_EXTRA_BITS[dc as usize] as u32,
                            )
                        }
                    }
                };
                dist_freqs[dsym as usize] += 1;
                entries.push(Entry {
                    table: 1,
                    sym: dsym,
                    extra: dextra,
                    extra_bits: dextra_bits,
                });
            }
        }
    }

    (entries, litlen_freqs, dist_freqs)
}

/// V5 FSE 字面量/长度表的表对数值（`2^9 = 512 >= 286`）。
const FSE_LITLEN_TABLELOG: u8 = 9;
/// V5 FSE 距离表的表对数值（`2^6 = 64 >= 53`）。
const FSE_DIST_TABLELOG: u8 = 6;

/// 固定 FSE 字面量/长度表归一化计数：前 226 符号计数 2、其余计数 1。
fn fixed_fse_litlen_counts() -> Vec<u32> {
    let mut c = vec![0u32; LITLEN_SYMBOLS];
    for (i, x) in c.iter_mut().enumerate() {
        *x = if i < 226 { 2 } else { 1 };
    }
    c
}

/// 固定 FSE 距离表归一化计数：前 11 符号计数 2、其余计数 1。
fn fixed_fse_dist_counts() -> Vec<u32> {
    let mut c = vec![0u32; V5_DIST_ALPHABET];
    for (i, x) in c.iter_mut().enumerate() {
        *x = if i < 11 { 2 } else { 1 };
    }
    c
}

/// 收集 V5 FSE 编码所需的符号流与额外位流。
#[allow(clippy::type_complexity)]
fn build_fse_streams(
    tokens: &[Token],
) -> (Vec<u16>, Vec<u16>, Vec<(u32, u32)>, Vec<u32>, Vec<u32>) {
    let mut litlen_syms = Vec::with_capacity(tokens.len() + 1);
    let mut dist_syms = Vec::with_capacity(tokens.len());
    let mut extra = Vec::with_capacity(tokens.len());
    let mut litlen_freqs = vec![0u32; LITLEN_SYMBOLS];
    let mut dist_freqs = vec![0u32; V5_DIST_ALPHABET];
    let mut reps = [1usize, 1, 1];

    for token in tokens {
        match token {
            Token::Literal(b) => {
                litlen_syms.push(*b as u16);
                litlen_freqs[*b as usize] += 1;
            }
            Token::Match { length, distance } => {
                let lc = length_code(*length);
                let lsym = LEN_SYMBOL_BASE + lc;
                litlen_syms.push(lsym);
                litlen_freqs[lsym as usize] += 1;
                extra.push((
                    (*length - LENGTH_BASE[lc as usize] as usize) as u32,
                    LENGTH_EXTRA_BITS[lc as usize] as u32,
                ));

                let dsym = if let Some(rep) = encode_rep_symbol(&mut reps, *distance) {
                    rep
                } else {
                    reps = [*distance, reps[0], reps[1]];
                    dist_code_v5(*distance) + REP_SYMBOLS as u16
                };
                dist_syms.push(dsym);
                dist_freqs[dsym as usize] += 1;

                if dsym >= REP_SYMBOLS as u16 {
                    let idx = (dsym - REP_SYMBOLS as u16) as usize;
                    extra.push((
                        (*distance - V5_DIST_BASE[idx] as usize) as u32,
                        V5_DIST_EXTRA_BITS[idx] as u32,
                    ));
                }
            }
        }
    }
    litlen_syms.push(EOB_SYMBOL);
    litlen_freqs[EOB_SYMBOL as usize] += 1;

    (litlen_syms, dist_syms, extra, litlen_freqs, dist_freqs)
}

/// 把额外位流打包为字节。
fn pack_extra_bits(extra: &[(u32, u32)]) -> Vec<u8> {
    let mut w = crate::bitio::LsbWriter::new();
    for &(value, count) in extra {
        w.write_bits(value, count);
    }
    w.finish()
}

/// 编码一个 V5 动态 FSE 块，返回块数据；失败返回 `None`（回退存储）。
fn encode_fse_dynamic(tokens: &[Token]) -> Option<Vec<u8>> {
    let (litlen_syms, dist_syms, extra, litlen_freqs, dist_freqs) = build_fse_streams(tokens);

    let litlen_counts = fse::normalize_counts(&litlen_freqs, FSE_LITLEN_TABLELOG).ok()?;
    let dist_counts = fse::normalize_counts(&dist_freqs, FSE_DIST_TABLELOG).ok()?;
    let litlen_table = fse::FSETable::build(&litlen_counts, FSE_LITLEN_TABLELOG).ok()?;
    let dist_table = fse::FSETable::build(&dist_counts, FSE_DIST_TABLELOG).ok()?;

    let litlen_stream = litlen_table.encode_all(&litlen_syms);
    let dist_stream = dist_table.encode_all(&dist_syms);
    let extra_stream = pack_extra_bits(&extra);

    let mut counts_w = crate::bitio::LsbWriter::new();
    fse::write_counts(&mut counts_w, &litlen_counts, FSE_LITLEN_TABLELOG);
    fse::write_counts(&mut counts_w, &dist_counts, FSE_DIST_TABLELOG);
    let counts_bytes = counts_w.finish();

    let mut out = Vec::with_capacity(
        12 + counts_bytes.len() + litlen_stream.len() + dist_stream.len() + extra_stream.len(),
    );
    out.extend_from_slice(&(counts_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(&(litlen_stream.len() as u32).to_le_bytes());
    out.extend_from_slice(&(dist_stream.len() as u32).to_le_bytes());
    out.extend_from_slice(&(extra_stream.len() as u32).to_le_bytes());
    out.extend_from_slice(&counts_bytes);
    out.extend_from_slice(&litlen_stream);
    out.extend_from_slice(&dist_stream);
    out.extend_from_slice(&extra_stream);
    Some(out)
}

/// 编码一个 V5 固定 FSE 块，返回块数据；失败返回 `None`。
fn encode_fse_fixed(tokens: &[Token]) -> Option<Vec<u8>> {
    let (litlen_syms, dist_syms, extra, _, _) = build_fse_streams(tokens);

    let litlen_table =
        fse::FSETable::build(&fixed_fse_litlen_counts(), FSE_LITLEN_TABLELOG).ok()?;
    let dist_table = fse::FSETable::build(&fixed_fse_dist_counts(), FSE_DIST_TABLELOG).ok()?;

    let litlen_stream = litlen_table.encode_all(&litlen_syms);
    let dist_stream = dist_table.encode_all(&dist_syms);
    let extra_stream = pack_extra_bits(&extra);

    let mut out =
        Vec::with_capacity(12 + litlen_stream.len() + dist_stream.len() + extra_stream.len());
    out.extend_from_slice(&(litlen_stream.len() as u32).to_le_bytes());
    out.extend_from_slice(&(dist_stream.len() as u32).to_le_bytes());
    out.extend_from_slice(&(extra_stream.len() as u32).to_le_bytes());
    out.extend_from_slice(&litlen_stream);
    out.extend_from_slice(&dist_stream);
    out.extend_from_slice(&extra_stream);
    Some(out)
}

/// 解码一个 V5 FSE 块。
fn decode_fse_block(data: &[u8], raw_len: usize, dict: &[u8], fixed: bool) -> Result<Vec<u8>> {
    use crate::bitio::LsbReader;

    let (litlen_table, dist_table, litlen_stream, dist_stream, extra_stream) = if fixed {
        if data.len() < 12 {
            return corrupt("fse fixed block too short");
        }
        let litlen_len = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
        let dist_len = u32::from_le_bytes(data[4..8].try_into().unwrap()) as usize;
        let extra_len = u32::from_le_bytes(data[8..12].try_into().unwrap()) as usize;
        if litlen_len + dist_len + extra_len > data.len() - 12 {
            return corrupt("fse fixed block length overflow");
        }
        let base = 12;
        (
            fse::FSETable::build(&fixed_fse_litlen_counts(), FSE_LITLEN_TABLELOG)?,
            fse::FSETable::build(&fixed_fse_dist_counts(), FSE_DIST_TABLELOG)?,
            &data[base..base + litlen_len],
            &data[base + litlen_len..base + litlen_len + dist_len],
            &data[base + litlen_len + dist_len..base + litlen_len + dist_len + extra_len],
        )
    } else {
        if data.len() < 16 {
            return corrupt("fse dynamic block too short");
        }
        let counts_len = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
        let litlen_len = u32::from_le_bytes(data[4..8].try_into().unwrap()) as usize;
        let dist_len = u32::from_le_bytes(data[8..12].try_into().unwrap()) as usize;
        let extra_len = u32::from_le_bytes(data[12..16].try_into().unwrap()) as usize;
        if counts_len > data.len() - 16 {
            return corrupt("fse dynamic counts overflow");
        }
        let counts_bytes = &data[16..16 + counts_len];
        let mut cr = LsbReader::new(counts_bytes);
        let (lk, litlen_counts) = fse::read_counts(&mut cr)?;
        let (dk, dist_counts) = fse::read_counts(&mut cr)?;
        let base = 16 + counts_len;
        let total = litlen_len + dist_len + extra_len;
        if total > data.len() - base {
            return corrupt("fse dynamic streams overflow");
        }
        (
            fse::FSETable::build(&litlen_counts, lk)?,
            fse::FSETable::build(&dist_counts, dk)?,
            &data[base..base + litlen_len],
            &data[base + litlen_len..base + litlen_len + dist_len],
            &data[base + litlen_len + dist_len..base + total],
        )
    };

    let mut lr = LsbReader::new(litlen_stream);
    let mut dr = LsbReader::new(dist_stream);
    let mut er = LsbReader::new(extra_stream);
    let mut litlen_state = lr.read_bits(litlen_table.table_log() as usize)?;
    let mut dist_state = dr.read_bits(dist_table.table_log() as usize)?;

    let dict_len = dict.len();
    let mut out = Vec::with_capacity(dict_len + raw_len);
    out.extend_from_slice(dict);
    let mut reps = [1usize, 1, 1];

    loop {
        let sym = litlen_table.decode_symbol(&mut litlen_state, &mut lr)?;
        if sym < 256 {
            out.push(sym as u8);
            if out.len() - dict_len > raw_len {
                return corrupt("block produced more data than declared");
            }
        } else if sym == EOB_SYMBOL {
            break;
        } else if sym < LITLEN_SYMBOLS as u16 {
            let lc = sym - LEN_SYMBOL_BASE;
            let lextra = er.read_bits(LENGTH_EXTRA_BITS[lc as usize] as usize)?;
            let length = LENGTH_BASE[lc as usize] as usize + lextra as usize;

            let dsym = dist_table.decode_symbol(&mut dist_state, &mut dr)?;
            let distance = if dsym < REP_SYMBOLS as u16 {
                decode_rep_symbol(&mut reps, dsym)
            } else {
                let idx = (dsym - REP_SYMBOLS as u16) as usize;
                let dextra = er.read_bits(V5_DIST_EXTRA_BITS[idx] as usize)?;
                let distance = V5_DIST_BASE[idx] as usize + dextra as usize;
                reps = [distance, reps[0], reps[1]];
                distance
            };

            if distance == 0 || distance > out.len() {
                return corrupt("match distance out of range");
            }
            let start = out.len() - distance;
            out.reserve(length);
            let mut remaining = length;
            while remaining > 0 {
                let available = out.len() - start;
                let n = remaining.min(available);
                let dst = out.len();
                out.resize(dst + n, 0);
                out.copy_within(start..start + n, dst);
                remaining -= n;
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

/// 压缩一个块，返回 `(块类型, 块数据)`。
///
/// 依次尝试动态 Huffman 与静态 Huffman，取较小者；若均不小于原始数据，
/// 则退化为存储块（`BTYPE_STORED`）。`fv` 决定距离字母表（V4 用 40 码、
/// V5 用 repcode + 扩展的 50 码）。
pub fn compress_block(
    dict: &[u8],
    data: &[u8],
    cfg: &MatchConfig,
    fv: FormatVersion,
) -> (u8, Vec<u8>) {
    if data.is_empty() {
        return (BTYPE_STORED, Vec::new());
    }

    // 按格式版本裁剪窗口上限：V4 保持 1 MiB，V5 扩展至 32 MiB。
    let window_limit = match fv {
        FormatVersion::V4 => MAX_DIST,
        FormatVersion::V5 => MAX_WINDOW_SIZE,
    };
    let mut cfg2 = *cfg;
    cfg2.window_size = cfg.window_size.min(window_limit);
    let cfg = &cfg2;

    // 最优解析：先用快速路径得到码长、构建代价模型，再用动态规划求最优令牌序列。
    let tokens = if cfg.optimal {
        let first = lz77::compress_block(dict, data, cfg);
        let (_, litlen_freqs, dist_freqs) = build_entries_and_freqs(&first, fv);
        let cm = lz77::CostModel::new(
            &huffman::compute_lengths(&litlen_freqs),
            &huffman::compute_lengths(&dist_freqs),
            fv,
        );
        lz77::compress_block_optimal(dict, data, cfg, &cm)
    } else {
        lz77::compress_block(dict, data, cfg)
    };

    // 拆分字母表：字面量/长度与距离各自独立统计频率与构建 Huffman 表。
    // V5 使用 FSE（tANS）熵编码；V4 沿用 Huffman。
    if fv == FormatVersion::V5 {
        let dynamic = encode_fse_dynamic(&tokens);
        let fixed = encode_fse_fixed(&tokens);
        let (btype, compressed) = match (dynamic, fixed) {
            (Some(d), Some(f)) if f.len() <= d.len() => (BTYPE_FSE_FIXED, f),
            (Some(d), _) => (BTYPE_FSE_DYNAMIC, d),
            (None, Some(f)) => (BTYPE_FSE_FIXED, f),
            (None, None) => (BTYPE_STORED, data.to_vec()),
        };
        if compressed.len() < data.len() {
            return (btype, compressed);
        }
        return (BTYPE_STORED, data.to_vec());
    }

    let (entries, mut litlen_freqs, dist_freqs) = build_entries_and_freqs(&tokens, fv);
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
    let fd = fixed_dist_lengths(fv);
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
/// `fv` 决定距离字母表；V5 下解码端对称维护最近 3 个距离以还原 repcode。
pub fn decompress_block(
    btype: u8,
    data: &[u8],
    raw_len: usize,
    dict: &[u8],
    fv: FormatVersion,
) -> Result<Vec<u8>> {
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
                    huffman::Decoder::new(&fixed_dist_lengths(fv))?,
                )
            } else {
                let litlen_lengths = huffman::read_lengths(&mut r, LITLEN_SYMBOLS)?;
                let dist_lengths = huffman::read_lengths(&mut r, dist_symbols(fv))?;
                (
                    huffman::Decoder::new(&litlen_lengths)?,
                    huffman::Decoder::new(&dist_lengths)?,
                )
            };

            let dict_len = dict.len();
            let mut out = Vec::with_capacity(dict_len + raw_len);
            out.extend_from_slice(dict);
            // V5 重复偏移状态（V4 不使用）。
            let mut reps = [1usize, 1, 1];

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
                    let distance = match fv {
                        FormatVersion::V4 => {
                            let dextra = r.read_bits(DIST_EXTRA_BITS[dc as usize] as usize)?;
                            DIST_BASE[dc as usize] as usize + dextra as usize
                        }
                        FormatVersion::V5 => {
                            if dc < REP_SYMBOLS as u16 {
                                decode_rep_symbol(&mut reps, dc)
                            } else {
                                let idx = (dc - REP_SYMBOLS as u16) as usize;
                                let dextra = r.read_bits(V5_DIST_EXTRA_BITS[idx] as usize)?;
                                let distance = V5_DIST_BASE[idx] as usize + dextra as usize;
                                reps = [distance, reps[0], reps[1]];
                                distance
                            }
                        }
                    };

                    if distance == 0 || distance > out.len() {
                        return corrupt("match distance out of range");
                    }
                    let start = out.len() - distance;
                    // 匹配拷贝：源是已产出字节，可能覆盖到尚未写出的位置（distance < length
                    // 时按周期重复）。先按 distance 分块，逐块用 `copy_within` 批量搬移
                    // （重叠安全），替代逐字节循环。
                    out.reserve(length);
                    let mut remaining = length;
                    while remaining > 0 {
                        let available = out.len() - start; // 已可从 start 读取的字节数
                        let n = remaining.min(available);
                        let dst = out.len();
                        out.resize(dst + n, 0);
                        out.copy_within(start..start + n, dst);
                        remaining -= n;
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
        BTYPE_FSE_DYNAMIC => decode_fse_block(data, raw_len, dict, false),
        BTYPE_FSE_FIXED => decode_fse_block(data, raw_len, dict, true),
        _ => corrupt(format!("unknown block type {btype}")),
    }
}

/// 有序生产者-消费者压缩流水线：按序号顺序回调每个块的压缩结果。
///
/// 与「等全部完成后统一写出」不同，这里在 [`std::thread::scope`] 内用有界
/// [`std::sync::mpsc::SyncSender`] 工作队列 + 原子序号重排：主线程（本函数调用者）
/// 按序号立即回调 `emit` 写出，从而让「压缩第 N+1 块」与「写出第 N 块」重叠；
/// 工作队列动态取活，也比分块静态切分具备更好的负载均衡。`threads <= 1` 或单块时
/// 退化为顺序压缩。每个块独立压缩（只共享只读字典 `dict`），结果与顺序压缩逐字节一致。
#[allow(clippy::too_many_arguments)]
pub fn compress_blocks_parallel_stream(
    dict: &[u8],
    blocks: &[Vec<u8>],
    cfg: &MatchConfig,
    threads: usize,
    fv: FormatVersion,
    emit: &mut dyn FnMut(usize, u8, Vec<u8>) -> crate::Result<()>,
) -> crate::Result<()> {
    let n = blocks.len();
    if n == 0 {
        return Ok(());
    }
    if n == 1 || threads <= 1 {
        for (i, b) in blocks.iter().enumerate() {
            let (bt, cd) = compress_block(dict, b, cfg, fv);
            emit(i, bt, cd)?;
        }
        return Ok(());
    }

    let threads = threads.min(n);

    std::thread::scope(|scope| -> crate::Result<()> {
        let (job_tx, job_rx) = std::sync::mpsc::sync_channel::<(usize, &[u8])>(threads);
        let (result_tx, result_rx) = std::sync::mpsc::channel::<(usize, (u8, Vec<u8>))>();

        // 工作线程：按需取块压缩，回传 (序号, 结果)。`Receiver` 不实现 `Clone`，
        // 用 `Arc<Mutex<Receiver>>` 让多个工作线程共享同一接收端（取活在锁内完成，
        // 取到后即释放锁再压缩）。
        let job_rx = std::sync::Arc::new(std::sync::Mutex::new(job_rx));
        for _ in 0..threads {
            let job_rx = std::sync::Arc::clone(&job_rx);
            let result_tx = result_tx.clone();
            scope.spawn(move || loop {
                let job = job_rx.lock().unwrap().recv();
                let (seq, block) = match job {
                    Ok(j) => j,
                    Err(_) => break,
                };
                let result = compress_block(dict, block, cfg, fv);
                if result_tx.send((seq, result)).is_err() {
                    break;
                }
            });
        }

        // 生产者线程：持续把 (序号, 块) 送入有界工作队列（队列满即背压）。
        scope.spawn(move || {
            for (seq, block) in blocks.iter().enumerate() {
                if job_tx.send((seq, block.as_slice())).is_err() {
                    break;
                }
            }
        });

        // 主线程：按序号重排（小顶堆语义的 BTreeMap）并立即回调写出。
        let mut reorder = std::collections::BTreeMap::new();
        let mut next = 0usize;
        while next < n {
            let (seq, result) = match result_rx.recv() {
                Ok(x) => x,
                Err(_) => {
                    return Err(crate::Error::Corrupt(
                        "compression worker channel closed".into(),
                    ))
                }
            };
            reorder.insert(seq, result);
            while let Some(r) = reorder.remove(&next) {
                emit(next, r.0, r.1)?;
                next += 1;
            }
        }
        Ok(())
    })
}

/// 并行压缩多个互不依赖的块，结果按输入顺序返回。
///
/// 等价于 [`compress_blocks_parallel_stream`] 的「收集到 Vec」形式，便于一次拿全结果。
/// 块数较少或 `threads <= 1` 时退化为顺序压缩。当前仅单元测试使用。
#[cfg(test)]
pub fn compress_blocks_parallel(
    dict: &[u8],
    blocks: &[Vec<u8>],
    cfg: &MatchConfig,
    threads: usize,
    fv: FormatVersion,
) -> Vec<(u8, Vec<u8>)> {
    let mut out = Vec::with_capacity(blocks.len());
    let _ = compress_blocks_parallel_stream(dict, blocks, cfg, threads, fv, &mut |_, bt, cd| {
        out.push((bt, cd));
        Ok(())
    });
    out
}

/// 并行解压多个互不依赖的块，结果按输入顺序返回。
///
/// `blocks` 为 `(块类型, 块数据, 原始长度)` 三元组；`dict` 为共享的预设字典。
/// 与 [`compress_blocks_parallel`] 一样使用 [`std::thread::scope`] 自实现并行，
/// 块数较少或 `threads <= 1` 时退化为顺序解压。当前仅单元测试使用。
#[cfg(test)]
pub fn decompress_blocks_parallel(
    dict: &[u8],
    blocks: &[(u8, Vec<u8>, usize)],
    threads: usize,
    fv: FormatVersion,
) -> Result<Vec<Vec<u8>>> {
    let n = blocks.len();
    if n == 0 {
        return Ok(Vec::new());
    }
    if n == 1 || threads <= 1 {
        return blocks
            .iter()
            .map(|(btype, data, raw_len)| decompress_block(*btype, data, *raw_len, dict, fv))
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
                    .map(|(btype, data, raw_len)| {
                        decompress_block(*btype, data, *raw_len, dict, fv)
                    })
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
        let (btype, block) = compress_block(&[], data, cfg, FormatVersion::V4);
        let out = decompress_block(btype, &block, data.len(), &[], FormatVersion::V4).unwrap();
        assert_eq!(out, data);
    }

    fn roundtrip_with_dict(dict: &[u8], data: &[u8], cfg: &MatchConfig) {
        let (btype, block) = compress_block(dict, data, cfg, FormatVersion::V4);
        let out = decompress_block(btype, &block, data.len(), dict, FormatVersion::V4).unwrap();
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
    fn roundtrip_overlapping_match_copy() {
        // 直接覆盖 distance < length 的重叠拷贝：周期为 distance 的数据会诱发
        // 大量小距离长匹配，走分块 copy_within 路径（含最后不足一个周期的部分块）。
        for distance in 1..=3usize {
            let data: Vec<u8> = (0..4096usize).map(|i| (i % distance) as u8).collect();
            roundtrip(&data, &MatchConfig::default());
        }
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
        let (btype, block) = compress_block(&[], &data, &cfg, FormatVersion::V4);
        let out = decompress_block(btype, &block, data.len(), &[], FormatVersion::V4).unwrap();
        assert_eq!(out, data);
        // 大距离匹配应带来可观的压缩收益（而非整块存储）。
        assert!(
            block.len() < data.len(),
            "expected compression from long-range match"
        );
    }

    #[test]
    fn roundtrip_long_distance_v5() {
        // > 1 MiB 距离：V5 大窗口应找到并编码远距离匹配（V4 无法覆盖该距离）。
        use crate::format::MAX_DIST;

        let unit: Vec<u8> = (0..50_000u32).map(|i| (i % 251) as u8).collect();
        let gap = MAX_DIST + 100_000; // 距离将超过 1 MiB
        let mut data = unit.clone();
        data.extend(std::iter::repeat_n(0xEEu8, gap));
        data.extend_from_slice(&unit);

        let cfg = MatchConfig {
            window_size: crate::format::MAX_WINDOW_SIZE,
            ..MatchConfig::default()
        };
        let (btype, block) = compress_block(&[], &data, &cfg, FormatVersion::V5);
        let out = decompress_block(btype, &block, data.len(), &[], FormatVersion::V5).unwrap();
        assert_eq!(out, data);
        assert!(
            block.len() < data.len(),
            "expected compression from long-distance match"
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
        let fd = fixed_dist_lengths(FormatVersion::V4);
        let fl_codes = huffman::build_canonical(&fl);
        let fd_codes = huffman::build_canonical(&fd);
        let mut w = BitWriter::new();
        write_symbol_stream(&mut w, &entries, &fl_codes, &fl, &fd_codes, &fd);
        let block = w.finish();

        let data = b"aaaa".to_vec();
        let out =
            decompress_block(BTYPE_FIXED, &block, data.len(), &[], FormatVersion::V4).unwrap();
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
            .map(|b| compress_block(&[], b, &cfg, FormatVersion::V4))
            .collect();
        let par = compress_blocks_parallel(&[], &blocks, &cfg, 4, FormatVersion::V4);
        assert_eq!(seq, par, "并行压缩必须与顺序压缩逐字节一致");

        let specs: Vec<_> = seq
            .iter()
            .map(|(t, d)| (*t, d.clone(), 10_000usize))
            .collect();
        let seq_out = decompress_blocks_parallel(&[], &specs, 1, FormatVersion::V4).unwrap();
        let par_out = decompress_blocks_parallel(&[], &specs, 4, FormatVersion::V4).unwrap();
        assert_eq!(seq_out, par_out, "并行解压必须与顺序解压一致");
        for (out, block) in par_out.iter().zip(&blocks) {
            assert_eq!(out, block);
        }
    }
    #[test]
    fn stream_pipeline_matches_sequential_in_order() {
        // 有序生产者-消费者流水线：结果必须按序号顺序回调，且与顺序压缩逐字节一致；
        // 多线程不改变输出。
        let cfg = MatchConfig::default();
        let mut blocks = Vec::new();
        let mut seed = 0x1234_5678u32;
        for _ in 0..24 {
            let mut b = vec![0u8; 5000];
            for x in b.iter_mut() {
                seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                *x = (seed >> 24) as u8;
            }
            blocks.push(b);
        }

        let seq: Vec<_> = blocks
            .iter()
            .map(|b| compress_block(&[], b, &cfg, FormatVersion::V4))
            .collect();

        for threads in [1usize, 2, 4, 8] {
            let mut streamed: Vec<(u8, Vec<u8>)> = Vec::new();
            let mut seen = 0usize;
            compress_blocks_parallel_stream(
                &[],
                &blocks,
                &cfg,
                threads,
                FormatVersion::V4,
                &mut |i, bt, cd| {
                    assert_eq!(i, seen, "回调必须按序号顺序，threads={threads}");
                    assert_eq!((bt, cd.clone()), seq[i]);
                    seen += 1;
                    streamed.push((bt, cd));
                    Ok(())
                },
            )
            .unwrap();
            assert_eq!(seen, blocks.len());
            assert_eq!(streamed, seq, "threads={threads} 不应改变输出");
        }
    }
}
