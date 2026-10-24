//! LZ77 匹配器：基于哈希链的贪心/惰性匹配。

use std::cell::RefCell;

use crate::format::{
    dist_code, length_code, DIST_EXTRA_BITS, DIST_SYMBOLS, LENGTH_EXTRA_BITS, LEN_SYMBOL_BASE,
    LITLEN_SYMBOLS, MAX_DIST, MAX_MATCH, MIN_MATCH,
};

/// 哈希桶数量（2^16）。
const HASH_BITS: usize = 16;
const HASH_SIZE: usize = 1 << HASH_BITS;

/// 最优解析时枚举哈希链候选的上限。
///
/// 动态规划本身已能充分探索「取当前匹配 vs 输出字面量后再取更长匹配」的选择空间，
/// 因此无需像贪心路径那样使用超大 `max_chain`；限制上限以控制最坏情况耗时。
const OPTIMAL_MAX_CHAIN: usize = 256;

/// 可复用的工作缓冲区：避免每个块都重新 malloc「字典+数据」「哈希桶」「前驱链」。
///
/// 并行压缩时每个工作线程顺序处理多个块，用 [`SCRATCH`] 线程局部变量复用这些
/// 缓冲区，省掉逐块的分配与清零开销。
struct Scratch {
    combined: Vec<u8>,
    head: Vec<i32>,
    prev: Vec<i32>,
}

impl Default for Scratch {
    fn default() -> Self {
        Scratch {
            combined: Vec::new(),
            head: vec![-1i32; HASH_SIZE],
            prev: Vec::new(),
        }
    }
}

thread_local! {
    static SCRATCH: RefCell<Scratch> = RefCell::new(Scratch::default());
}

/// 匹配器配置，由压缩级别映射而来。
#[derive(Clone, Copy, Debug)]
pub struct MatchConfig {
    /// 最大回溯距离。
    pub window_size: usize,
    /// 哈希链搜索上限（越大越慢、匹配越好）。
    pub max_chain: usize,
    /// 达到该匹配长度即提前停止搜索。
    pub nice_len: usize,
    /// 是否启用惰性匹配。
    pub lazy: bool,
    /// 惰性匹配向前搜索的最大步数（`lazy` 为真时生效）。
    pub max_lazy: usize,
    /// 是否启用最优解析（动态规划，仅高等级）。为真时编码端走两趟：
    /// 先用快速路径建代价模型，再用动态规划求最优令牌序列。
    pub optimal: bool,
}

impl Default for MatchConfig {
    fn default() -> Self {
        MatchConfig {
            window_size: MAX_DIST,
            max_chain: 128,
            nice_len: 128,
            lazy: true,
            max_lazy: 8,
            optimal: false,
        }
    }
}

/// LZ77 输出令牌。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Token {
    Literal(u8),
    Match { length: usize, distance: usize },
}

/// 对一整块数据进行 LZ77 编码，返回令牌序列。
///
/// `dict` 是作为「前置历史」参与匹配的预设字典：其中的内容不产生输出令牌，
/// 但可作为匹配候选，使距离指向字典（从而跨越字典/数据边界）。
pub fn compress_block(dict: &[u8], data: &[u8], cfg: &MatchConfig) -> Vec<Token> {
    SCRATCH.with(|cell| {
        let mut cell = cell.borrow_mut();
        // 经 `&mut Scratch` 重借用，使不同字段的借用可被借用检查器区分。
        let sc: &mut Scratch = &mut cell;
        let dict_len = dict.len();
        let total = dict_len + data.len();

        // 合并字典与数据，便于统一索引（复用线程局部缓冲区，避免逐块分配）。
        sc.combined.clear();
        sc.combined.extend_from_slice(dict);
        sc.combined.extend_from_slice(data);
        sc.head.fill(-1);
        sc.prev.clear();
        sc.prev.resize(total, -1);

        let combined = &sc.combined;
        let head = &mut sc.head;
        let prev = &mut sc.prev;
        let window = cfg.window_size.min(MAX_DIST);

        let mut tokens = Vec::with_capacity(data.len() / 2 + 1);

        // 预先把字典中的位置插入哈希链，作为匹配候选。
        for i in 0..dict_len {
            if i + MIN_MATCH <= total {
                insert(i, hash3(combined, i), head, prev);
            }
        }

        let mut i = dict_len;
        let n = total;

        while i < n {
            // 剩余不足一个最小匹配时，直接输出字面量。
            if i + MIN_MATCH > n {
                tokens.push(Token::Literal(combined[i]));
                i += 1;
                continue;
            }

            let h = hash3(combined, i);
            let (best_len, best_dist) = find_match(combined, i, h, head, prev, cfg, window);

            // 标准惰性匹配：仅当「前进一步能匹配得更长」时，才把当前字节降级为
            // 字面量并前进一步；最多推进 `max_lazy` 步，避免无界地追逐更长的匹配。
            // （原先的多步跳跃会一次性把中间若干字节按字面量输出、跳去取远处更长
            //   的匹配，忽略这些字面量的编码成本，导致高等级压缩率反而劣化。）
            if cfg.lazy && best_len >= MIN_MATCH {
                let mut cur_pos = i;
                let mut cur_len = best_len;
                let mut cur_dist = best_dist;
                let mut steps = 0usize;

                while steps < cfg.max_lazy && cur_pos + MIN_MATCH < n {
                    let p = cur_pos + 1;
                    let hp = hash3(combined, p);
                    let (lp, dp) = find_match(combined, p, hp, head, prev, cfg, window);
                    if lp <= cur_len {
                        break;
                    }
                    // 当前字节降级为字面量并前进一步。
                    let hk = hash3(combined, cur_pos);
                    insert(cur_pos, hk, head, prev);
                    tokens.push(Token::Literal(combined[cur_pos]));
                    cur_pos = p;
                    cur_len = lp;
                    cur_dist = dp;
                    steps += 1;
                }

                // 输出最终匹配，并把匹配覆盖范围内的每个位置插入哈希表。
                tokens.push(Token::Match {
                    length: cur_len,
                    distance: cur_dist,
                });
                for k in 0..cur_len {
                    if cur_pos + k + MIN_MATCH <= n {
                        let hh = hash3(combined, cur_pos + k);
                        insert(cur_pos + k, hh, head, prev);
                    }
                }
                i = cur_pos + cur_len;
                continue;
            }

            if best_len >= MIN_MATCH {
                tokens.push(Token::Match {
                    length: best_len,
                    distance: best_dist,
                });
                // 将匹配覆盖范围内的每个位置插入哈希表。
                for k in 0..best_len {
                    if i + k + MIN_MATCH <= n {
                        let hh = hash3(combined, i + k);
                        insert(i + k, hh, head, prev);
                    }
                }
                i += best_len;
            } else {
                tokens.push(Token::Literal(combined[i]));
                insert(i, h, head, prev);
                i += 1;
            }
        }

        tokens
    })
}

/// 计算位置 i 处三字节的哈希。
#[inline]
fn hash3(data: &[u8], i: usize) -> usize {
    let v = (data[i] as u32) | ((data[i + 1] as u32) << 8) | ((data[i + 2] as u32) << 16);
    (v.wrapping_mul(2_654_435_761) >> (32 - HASH_BITS)) as usize
}

/// 将位置 i 插入哈希链。
#[inline]
fn insert(i: usize, h: usize, head: &mut [i32], prev: &mut [i32]) {
    prev[i] = head[h];
    head[h] = i as i32;
}

/// 在哈希链中查找位置 i 的最长匹配，返回 (长度, 距离)。
#[inline]
fn find_match(
    data: &[u8],
    i: usize,
    h: usize,
    head: &[i32],
    prev: &[i32],
    cfg: &MatchConfig,
    window: usize,
) -> (usize, usize) {
    let mut best_len = 0usize;
    let mut best_dist = 0usize;
    let max_len = MAX_MATCH.min(data.len() - i);
    let mut chain = 0usize;
    let mut cur = head[h];

    while cur >= 0 && chain < cfg.max_chain {
        let cand = cur as usize;
        let dist = i - cand;
        if dist > window {
            break; // 链上后续候选更远。
        }
        // 快速判断：至少前几个字节相同再继续。
        if best_len < max_len
            && data[cand + best_len] == data[i + best_len]
            && data[cand] == data[i]
            && data[cand + 1] == data[i + 1]
        {
            // 逐字节扩展匹配。
            let mut l = 2;
            while l < max_len && data[cand + l] == data[i + l] {
                l += 1;
            }
            if l > best_len {
                best_len = l;
                best_dist = dist;
                if best_len >= cfg.nice_len {
                    break;
                }
            }
        }
        cur = prev[cand];
        chain += 1;
    }

    (best_len, best_dist)
}

/// 最优解析的「代价模型」：每个字面量/长度符号与距离符号的估计码长（位）。
///
/// 由首次快速解析得到的 Huffman 码长构建；未出现（码长为 0）的符号用保守的
/// 默认值兜底，避免其被误判为 0 代价。
pub struct CostModel {
    litlen_bits: [u8; LITLEN_SYMBOLS],
    dist_bits: [u8; DIST_SYMBOLS],
}

impl CostModel {
    /// 由首次解析得到的码长构建代价模型。
    pub fn new(litlen_lengths: &[u8], dist_lengths: &[u8]) -> Self {
        let mut litlen_bits = [8u8; LITLEN_SYMBOLS];
        let mut dist_bits = [6u8; DIST_SYMBOLS];
        for (sym, &l) in litlen_lengths.iter().enumerate() {
            if l > 0 {
                litlen_bits[sym] = l;
            }
        }
        for (sym, &l) in dist_lengths.iter().enumerate() {
            if l > 0 {
                dist_bits[sym] = l;
            }
        }
        CostModel {
            litlen_bits,
            dist_bits,
        }
    }

    /// 字面量的估计码长。
    #[inline]
    fn literal_cost(&self, b: u8) -> u32 {
        self.litlen_bits[b as usize] as u32
    }

    /// 匹配（长度 + 距离）的估计码长。
    #[inline]
    fn match_cost(&self, length: usize, distance: usize) -> u32 {
        let lc = length_code(length);
        let lsym = (LEN_SYMBOL_BASE + lc) as usize;
        let dc = dist_code(distance);
        self.litlen_bits[lsym] as u32
            + LENGTH_EXTRA_BITS[lc as usize] as u32
            + self.dist_bits[dc as usize] as u32
            + DIST_EXTRA_BITS[dc as usize] as u32
    }
}

/// 用动态规划求整块数据的「最小估计代价」令牌序列（最优解析）。
///
/// 先正向把「字典 + 数据」全部位置插入哈希链，再反向 DP：对每个位置枚举所有
/// 候选匹配长度，选择使 `字面量/匹配` 组合总代价最小的解析。代价由 [`CostModel`]
/// 提供（位数为单位）。
pub fn compress_block_optimal(
    dict: &[u8],
    data: &[u8],
    cfg: &MatchConfig,
    cm: &CostModel,
) -> Vec<Token> {
    SCRATCH.with(|cell| {
        let mut cell = cell.borrow_mut();
        let sc: &mut Scratch = &mut cell;
        let dict_len = dict.len();
        let total = dict_len + data.len();

        sc.combined.clear();
        sc.combined.extend_from_slice(dict);
        sc.combined.extend_from_slice(data);
        sc.head.fill(-1);
        sc.prev.clear();
        sc.prev.resize(total, -1);

        let combined = &sc.combined;
        let head = &mut sc.head;
        let prev = &mut sc.prev;
        let window = cfg.window_size.min(MAX_DIST);
        let chain_limit = cfg.max_chain.min(OPTIMAL_MAX_CHAIN);

        // 正向：把所有位置（含字典）插入哈希链，使 `prev[i]` 指向「同哈希且紧邻
        // 在其之前」的位置；反向 DP 时沿 `prev[i]` 即可枚举到所有小于 i 的候选。
        for i in 0..total {
            if i + MIN_MATCH <= total {
                insert(i, hash3(combined, i), head, prev);
            }
        }

        let n = data.len();
        let mut cost = vec![u32::MAX; n + 1];
        let mut choice_len = vec![0u16; n];
        let mut choice_dist = vec![0u32; n];
        cost[n] = 0;

        // 复用「各匹配长度的最近距离」表；每轮只读取被 `covered` 覆盖的长度。
        let mut best_dist = [0u32; MAX_MATCH + 1];

        // 反向 DP：cost[k] = 从 data[k..] 到结尾的最小估计代价。
        for k in (0..n).rev() {
            let i = dict_len + k;
            let max_len = MAX_MATCH.min(n - k);

            // 默认：输出一个字面量。
            let mut best = cm.literal_cost(combined[i]) + cost[k + 1];
            let mut best_len = 0u16;
            let mut best_d = 0u32;

            if max_len >= MIN_MATCH {
                let mut cur = prev[i];
                let mut chain = 0usize;
                let mut covered = MIN_MATCH - 1;

                while cur >= 0 && chain < chain_limit && covered < max_len {
                    let cand = cur as usize;
                    let dist = i - cand;
                    if dist > window {
                        break;
                    }
                    // 快速拒绝：前两字节或「已覆盖长度处」不匹配，则无法更长。
                    if combined[cand] == combined[i]
                        && combined[cand + 1] == combined[i + 1]
                        && combined[cand + covered] == combined[i + covered]
                    {
                        let mut l = 2;
                        while l < max_len && combined[cand + l] == combined[i + l] {
                            l += 1;
                        }
                        if l > covered {
                            best_dist[(covered + 1)..=l].fill(dist as u32);
                            covered = l;
                        }
                    }
                    cur = prev[cand];
                    chain += 1;
                }

                // 在所有枚举到的匹配长度中选代价最小者。
                for len in MIN_MATCH..=covered {
                    let c = cm.match_cost(len, best_dist[len] as usize) + cost[k + len];
                    if c < best {
                        best = c;
                        best_len = len as u16;
                        best_d = best_dist[len];
                    }
                }
            }

            cost[k] = best;
            choice_len[k] = best_len;
            choice_dist[k] = best_d;
        }

        // 正向回溯，输出令牌序列。
        let mut tokens = Vec::with_capacity(n / 2 + 1);
        let mut k = 0;
        while k < n {
            let l = choice_len[k];
            if l == 0 {
                tokens.push(Token::Literal(combined[dict_len + k]));
                k += 1;
            } else {
                tokens.push(Token::Match {
                    length: l as usize,
                    distance: choice_dist[k] as usize,
                });
                k += l as usize;
            }
        }

        tokens
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_tokens(data: &[u8], tokens: &[Token]) -> Vec<u8> {
        let mut out = Vec::new();
        for t in tokens {
            match *t {
                Token::Literal(b) => out.push(b),
                Token::Match { length, distance } => {
                    let start = out.len() - distance;
                    for k in 0..length {
                        let b = out[start + k];
                        out.push(b);
                    }
                }
            }
        }
        assert_eq!(out, data, "token stream must reproduce input");
        out
    }

    #[test]
    fn roundtrip_repetitive() {
        let mut data = Vec::new();
        for _ in 0..1000 {
            data.extend_from_slice(b"hello world, this is a test of rzp compression. ");
        }
        let cfg = MatchConfig::default();
        let tokens = compress_block(&[], &data, &cfg);
        decode_tokens(&data, &tokens);
    }

    #[test]
    fn roundtrip_random() {
        // 伪随机数据（低压缩率，但必须无损）。
        let mut seed = 0x1234_5678u32;
        let mut data = vec![0u8; 10000];
        for b in data.iter_mut() {
            seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            *b = (seed >> 24) as u8;
        }
        let tokens = compress_block(&[], &data, &MatchConfig::default());
        decode_tokens(&data, &tokens);
    }

    #[test]
    fn roundtrip_small_and_edge() {
        for len in 0..64usize {
            let data: Vec<u8> = (0..len).map(|x| (x * 7 % 251) as u8).collect();
            let tokens = compress_block(&[], &data, &MatchConfig::default());
            decode_tokens(&data, &tokens);
        }
    }

    #[test]
    fn dict_enables_match_into_history() {
        // 数据恰好是字典的后缀，应产生一个跨越边界的匹配，而非全字面量。
        let phrase = b"the quick brown fox jumps over the lazy dog. ";
        let dict: Vec<u8> = phrase.repeat(100);
        let data = phrase.to_vec();

        let tokens = compress_block(&dict, &data, &MatchConfig::default());
        let match_count = tokens
            .iter()
            .filter(|t| matches!(t, Token::Match { .. }))
            .count();
        assert!(match_count > 0, "字典应提供可引用的匹配: {tokens:?}");
    }
}
