//! LZ77 匹配器：哈希链（3/4 字节）与二分树的贪心/惰性匹配，及最优解析（动态规划）。
//!
//! [`MatchFinder`] 提供三种查找器：
//! - `HashChain3` / `HashChain4`：哈希链，按 3 或 4 字节哈希分桶。
//! - `BinaryTree`：经典二分树，维护每个位置的左右儿子指针，搜索时沿树双向遍历，
//!   可找到比哈希链更长的匹配（高等级）。

use std::cell::RefCell;

use crate::format::{
    dist_code, dist_code_v5, length_code, FormatVersion, DIST_EXTRA_BITS, LENGTH_EXTRA_BITS,
    LEN_SYMBOL_BASE, LITLEN_SYMBOLS, MAX_MATCH, MAX_WINDOW_SIZE, MIN_MATCH, REP_SYMBOLS,
    V5_DIST_ALPHABET, V5_DIST_EXTRA_BITS,
};

/// 哈希桶数量（2^16）。
const HASH_BITS: usize = 16;
const HASH_SIZE: usize = 1 << HASH_BITS;

/// 最优解析时枚举候选的上限。
///
/// 动态规划本身已能充分探索「取当前匹配 vs 输出字面量后再取更长匹配」的选择空间，
/// 因此无需像贪心路径那样使用超大 `max_chain`；限制上限以控制最坏情况耗时。
const OPTIMAL_MAX_CHAIN: usize = 256;

/// 匹配查找器类型。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MatchFinder {
    /// 3 字节哈希链：最快，低等级（L1–L5）。
    HashChain3,
    /// 4 字节哈希链：哈希碰撞更少，中等级（L6）。
    HashChain4,
    /// 二分树：可搜索范围内的最长匹配，最高等级（L7–L9）。
    BinaryTree,
}

/// 可复用的工作缓冲区：避免每个块都重新 malloc「字典+数据」「哈希桶」「前驱链」。
///
/// 并行压缩时每个工作线程顺序处理多个块，用 [`SCRATCH`] 线程局部变量复用这些
/// 缓冲区，省掉逐块的分配与清零开销。
///
/// 3 字节与 4 字节哈希各持一套头表与前驱链：位置 `i` 满足 `i + 4 <= total` 时
/// 归入 4 字节表，仅剩 3 字节可用的末尾位置归入 3 字节表。二分树额外持有每个
/// 位置在树中的左右儿子指针。
struct Scratch {
    combined: Vec<u8>,
    head3: Vec<i32>,
    prev3: Vec<i32>,
    head4: Vec<i32>,
    prev4: Vec<i32>,
    smaller: Vec<i32>,
    larger: Vec<i32>,
}

impl Default for Scratch {
    fn default() -> Self {
        Scratch {
            combined: Vec::new(),
            head3: vec![-1i32; HASH_SIZE],
            prev3: Vec::new(),
            head4: vec![-1i32; HASH_SIZE],
            prev4: Vec::new(),
            smaller: Vec::new(),
            larger: Vec::new(),
        }
    }
}

thread_local! {
    static SCRATCH: RefCell<Scratch> = RefCell::new(Scratch::default());
}

/// 匹配器配置，由压缩级别映射而来。
#[derive(Clone, Copy, Debug)]
pub struct MatchConfig {
    /// 使用的查找器（3/4 字节哈希链，或二分树）。
    pub finder: MatchFinder,
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
            finder: MatchFinder::HashChain4,
            window_size: MAX_WINDOW_SIZE,
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
    match cfg.finder {
        MatchFinder::BinaryTree => compress_block_tree(dict, data, cfg),
        _ => compress_block_hash(dict, data, cfg),
    }
}

/// 哈希链路径：贪心/惰性匹配。
fn compress_block_hash(dict: &[u8], data: &[u8], cfg: &MatchConfig) -> Vec<Token> {
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
        sc.head3.fill(-1);
        sc.head4.fill(-1);
        sc.prev3.clear();
        sc.prev3.resize(total, -1);
        sc.prev4.clear();
        sc.prev4.resize(total, -1);

        let combined = &sc.combined;
        let head3 = &mut sc.head3;
        let prev3 = &mut sc.prev3;
        let head4 = &mut sc.head4;
        let prev4 = &mut sc.prev4;
        let window = cfg.window_size.min(MAX_WINDOW_SIZE);
        let use4 = cfg.finder != MatchFinder::HashChain3;

        let mut tokens = Vec::with_capacity(data.len() / 2 + 1);

        // 预先把字典中的位置插入哈希链，作为匹配候选。
        for i in 0..dict_len {
            insert_position(combined, i, total, use4, head3, prev3, head4, prev4);
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

            let (best_len, best_dist) = find_at(
                combined, i, total, use4, head3, prev3, head4, prev4, cfg, window,
            );

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
                    let (lp, dp) = find_at(
                        combined, p, total, use4, head3, prev3, head4, prev4, cfg, window,
                    );
                    if lp <= cur_len {
                        break;
                    }
                    // 当前字节降级为字面量并前进一步。
                    insert_position(combined, cur_pos, total, use4, head3, prev3, head4, prev4);
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
                    insert_position(
                        combined,
                        cur_pos + k,
                        total,
                        use4,
                        head3,
                        prev3,
                        head4,
                        prev4,
                    );
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
                    insert_position(combined, i + k, total, use4, head3, prev3, head4, prev4);
                }
                i += best_len;
            } else {
                tokens.push(Token::Literal(combined[i]));
                insert_position(combined, i, total, use4, head3, prev3, head4, prev4);
                i += 1;
            }
        }

        tokens
    })
}

/// 二分树路径：贪心/惰性匹配。
fn compress_block_tree(dict: &[u8], data: &[u8], cfg: &MatchConfig) -> Vec<Token> {
    SCRATCH.with(|cell| {
        let mut cell = cell.borrow_mut();
        let sc: &mut Scratch = &mut cell;
        let dict_len = dict.len();
        let total = dict_len + data.len();

        sc.combined.clear();
        sc.combined.extend_from_slice(dict);
        sc.combined.extend_from_slice(data);
        // 末尾填充 MAX_MATCH 字节，保证 tree_cmp 可对任意真实位置比较满长前缀。
        sc.combined.resize(sc.combined.len() + MAX_MATCH, 0);
        sc.head4.fill(-1);
        sc.smaller.clear();
        sc.smaller.resize(total, -1);
        sc.larger.clear();
        sc.larger.resize(total, -1);

        let combined = &sc.combined;
        let head = &mut sc.head4;
        let smaller = &mut sc.smaller;
        let larger = &mut sc.larger;
        let window = cfg.window_size.min(MAX_WINDOW_SIZE);

        let mut tokens = Vec::with_capacity(data.len() / 2 + 1);

        // 预先把字典中的位置插入二分树。
        for i in 0..dict_len {
            tree_insert(combined, i, total, head, smaller, larger);
        }

        let mut i = dict_len;
        let n = total;

        while i < n {
            if i + MIN_MATCH > n {
                tokens.push(Token::Literal(combined[i]));
                i += 1;
                continue;
            }

            let (best_len, best_dist) =
                tree_find_match(combined, i, total, head, smaller, larger, cfg, window);

            if cfg.lazy && best_len >= MIN_MATCH {
                let mut cur_pos = i;
                let mut cur_len = best_len;
                let mut cur_dist = best_dist;
                let mut steps = 0usize;

                while steps < cfg.max_lazy && cur_pos + MIN_MATCH < n {
                    let p = cur_pos + 1;
                    let (lp, dp) =
                        tree_find_match(combined, p, total, head, smaller, larger, cfg, window);
                    if lp <= cur_len {
                        break;
                    }
                    tree_insert(combined, cur_pos, total, head, smaller, larger);
                    tokens.push(Token::Literal(combined[cur_pos]));
                    cur_pos = p;
                    cur_len = lp;
                    cur_dist = dp;
                    steps += 1;
                }

                tokens.push(Token::Match {
                    length: cur_len,
                    distance: cur_dist,
                });
                for k in 0..cur_len {
                    tree_insert(combined, cur_pos + k, total, head, smaller, larger);
                }
                i = cur_pos + cur_len;
                continue;
            }

            if best_len >= MIN_MATCH {
                tokens.push(Token::Match {
                    length: best_len,
                    distance: best_dist,
                });
                for k in 0..best_len {
                    tree_insert(combined, i + k, total, head, smaller, larger);
                }
                i += best_len;
            } else {
                tokens.push(Token::Literal(combined[i]));
                tree_insert(combined, i, total, head, smaller, larger);
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

/// 计算位置 i 处四字节的哈希。
#[inline]
fn hash4(data: &[u8], i: usize) -> usize {
    let v = (data[i] as u32)
        | ((data[i + 1] as u32) << 8)
        | ((data[i + 2] as u32) << 16)
        | ((data[i + 3] as u32) << 24);
    (v.wrapping_mul(2_654_435_761) >> (32 - HASH_BITS)) as usize
}

/// 将位置 i 插入哈希链。
#[inline]
fn insert(i: usize, h: usize, head: &mut [i32], prev: &mut [i32]) {
    prev[i] = head[h];
    head[h] = i as i32;
}

/// 将位置 i 插入合适的哈希链（4 字节优先，末尾仅剩 3 字节时回退 3 字节）。
#[inline]
#[allow(clippy::too_many_arguments)]
fn insert_position(
    data: &[u8],
    i: usize,
    total: usize,
    use4: bool,
    head3: &mut [i32],
    prev3: &mut [i32],
    head4: &mut [i32],
    prev4: &mut [i32],
) {
    if i + MIN_MATCH > total {
        return;
    }
    if use4 && i + 4 <= total {
        insert(i, hash4(data, i), head4, prev4);
    } else {
        insert(i, hash3(data, i), head3, prev3);
    }
}

/// 读取位置 i 在对应哈希链中的前驱指针（`prev3`/`prev4` 二选一）。
#[inline]
fn prev_at(prev3: &[i32], prev4: &[i32], use4: bool, total: usize, i: usize) -> i32 {
    if use4 && i + 4 <= total {
        prev4[i]
    } else {
        prev3[i]
    }
}

/// 在位置 i 对应的哈希链中查找最长匹配，返回 (长度, 距离)。
#[inline]
#[allow(clippy::too_many_arguments)]
fn find_at(
    data: &[u8],
    i: usize,
    total: usize,
    use4: bool,
    head3: &[i32],
    prev3: &[i32],
    head4: &[i32],
    prev4: &[i32],
    cfg: &MatchConfig,
    window: usize,
) -> (usize, usize) {
    if use4 && i + 4 <= total {
        let h = hash4(data, i);
        find_match(data, i, h, head4, prev4, cfg, window)
    } else {
        let h = hash3(data, i);
        find_match(data, i, h, head3, prev3, cfg, window)
    }
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

/// 比较 `data[a..]` 与 `data[b..]` 的前 [`MAX_MATCH`] 字节。
///
/// 调用方保证 `data` 已在末尾填充 [`MAX_MATCH`] 字节，因此任意真实位置都可安全
/// 比较满 [`MAX_MATCH`] 字节，比较长度恒定、序一致（稳定总序）。返回
/// `(公共前缀长度, 序)`：序为 `-1` 表示 a 更小、`1` 表示更大；满长相等时按位置
/// 兜底定序。
#[inline]
fn tree_cmp(data: &[u8], a: usize, b: usize) -> (usize, i8) {
    let mut len = 0usize;
    // 按 8 字节逐块比较，加速长公共前缀的判定。
    while len + 8 <= MAX_MATCH {
        let wa = u64::from_le_bytes(data[a + len..a + len + 8].try_into().unwrap());
        let wb = u64::from_le_bytes(data[b + len..b + len + 8].try_into().unwrap());
        if wa != wb {
            let byte = ((wa ^ wb).trailing_zeros() / 8) as usize;
            return (
                len + byte,
                if data[a + len + byte] < data[b + len + byte] {
                    -1
                } else {
                    1
                },
            );
        }
        len += 8;
    }
    while len < MAX_MATCH && data[a + len] == data[b + len] {
        len += 1;
    }
    if len == MAX_MATCH {
        (len, if a < b { -1 } else { 1 })
    } else if data[a + len] < data[b + len] {
        (len, -1)
    } else {
        (len, 1)
    }
}
/// 将位置 i 插入二分树（仅当 `i + 4 <= total`，末尾不足 4 字节的位置不参与）。
///
/// 采用「最新者为根」策略（LZMA 经典做法）：`head[h]` 始终指向该哈希桶内最近
/// 插入的位置，搜索自根向下按「近 → 远」访问候选，同长度下天然优先命中更近的距离
/// （距离码更短）。插入时沿比较路径把旧树**尾插**切分为「小于 i」（less）与
/// 「大于 i」（greater）两棵子树，分别挂到 `smaller[i]` / `larger[i]`，对单调/全同
/// 退化语料切分在常数步内结束，避免朴素 BST 的 O(n) 链式插入。
#[inline]
fn tree_insert(
    data: &[u8],
    i: usize,
    total: usize,
    head: &mut [i32],
    smaller: &mut [i32],
    larger: &mut [i32],
) {
    if i + 4 > total {
        return;
    }
    let h = hash4(data, i);
    smaller[i] = -1;
    larger[i] = -1;

    let old = head[h];
    head[h] = i as i32;
    if old < 0 {
        return;
    }

    // 尾插切分：less/greater 分别维护「结果树的根」与「当前尾节点」，沿比较路径
    // 把旧树节点按序接到对应侧，保证切分结果仍是合法 BST。
    let mut less_root = -1i32;
    let mut less_tail = -1i32;
    let mut greater_root = -1i32;
    let mut greater_tail = -1i32;
    let mut cur = old;
    while cur >= 0 {
        let cand = cur as usize;
        let (_, ord) = tree_cmp(data, i, cand);
        if ord < 0 {
            // i < cand：cand 归入 greater（作为其左子链的尾）。
            if greater_tail < 0 {
                greater_root = cur;
            } else {
                smaller[greater_tail as usize] = cur;
            }
            greater_tail = cur;
            cur = smaller[cand];
        } else {
            // i >= cand：cand 归入 less（作为其右子链的尾）。
            if less_tail < 0 {
                less_root = cur;
            } else {
                larger[less_tail as usize] = cur;
            }
            less_tail = cur;
            cur = larger[cand];
        }
    }
    if less_tail >= 0 {
        larger[less_tail as usize] = -1;
    }
    if greater_tail >= 0 {
        smaller[greater_tail as usize] = -1;
    }
    smaller[i] = less_root;
    larger[i] = greater_root;
}

/// 在二分树中查找位置 i 的最长匹配，返回 (长度, 距离)。
#[inline]
#[allow(clippy::too_many_arguments)]
fn tree_find_match(
    data: &[u8],
    i: usize,
    total: usize,
    head: &[i32],
    smaller: &[i32],
    larger: &[i32],
    cfg: &MatchConfig,
    window: usize,
) -> (usize, usize) {
    if i + 4 > total {
        return (0, 0);
    }
    let max_len = MAX_MATCH.min(total - i);
    let h = hash4(data, i);
    let mut best_len = 0usize;
    let mut best_dist = 0usize;
    let mut chain = 0usize;
    let mut cur = head[h];

    while cur >= 0 && chain < cfg.max_chain {
        let cand = cur as usize;
        let dist = i - cand;
        let (raw_len, ord) = tree_cmp(data, i, cand);
        let len = raw_len.min(max_len);
        // 树自根（最远）向下（更近）遍历；同长度时保留更近的距离，得到「最长且最近」。
        if dist <= window && (len > best_len || (len == best_len && dist < best_dist)) {
            best_len = len;
            best_dist = dist;
        }
        cur = if ord < 0 { smaller[cand] } else { larger[cand] };
        chain += 1;
    }

    (best_len, best_dist)
}

/// 最优解析的「代价模型」：每个字面量/长度符号与距离符号的估计码长（位）。
///
/// 由首次快速解析得到的 Huffman 码长构建；未出现（码长为 0）的符号用保守的
/// 默认值兜底，避免其被误判为 0 代价。距离代价数组按 V5 符号数扩展，V4 仅使用
/// 前 [`DIST_SYMBOLS`] 项。
pub struct CostModel {
    litlen_bits: [u8; LITLEN_SYMBOLS],
    dist_bits: [u8; V5_DIST_ALPHABET],
    fv: FormatVersion,
}

impl CostModel {
    /// 由首次解析得到的码长构建代价模型。
    pub fn new(litlen_lengths: &[u8], dist_lengths: &[u8], fv: FormatVersion) -> Self {
        let mut litlen_bits = [8u8; LITLEN_SYMBOLS];
        let mut dist_bits = [6u8; V5_DIST_ALPHABET];
        for (sym, &l) in litlen_lengths.iter().enumerate() {
            if l > 0 {
                litlen_bits[sym] = l;
            }
        }
        for (sym, &l) in dist_lengths.iter().enumerate().take(V5_DIST_ALPHABET) {
            if l > 0 {
                dist_bits[sym] = l;
            }
        }
        CostModel {
            litlen_bits,
            dist_bits,
            fv,
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
        let (sym, dextra) = match self.fv {
            FormatVersion::V5 => {
                let dc = dist_code_v5(distance);
                (
                    (dc + REP_SYMBOLS as u16) as usize,
                    V5_DIST_EXTRA_BITS[dc as usize] as u32,
                )
            }
            FormatVersion::V4 => {
                let dc = dist_code(distance);
                (dc as usize, DIST_EXTRA_BITS[dc as usize] as u32)
            }
        };
        self.litlen_bits[lsym] as u32
            + LENGTH_EXTRA_BITS[lc as usize] as u32
            + self.dist_bits[sym] as u32
            + dextra
    }

    /// 匹配（长度 + 距离）在给定 rep 状态下的估计码长。
    ///
    /// 与 [`CostModel::match_cost`] 的区别在于：V5 下若 `distance` 命中 `reps` 中的
    /// 某个偏移，则按对应的 repcode 符号（0/1/2）计价，而非按完整距离码计价。这样
    /// 最优解析才能识别「复用最近偏移」的低成本，从而更愿意选择能命中 rep 的匹配。
    #[inline]
    fn match_cost_rep(&self, length: usize, distance: usize, reps: &[usize; 3]) -> u32 {
        let lc = length_code(length);
        let lsym = (LEN_SYMBOL_BASE + lc) as usize;
        let (sym, dextra) = match self.fv {
            FormatVersion::V5 => {
                if distance == reps[0] {
                    (0usize, 0u32)
                } else if distance == reps[1] {
                    (1usize, 0u32)
                } else if distance == reps[2] {
                    (2usize, 0u32)
                } else {
                    let dc = dist_code_v5(distance);
                    (
                        (dc + REP_SYMBOLS as u16) as usize,
                        V5_DIST_EXTRA_BITS[dc as usize] as u32,
                    )
                }
            }
            FormatVersion::V4 => {
                let dc = dist_code(distance);
                (dc as usize, DIST_EXTRA_BITS[dc as usize] as u32)
            }
        };
        self.litlen_bits[lsym] as u32
            + LENGTH_EXTRA_BITS[lc as usize] as u32
            + self.dist_bits[sym] as u32
            + dextra
    }
}

/// 模拟编码端的 repcode 更新：把 `distance` 按 zstd 语义并入最近距离数组。
///
/// 必须与 [`crate::codec::encode_rep_symbol`] 的更新逻辑保持一致（命中 rep0 不变、
/// rep1/rep2 提到首位、未命中则插入到首位并丢弃最旧者），否则代价模型会与实际
/// 编码产生偏差。这里独立实现是因为 lz77 模块不能反向依赖 codec。
#[inline]
fn update_reps(reps: &mut [usize; 3], distance: usize) {
    if distance == reps[0] {
        // 命中 rep0：数组不变。
    } else if distance == reps[1] {
        reps.swap(0, 1);
    } else if distance == reps[2] {
        let r = reps[2];
        reps[2] = reps[1];
        reps[1] = reps[0];
        reps[0] = r;
    } else {
        reps[2] = reps[1];
        reps[1] = reps[0];
        reps[0] = distance;
    }
}

/// 用动态规划求整块数据的「最小估计代价」令牌序列（最优解析）。
pub fn compress_block_optimal(
    dict: &[u8],
    data: &[u8],
    cfg: &MatchConfig,
    cm: &CostModel,
) -> Vec<Token> {
    match cfg.finder {
        MatchFinder::BinaryTree => compress_block_optimal_tree(dict, data, cfg, cm),
        _ => compress_block_optimal_hash(dict, data, cfg, cm),
    }
}

/// 哈希链路径的最优解析。
fn compress_block_optimal_hash(
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
        sc.head3.fill(-1);
        sc.head4.fill(-1);
        sc.prev3.clear();
        sc.prev3.resize(total, -1);
        sc.prev4.clear();
        sc.prev4.resize(total, -1);

        let combined = &sc.combined;
        let head3 = &mut sc.head3;
        let prev3 = &mut sc.prev3;
        let head4 = &mut sc.head4;
        let prev4 = &mut sc.prev4;
        let window = cfg.window_size.min(MAX_WINDOW_SIZE);
        let chain_limit = cfg.max_chain.min(OPTIMAL_MAX_CHAIN);
        let use4 = cfg.finder != MatchFinder::HashChain3;

        // 正向：把所有位置（含字典）插入哈希链，使 `prev[i]` 指向「同哈希且紧邻
        // 在其之前」的位置；反向 DP 时沿 `prev[i]` 即可枚举到所有小于 i 的候选。
        for i in 0..total {
            insert_position(combined, i, total, use4, head3, prev3, head4, prev4);
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
                let mut cur = prev_at(prev3, prev4, use4, total, i);
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
                    cur = prev_at(prev3, prev4, use4, total, cand);
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

/// 二分树路径的最优解析。
///
/// 与哈希链路径（反向 DP）不同，二分树在反向枚举「起始于当前位置的匹配」时会把
/// 尚未处理、位置更靠后的节点也纳入树中，无法简洁地仅枚举 `cand < i` 的候选。
/// 因此这里改为**正向 DP**：按位置递增逐步把「字典 + 已处理数据」插入二分树，使
/// 搜索位置 i 时树中恰好只含 `0..i` 之前的历史；枚举出的候选距离自然合法，且
/// 「最新者为根」保证同长度时优先命中最近距离。代价与回溯语义与反向 DP 完全对偶。
fn compress_block_optimal_tree(
    dict: &[u8],
    data: &[u8],
    cfg: &MatchConfig,
    cm: &CostModel,
) -> Vec<Token> {
    SCRATCH.with(|cell| {
        let mut cell = cell.borrow_mut();
        let sc: &mut Scratch = &mut cell;
        let dict_len = dict.len();
        let n = data.len();
        let total = dict_len + n;

        sc.combined.clear();
        sc.combined.extend_from_slice(dict);
        sc.combined.extend_from_slice(data);
        // 末尾填充 MAX_MATCH 字节，保证 tree_cmp 可对任意真实位置比较满长前缀。
        sc.combined.resize(sc.combined.len() + MAX_MATCH, 0);
        sc.head4.fill(-1);
        sc.smaller.clear();
        sc.smaller.resize(total, -1);
        sc.larger.clear();
        sc.larger.resize(total, -1);

        let combined = &sc.combined;
        let head = &mut sc.head4;
        let smaller = &mut sc.smaller;
        let larger = &mut sc.larger;
        let window = cfg.window_size.min(MAX_WINDOW_SIZE);
        let chain_limit = cfg.max_chain.min(OPTIMAL_MAX_CHAIN);

        // 预先把字典位置插入二分树，作为跨越字典/数据边界的候选历史。
        for i in 0..dict_len {
            tree_insert(combined, i, total, head, smaller, larger);
        }

        // 正向 DP：cost[k] = 编码 data[0..k] 的最小估计代价（位）。
        // prev_len[k] 记录「到达 k」的那一步匹配长度（0 = 字面量），
        // prev_dist[k] 记录对应距离；据此从 n 反向回溯出令牌序列。
        let mut cost = vec![u32::MAX; n + 1];
        let mut prev_len = vec![0u16; n + 1];
        let mut prev_dist = vec![0u32; n + 1];
        cost[0] = 0;

        // 每个位置「最优路径」所携带的最近 3 个距离（rep 状态）。初始与编码端一致
        // （见 `build_entries_and_freqs` 的 `reps = [1, 1, 1]`），用于让最优解析感知
        // repcode 命中时的低成本，从而更愿意复用最近偏移。
        let mut rep_state = vec![[1usize, 1, 1]; n + 1];

        // 复用「各匹配长度的最近距离」表；每轮只读取被 covered 覆盖的长度。
        let mut best_dist = [0u32; MAX_MATCH + 1];
        // 候选缓存：树自根（最远）向下（更近）遍历，先收集再逆序（近 → 远）填充，
        // 使同长度下优先保留最近距离（距离码更短）。
        let mut cand_len = [0u16; OPTIMAL_MAX_CHAIN];
        let mut cand_dist = [0u32; OPTIMAL_MAX_CHAIN];

        for k in 0..n {
            let i = dict_len + k;
            let max_len = MAX_MATCH.min(n - k);

            // 字面量转移：k -> k+1。
            let lit_cost = cm.literal_cost(combined[i]);
            if cost[k] + lit_cost < cost[k + 1] {
                cost[k + 1] = cost[k] + lit_cost;
                prev_len[k + 1] = 0;
                prev_dist[k + 1] = 0;
                rep_state[k + 1] = rep_state[k];
            }

            // 匹配转移：k -> k+len，枚举二分树中的候选（此时树内只含 < i 的位置）。
            if max_len >= MIN_MATCH && i + 4 <= total {
                let h = hash4(combined, i);
                let mut cur = head[h];
                let mut chain = 0usize;
                let mut ncand = 0usize;

                while cur >= 0 && chain < chain_limit {
                    let cand = cur as usize;
                    let (raw_len, ord) = tree_cmp(combined, i, cand);
                    let len = raw_len.min(max_len);
                    let dist = i - cand;
                    if dist <= window && len >= MIN_MATCH {
                        cand_len[ncand] = len as u16;
                        cand_dist[ncand] = dist as u32;
                        ncand += 1;
                    }
                    cur = if ord < 0 { smaller[cand] } else { larger[cand] };
                    chain += 1;
                }

                // 逆序（近 → 远）填充：先命中的（最近）距离胜出。
                let mut covered = MIN_MATCH - 1;
                for idx in (0..ncand).rev() {
                    let len = cand_len[idx] as usize;
                    let dist = cand_dist[idx] as usize;
                    if len > covered {
                        best_dist[(covered + 1)..=len].fill(dist as u32);
                        covered = len;
                    }
                }

                let cur_reps = rep_state[k];
                for len in MIN_MATCH..=covered {
                    let dist = best_dist[len] as usize;
                    let c = cost[k] + cm.match_cost_rep(len, dist, &cur_reps);
                    if c < cost[k + len] {
                        cost[k + len] = c;
                        prev_len[k + len] = len as u16;
                        prev_dist[k + len] = best_dist[len];
                        let mut reps = cur_reps;
                        update_reps(&mut reps, dist);
                        rep_state[k + len] = reps;
                    }
                }
            }

            // 处理完从 i 出发的转移后，把 i 插入树，供后续位置引用。
            tree_insert(combined, i, total, head, smaller, larger);
        }

        // 反向回溯令牌序列，再反转为正向顺序。
        let mut tokens = Vec::with_capacity(n / 2 + 1);
        let mut target = n;
        while target > 0 {
            let l = prev_len[target];
            if l == 0 {
                tokens.push(Token::Literal(combined[dict_len + target - 1]));
                target -= 1;
            } else {
                tokens.push(Token::Match {
                    length: l as usize,
                    distance: prev_dist[target] as usize,
                });
                target -= l as usize;
            }
        }
        tokens.reverse();
        tokens
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::{DIST_SYMBOLS, MAX_DIST};

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

    /// 统计令牌流中匹配覆盖的总字节数（衡量匹配质量）。
    fn matched_bytes(tokens: &[Token]) -> usize {
        tokens
            .iter()
            .map(|t| match t {
                Token::Match { length, .. } => *length,
                Token::Literal(_) => 0,
            })
            .sum()
    }

    /// 由快速令牌构建代价模型（与 codec 两趟逻辑一致）。
    fn build_cost_model(tokens: &[Token]) -> CostModel {
        use crate::format::EOB_SYMBOL;
        use crate::huffman;

        let mut litlen = vec![0u32; LITLEN_SYMBOLS];
        let mut dist = vec![0u32; DIST_SYMBOLS];
        for t in tokens {
            match t {
                Token::Literal(b) => litlen[*b as usize] += 1,
                Token::Match { length, distance } => {
                    litlen[(LEN_SYMBOL_BASE + length_code(*length)) as usize] += 1;
                    dist[dist_code(*distance) as usize] += 1;
                }
            }
        }
        litlen[EOB_SYMBOL as usize] += 1;
        CostModel::new(
            &huffman::compute_lengths(&litlen),
            &huffman::compute_lengths(&dist),
            FormatVersion::V4,
        )
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

    #[test]
    fn hash4_not_worse_than_hash3() {
        // 高重复语料上，4 字节哈希的碰撞更少，应能匹配到不少于 3 字节哈希的字节数。
        let mut data = Vec::new();
        for _ in 0..2000 {
            data.extend_from_slice(b"the quick brown fox jumps over the lazy dog. ");
        }

        let cfg3 = MatchConfig {
            finder: MatchFinder::HashChain3,
            ..MatchConfig::default()
        };
        let cfg4 = MatchConfig {
            finder: MatchFinder::HashChain4,
            ..MatchConfig::default()
        };

        let t3 = compress_block(&[], &data, &cfg3);
        let t4 = compress_block(&[], &data, &cfg4);
        assert!(
            matched_bytes(&t4) >= matched_bytes(&t3),
            "4 字节哈希应不劣于 3 字节哈希"
        );
        decode_tokens(&data, &t4);
    }

    #[test]
    fn hash3_hash4_roundtrip_random_and_repetitive() {
        // 两种哈希宽度都必须在随机/重复语料上无损往返。
        let mut repetitive = Vec::new();
        for _ in 0..300 {
            repetitive.extend_from_slice(b"aaaaabbbbbcccccddddd");
        }
        let mut seed = 0xdead_beefu32;
        let mut random = vec![0u8; 20000];
        for b in random.iter_mut() {
            seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            *b = (seed >> 16) as u8;
        }

        for finder in [MatchFinder::HashChain3, MatchFinder::HashChain4] {
            let cfg = MatchConfig {
                finder,
                ..MatchConfig::default()
            };
            for data in [&repetitive, &random] {
                let tokens = compress_block(&[], data, &cfg);
                decode_tokens(data, &tokens);
            }
        }
    }

    #[test]
    fn optimal_hash4_roundtrip() {
        let mut data = Vec::new();
        for _ in 0..1000 {
            data.extend_from_slice(b"optimal parsing over a repetitive corpus. ");
        }
        let cfg = MatchConfig {
            finder: MatchFinder::HashChain4,
            optimal: true,
            ..MatchConfig::default()
        };
        let first = compress_block(&[], &data, &cfg);
        let cm = build_cost_model(&first);
        let tokens = compress_block_optimal(&[], &data, &cfg, &cm);
        decode_tokens(&data, &tokens);
    }

    #[test]
    fn binary_tree_roundtrip_greedy_and_optimal() {
        let mut repetitive = Vec::new();
        for _ in 0..500 {
            repetitive.extend_from_slice(b"binary tree match finder test corpus. ");
        }
        let mut seed = 0x9e37_79b9u32;
        let mut random = vec![0u8; 12000];
        for b in random.iter_mut() {
            seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            *b = (seed >> 24) as u8;
        }

        let cfg = MatchConfig {
            finder: MatchFinder::BinaryTree,
            ..MatchConfig::default()
        };
        for data in [&repetitive, &random] {
            let tokens = compress_block(&[], data, &cfg);
            decode_tokens(data, &tokens);
        }

        // 最优解析 + 二分树路径。
        let cfg_opt = MatchConfig {
            finder: MatchFinder::BinaryTree,
            optimal: true,
            ..MatchConfig::default()
        };
        let first = compress_block(&[], &repetitive, &cfg_opt);
        let cm = build_cost_model(&first);
        let tokens = compress_block_optimal(&[], &repetitive, &cfg_opt, &cm);
        decode_tokens(&repetitive, &tokens);
    }

    #[test]
    fn binary_tree_not_worse_than_hash_chain() {
        // 高重复语料上二分树应找到不少于 4 字节哈希链的匹配字节数。
        let mut data = Vec::new();
        for _ in 0..1000 {
            data.extend_from_slice(b"aaaaabbbbbcccccdddddeeeeefffffggggghhhhh");
        }
        let hash_cfg = MatchConfig {
            finder: MatchFinder::HashChain4,
            max_chain: 64,
            nice_len: 258,
            ..MatchConfig::default()
        };
        let tree_cfg = MatchConfig {
            finder: MatchFinder::BinaryTree,
            max_chain: 64,
            nice_len: 258,
            ..MatchConfig::default()
        };
        let th = compress_block(&[], &data, &hash_cfg);
        let tt = compress_block(&[], &data, &tree_cfg);
        // 二分树与哈希链在重复语料上均能覆盖几乎全部字节；允许 1% 以内的小幅差异
        // （二者遍历候选的顺序不同，边角位置的匹配取舍可略有出入）。
        assert!(
            matched_bytes(&tt) * 100 >= matched_bytes(&th) * 99,
            "二分树应接近哈希链（tree={} hash={}）",
            matched_bytes(&tt),
            matched_bytes(&th)
        );
        decode_tokens(&data, &tt);
    }

    #[test]
    fn binary_tree_finds_long_range_match() {
        // 长距离重复：同一段独特数据在远处再次出现，二分树应找到长匹配。
        let unit: Vec<u8> = (0..30_000u32).map(|i| (i % 251) as u8).collect();
        let mut data = unit.clone();
        data.extend_from_slice(&[0xEEu8; 10_000]);
        data.extend_from_slice(&unit);

        let cfg = MatchConfig {
            finder: MatchFinder::BinaryTree,
            window_size: MAX_DIST,
            max_chain: 128,
            nice_len: 258,
            ..MatchConfig::default()
        };
        let tokens = compress_block(&[], &data, &cfg);
        decode_tokens(&data, &tokens);
        let max_match = tokens
            .iter()
            .filter_map(|t| match t {
                Token::Match { length, .. } => Some(*length),
                _ => None,
            })
            .max()
            .unwrap_or(0);
        assert!(max_match >= 258, "二分树应找到满长匹配，实际 {max_match}");
    }
}
