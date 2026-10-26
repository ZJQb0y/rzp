//! RZP 二进制格式常量与静态查找表。

/// 文件魔数："RZP"。
pub const MAGIC: [u8; 3] = *b"RZP";

/// 历史格式版本 4（只读兼容）。
pub const VERSION_V4: u8 = 4;
/// 格式版本 5（当前可写）。
pub const FORMAT_V5: u8 = 5;
/// 加密信封版本（与流版本解耦；信封布局保持 v4 不变）。
pub const ENVELOPE_VERSION: u8 = 4;
/// 当前格式版本（编码器默认产出）。
pub const VERSION: u8 = FORMAT_V5;

/// 格式版本。
///
/// 解码端对 [`FormatVersion::V4`] 永久只读兼容；编码端默认仅产出
/// [`FormatVersion::V5`]（在 M3 收尾阶段切换，此前通过开关回退 V4）。
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FormatVersion {
    /// 历史版本 4：只读兼容。
    V4 = 4,
    /// 版本 5：当前可写。
    V5 = 5,
}

impl FormatVersion {
    /// 由版本字节解析；未知版本返回 `None`。
    pub fn from_u8(v: u8) -> Option<FormatVersion> {
        match v {
            VERSION_V4 => Some(FormatVersion::V4),
            FORMAT_V5 => Some(FormatVersion::V5),
            _ => None,
        }
    }

    /// 返回版本字节。
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    /// 是否可由编码器写出。
    pub fn is_writable(self) -> bool {
        matches!(self, FormatVersion::V5)
    }
}

impl Default for FormatVersion {
    /// 编码器默认产出格式。
    fn default() -> Self {
        FormatVersion::V5
    }
}

/// 头大小（魔数 3 + 版本 1 + 级别 1 + 标志 1 + 保留 2）。
pub const HEADER_SIZE: usize = 8;
/// 块头大小（原始长度 4 + 压缩长度 4 + 结束标志 1 + 块类型 1）。
pub const BLOCK_HEADER_SIZE: usize = 10;
/// 尾部大小（crc32 4 + 原始总长 8）。
pub const FOOTER_SIZE: usize = 12;
/// 强校验摘要长度（BLAKE2b-256，字节）。
pub const BLAKE2B_DIGEST_SIZE: usize = 32;
/// 强校验尾部大小（blake2b 32 + 原始总长 8）。
pub const FOOTER_STRONG_SIZE: usize = BLAKE2B_DIGEST_SIZE + 8;

/// 头标志位 bit0：存在尾部（CRC + 总长）。
pub const FLAG_FOOTER: u8 = 0x01;
/// 头标志位 bit1：使用预设字典（头后紧随 4 字节字典 CRC-32）。
pub const FLAG_DICT: u8 = 0x02;
/// 头标志位 bit2：加密信封（仅出现在加密容器外层头）。
pub const FLAG_ENCRYPTED: u8 = 0x04;
/// 头标志位 bit3：负载为目录归档（解压后按目录树还原，而非单文件）。
pub const FLAG_DIR: u8 = 0x08;
/// 头标志位 bit4：尾部使用更强校验（BLAKE2b-256）而非 CRC-32。
pub const FLAG_BLAKE2B: u8 = 0x10;
/// 字典 CRC-32 的大小（字节）。
pub const DICT_CRC_SIZE: usize = 4;

/// 由头标志位计算尾部大小（强校验 40 字节，普通 CRC 12 字节）。
pub const fn footer_size(flags: u8) -> usize {
    if flags & FLAG_BLAKE2B != 0 {
        FOOTER_STRONG_SIZE
    } else {
        FOOTER_SIZE
    }
}

/// 加密信封外层头大小（magic 3 + 版本 1 + 级别 1 + 标志 1 + KDF 标识 1 +
/// AEAD 标识 1 + m_cost 4 + t_cost 4 + p_cost 4 + KCV 8）。
pub const ENC_HEADER_SIZE: usize = 28;
/// KDF 盐长度（字节）。
pub const SALT_LEN: usize = 16;
/// ChaCha20-Poly1305 基础 nonce 长度（字节）。
pub const NONCE_LEN: usize = 12;
/// Poly1305 认证标签长度（字节）。
pub const TAG_LEN: usize = 16;
/// 密钥校验值（KCV）长度（字节）：用于快速拒绝错误密码。
pub const KCV_LEN: usize = 8;

/// 加密信封 KDF 标识：Argon2id。
pub const KDF_ARGON2ID: u8 = 1;
/// 加密信封 AEAD 标识：ChaCha20-Poly1305（分块流式）。
pub const AEAD_CHACHA20_POLY1305: u8 = 1;

/// 流式加密的分块大小（明文，字节）。
pub const AEAD_CHUNK_SIZE: usize = 1 << 20;

/// 默认 Argon2id 内存成本（KiB，64 MiB，RFC 9106 第二推荐）。
pub const ARGON2_DEFAULT_MEMORY_KIB: u32 = 64 * 1024;
/// 默认 Argon2id 时间成本（迭代次数）。
pub const ARGON2_DEFAULT_ITERATIONS: u32 = 3;
/// 默认 Argon2id 并行度（车道数）。
pub const ARGON2_DEFAULT_LANES: u32 = 4;
/// 允许的 Argon2id 内存成本上限（KiB，2 GiB，防恶意归档 DoS）。
pub const ARGON2_MAX_MEMORY_KIB: u32 = 2 * 1024 * 1024;
/// 允许的 Argon2id 时间成本上限。
pub const ARGON2_MAX_ITERATIONS: u32 = 1024;
/// 允许的 Argon2id 并行度上限。
pub const ARGON2_MAX_LANES: u32 = 256;

/// 块类型：直接存储。
pub const BTYPE_STORED: u8 = 0;
/// 块类型：LZ77 + 动态 Huffman 压缩。
pub const BTYPE_COMPRESSED: u8 = 1;
/// 块类型：LZ77 + 静态（固定）Huffman 压缩，无需在块内发送码长。
pub const BTYPE_FIXED: u8 = 2;

/// 块类型：LZ77 + 动态 FSE（tANS）压缩（V5）。
pub const BTYPE_FSE_DYNAMIC: u8 = 3;
/// 块类型：LZ77 + 静态（固定）FSE 压缩，块内不发送归一化计数（V5）。
pub const BTYPE_FSE_FIXED: u8 = 4;

/// 最大/默认块大小（未压缩）。
pub const BLOCK_SIZE: usize = 1_048_576;
/// 允许的最大块大小上限（供解压端健壮性校验，防恶意超大块）。
pub const MAX_BLOCK_SIZE: usize = 64 * 1024 * 1024;

/// 最小匹配长度。
pub const MIN_MATCH: usize = 3;
/// 最大匹配长度。
pub const MAX_MATCH: usize = 258;
/// 最大回溯距离（V4 的 1 MiB 窗口）。
pub const MAX_DIST: usize = 1_048_576;
/// V5 的最大回溯距离（32 MiB 窗口）。
pub const MAX_WINDOW_SIZE: usize = 32 * 1024 * 1024;

/// Huffman 码最大长度（位）。
pub const MAX_BITS: usize = 15;

/// 块结束标记（字面量/长度表内的 EOB 符号）。
pub const EOB_SYMBOL: u16 = 256;
/// 长度码起始符号（257..=285，共 29 个）。
pub const LEN_SYMBOL_BASE: u16 = 257;
/// 字面量/长度表大小：256 字面量 + 1 EOB + 29 长度码。
pub const LITLEN_SYMBOLS: usize = 286;
/// 距离表大小：40 个距离码（覆盖 1..=MAX_DIST）。
pub const DIST_SYMBOLS: usize = 40;
/// V5 距离表大小：50 个距离码（覆盖 1..=MAX_WINDOW_SIZE）。
pub const V5_DIST_SYMBOLS: usize = 50;

/// V5 距离字母表中的重复偏移符号数（rep0/rep1/rep2）。
pub const REP_SYMBOLS: usize = 3;
/// V5 距离字母表总大小：3 个重复偏移 + 50 个字面量距离码。
pub const V5_DIST_ALPHABET: usize = REP_SYMBOLS + V5_DIST_SYMBOLS;

/// 每个长度码对应的额外位数。
pub const LENGTH_EXTRA_BITS: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];

/// 每个长度码对应的基准长度。
pub const LENGTH_BASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];

/// 每个距离码对应的额外位数。
pub const DIST_EXTRA_BITS: [u8; 40] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13, 14, 14, 15, 15, 16, 16, 17, 17, 18, 18,
];

/// 每个距离码对应的基准距离。
pub const DIST_BASE: [u32; 40] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577, 32769, 49153, 65537, 98305, 131073, 196609,
    262145, 393217, 524289, 786433,
];

/// V5 每个距离码对应的额外位数（沿 V4 几何增长规律扩展到额外位 23，覆盖 2^25）。
pub const V5_DIST_EXTRA_BITS: [u8; 50] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13, 14, 14, 15, 15, 16, 16, 17, 17, 18, 18, 19, 19, 20, 20, 21, 21, 22, 22, 23, 23,
];

/// V5 每个距离码对应的基准距离。
pub const V5_DIST_BASE: [u32; 50] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577, 32769, 49153, 65537, 98305, 131073, 196609,
    262145, 393217, 524289, 786433, 1048577, 1572865, 2097153, 3145729, 4194305, 6291457, 8388609,
    12582913, 16777217, 25165825,
];

/// 由匹配长度（3..=258）查找长度码（0..=28）。
pub fn length_code(len: usize) -> u16 {
    debug_assert!((MIN_MATCH..=MAX_MATCH).contains(&len));
    // 长度 258 使用最后一个码（0 额外位），比用码 27 + 5 额外位更省。
    if len == MAX_MATCH {
        return 28;
    }
    let mut code = 0u16;
    while len as u16
        > LENGTH_BASE[code as usize] + ((1 << LENGTH_EXTRA_BITS[code as usize]) - 1) as u16
    {
        code += 1;
    }
    code
}

/// 由距离（1..=MAX_DIST）查找距离码（0..=DIST_SYMBOLS-1）。
pub fn dist_code(dist: usize) -> u16 {
    debug_assert!((1..=MAX_DIST).contains(&dist));
    let mut code = 0u16;
    while code < (DIST_SYMBOLS - 1) as u16
        && dist as u32 > DIST_BASE[code as usize] + ((1u32 << DIST_EXTRA_BITS[code as usize]) - 1)
    {
        code += 1;
    }
    code
}

/// 由距离（1..=MAX_WINDOW_SIZE）查找 V5 距离码（0..=V5_DIST_SYMBOLS-1）。
pub fn dist_code_v5(dist: usize) -> u16 {
    debug_assert!((1..=MAX_WINDOW_SIZE).contains(&dist));
    let mut code = 0u16;
    while code < (V5_DIST_SYMBOLS - 1) as u16
        && dist as u32
            > V5_DIST_BASE[code as usize] + ((1u32 << V5_DIST_EXTRA_BITS[code as usize]) - 1)
    {
        code += 1;
    }
    code
}
