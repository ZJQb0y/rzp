//! # RZP —— 从零实现的流式压缩格式
//!
//! RZP 是一套完全从零实现的文件压缩方案，具备：
//!
//! - **压缩/解压**：LZ77 匹配 + 限长规范 Huffman 熵编码。
//! - **完整性校验**：流尾部携带校验和（默认 CRC-32，可选 BLAKE2b-256），解码结束自动校验。
//! - **密码加密**：ChaCha20-Poly1305 AEAD + Argon2id KDF 加密信封（含 KCV 快速口令拒绝）。
//! - **压缩级别**：0（仅存储）到 9（最慢最强），见 [`Level`]。
//! - **流式处理**：[`Encoder`] 实现 `Write`、[`Decoder`] 实现 `Read`。
//! - **标准格式**：固定魔数 + 版本 + 分块 + 尾部，详见格式规范。
//!
//! ## 示例
//!
//! ```
//! use rzp::{compress, decompress, Level};
//!
//! let data = b"hello world, hello world, hello world";
//! let packed = compress(data, Level::L6);
//! let restored = decompress(&packed).unwrap();
//! assert_eq!(restored, data);
//! ```

pub mod archive;
mod bitio;
mod codec;
mod crc32;
mod crypto;
mod error;
mod format;
mod fse;
mod huffman;
mod lz77;
mod stream;
mod xattr;

pub use error::{Error, Result};
pub use format::{
    FormatVersion, ARGON2_DEFAULT_ITERATIONS, ARGON2_DEFAULT_LANES, ARGON2_DEFAULT_MEMORY_KIB,
    ARGON2_MAX_ITERATIONS, ARGON2_MAX_LANES, ARGON2_MAX_MEMORY_KIB, BLOCK_SIZE, MAX_BLOCK_SIZE,
    VERSION,
};
pub use stream::{Decoder, Encoder, EncoderStats};

/// 流式解密器（读侧）：从 v4 信封逐块解密并认证。
pub use crate::crypto::stream::Decryptor as EncryptedDecoder;
/// 流式加密器（写侧）：把内层明文按 1 MiB 分块加密为 v4 信封。
pub use crate::crypto::stream::Encryptor as EncryptedEncoder;

use crate::lz77::MatchConfig;

/// 返回系统可用并行度（逻辑 CPU 数）；探测失败时返回 1。
///
/// RZP 默认用它作为压缩/解压的工作线程数，可通过
/// [`Encoder::with_threads`] / [`Decoder::with_threads`] 覆盖。
pub fn default_threads() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

/// 压缩级别（0 到 9）。
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Level {
    /// 仅存储，不做压缩。
    L0 = 0,
    /// 最快。
    L1 = 1,
    L2 = 2,
    L3 = 3,
    L4 = 4,
    L5 = 5,
    /// 默认级别（速度与压缩率的平衡点）。
    L6 = 6,
    L7 = 7,
    L8 = 8,
    /// 最慢，压缩率最高。
    L9 = 9,
}

impl Level {
    /// 默认压缩级别。
    pub const DEFAULT: Level = Level::L6;

    /// 由 `u8` 构造级别，超出范围时收敛到 `0..=9`。
    pub fn from_u8(v: u8) -> Level {
        match v {
            0 => Level::L0,
            1 => Level::L1,
            2 => Level::L2,
            3 => Level::L3,
            4 => Level::L4,
            5 => Level::L5,
            6 => Level::L6,
            7 => Level::L7,
            8 => Level::L8,
            _ => Level::L9,
        }
    }

    /// 返回对应的 `u8` 值。
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    /// 该级别对应的匹配器配置；级别 0 返回 `None`（仅存储）。
    ///
    /// 窗口大小按 V5（32 MiB 上限）配置；编码时由 codec 层再按格式版本裁剪
    /// （V4 裁剪到 [`MAX_DIST`]，V5 裁剪到 [`MAX_WINDOW_SIZE`]）。
    pub(crate) fn match_config(self) -> Option<MatchConfig> {
        use crate::format::MAX_WINDOW_SIZE;
        use crate::lz77::MatchFinder;
        match self {
            Level::L0 => None,
            Level::L1 => Some(MatchConfig {
                finder: MatchFinder::HashChain3,
                window_size: 4096,
                max_chain: 4,
                nice_len: 8,
                lazy: false,
                max_lazy: 0,
                optimal: false,
            }),
            Level::L2 => Some(MatchConfig {
                finder: MatchFinder::HashChain3,
                window_size: 8192,
                max_chain: 16,
                nice_len: 16,
                lazy: false,
                max_lazy: 0,
                optimal: false,
            }),
            Level::L3 => Some(MatchConfig {
                finder: MatchFinder::HashChain3,
                window_size: 16384,
                max_chain: 32,
                nice_len: 32,
                lazy: false,
                max_lazy: 0,
                optimal: false,
            }),
            Level::L4 => Some(MatchConfig {
                finder: MatchFinder::HashChain3,
                window_size: 32768,
                max_chain: 64,
                nice_len: 64,
                lazy: false,
                max_lazy: 0,
                optimal: false,
            }),
            Level::L5 => Some(MatchConfig {
                finder: MatchFinder::HashChain3,
                window_size: 65536,
                max_chain: 128,
                nice_len: 128,
                lazy: false,
                max_lazy: 0,
                optimal: false,
            }),
            Level::L6 => Some(MatchConfig {
                finder: MatchFinder::HashChain4,
                window_size: 131072,
                max_chain: 256,
                nice_len: 128,
                lazy: true,
                max_lazy: 4,
                optimal: false,
            }),
            Level::L7 => Some(MatchConfig {
                finder: MatchFinder::BinaryTree,
                window_size: 4 * 1024 * 1024,
                max_chain: 512,
                nice_len: 258,
                lazy: true,
                max_lazy: 8,
                optimal: true,
            }),
            Level::L8 => Some(MatchConfig {
                finder: MatchFinder::BinaryTree,
                window_size: 16 * 1024 * 1024,
                max_chain: 1024,
                nice_len: 258,
                lazy: true,
                max_lazy: 16,
                optimal: true,
            }),
            Level::L9 => Some(MatchConfig {
                finder: MatchFinder::BinaryTree,
                window_size: MAX_WINDOW_SIZE,
                max_chain: 4096,
                nice_len: 258,
                lazy: true,
                max_lazy: 32,
                optimal: true,
            }),
        }
    }

    /// 该级别默认使用的目标块大小（未压缩字节数）。
    ///
    /// 低等级保持 1 MiB（快速、内存友好、并行粒度细）；高等级（L7–L9）使用与
    /// 匹配窗口一致的更大块，让 32 MiB 窗口真正生效——否则单块 1 MiB 会把匹配
    /// 距离截断在 1 MiB 以内，跨块的长距离重复无法利用。
    pub fn default_block_size(self) -> usize {
        use crate::format::{BLOCK_SIZE, MAX_WINDOW_SIZE};
        match self {
            Level::L0
            | Level::L1
            | Level::L2
            | Level::L3
            | Level::L4
            | Level::L5
            | Level::L6 => BLOCK_SIZE,
            Level::L7 => 4 * 1024 * 1024,
            Level::L8 => 16 * 1024 * 1024,
            Level::L9 => MAX_WINDOW_SIZE,
        }
    }
}

/// 一次性压缩：把整块数据压缩为 RZP 字节流。
pub fn compress(data: &[u8], level: Level) -> Vec<u8> {
    use std::io::Write;
    let mut enc = Encoder::new(Vec::new(), level);
    enc.write_all(data).expect("writing into a Vec cannot fail");
    enc.finish().expect("finishing into a Vec cannot fail")
}

/// 使用预设字典一次性压缩（见 [`Encoder::with_dictionary`]）。
pub fn compress_with_dictionary(data: &[u8], level: Level, dict: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut enc = Encoder::with_dictionary(Vec::new(), level, dict);
    enc.write_all(data).expect("writing into a Vec cannot fail");
    enc.finish().expect("finishing into a Vec cannot fail")
}

/// 一次性解压：把整段 RZP 字节流解压回原始数据，并校验完整性。
pub fn decompress(data: &[u8]) -> Result<Vec<u8>> {
    let mut dec = Decoder::new(std::io::Cursor::new(data));
    let mut out = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = dec.pump(&mut buf)?;
        if n == 0 {
            break;
        }
        out.extend_from_slice(&buf[..n]);
    }
    Ok(out)
}

/// 使用预设字典一次性解压（见 [`Decoder::with_dictionary`]）。
pub fn decompress_with_dictionary(data: &[u8], dict: &[u8]) -> Result<Vec<u8>> {
    let mut dec = Decoder::with_dictionary(std::io::Cursor::new(data), dict);
    let mut out = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = dec.pump(&mut buf)?;
        if n == 0 {
            break;
        }
        out.extend_from_slice(&buf[..n]);
    }
    Ok(out)
}

/// 按指定线程数、使用预设字典一次性压缩（内部辅助）。
fn compress_with_dictionary_and_threads(
    data: &[u8],
    level: Level,
    dict: &[u8],
    threads: usize,
) -> Vec<u8> {
    use std::io::Write;
    let mut enc = Encoder::with_dictionary(Vec::new(), level, dict).with_threads(threads);
    enc.write_all(data).expect("writing into a Vec cannot fail");
    enc.finish().expect("finishing into a Vec cannot fail")
}

/// 按指定线程数、使用预设字典一次性解压（内部辅助）。
fn decompress_with_dictionary_and_threads(
    data: &[u8],
    dict: &[u8],
    threads: usize,
) -> Result<Vec<u8>> {
    let mut dec = Decoder::with_dictionary(std::io::Cursor::new(data), dict).with_threads(threads);
    let mut out = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = dec.pump(&mut buf)?;
        if n == 0 {
            break;
        }
        out.extend_from_slice(&buf[..n]);
    }
    Ok(out)
}

/// 一次性压缩（[`compress`] 的别名）。
pub fn encode(data: &[u8], level: Level) -> Vec<u8> {
    compress(data, level)
}

/// 一次性解压（[`decompress`] 的别名）。
pub fn decode(data: &[u8]) -> Result<Vec<u8>> {
    decompress(data)
}

/// 不解压直接返回 RZP 流的原始数据长度（字节）。
///
/// 用于预分配缓冲区等场景；只做结构校验，不校验 CRC。等价于
/// [`inspect`] 后取 [`Info::raw_size`]。
pub fn decode_len(data: &[u8]) -> Result<u64> {
    let mut slice = data;
    Ok(inspect(&mut slice)?.raw_size)
}

/// RZP 流的元信息（由 [`inspect`] 解析得到，不解压内容）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Info {
    /// 压缩级别（来自流头）。
    pub level: Level,
    /// 原始数据总字节数（来自尾部）。
    pub raw_size: u64,
    /// 压缩后字节数（头 + 块 + 尾）。
    pub compressed_size: u64,
    /// 块总数。
    pub block_count: u64,
    /// 存储块（未压缩）数量。
    pub stored_blocks: u64,
    /// 压缩块数量。
    pub compressed_blocks: u64,
    /// 是否使用了预设字典（头标志 bit1）。
    pub has_dictionary: bool,
}

/// 解析 RZP 流的头、块头与尾部，返回元信息。
///
/// 不解压数据、不校验 CRC；仅做结构校验（魔数、版本、块尺寸上限、
/// 块类型、以及尾部总长与各块原始长度之和一致）。
///
/// 若流头标记为加密信封（`FLAG_ENCRYPTED`），则返回 [`Error::PasswordRequired`]。
pub fn inspect<R: std::io::Read>(reader: &mut R) -> Result<Info> {
    use crate::format::{
        footer_size, FormatVersion, BLOCK_HEADER_SIZE, BTYPE_COMPRESSED, BTYPE_FIXED,
        BTYPE_FSE_DYNAMIC, BTYPE_FSE_FIXED, BTYPE_STORED, DICT_CRC_SIZE, FLAG_DICT, FLAG_ENCRYPTED,
        FLAG_FOOTER, HEADER_SIZE, MAGIC, MAX_BLOCK_SIZE,
    };

    let mut compressed_size: u64 = 0;
    let mut block_count: u64 = 0;
    let mut stored_blocks: u64 = 0;
    let mut compressed_blocks: u64 = 0;
    let mut raw_sum: u64 = 0;

    // 头。
    let mut h = [0u8; HEADER_SIZE];
    reader.read_exact(&mut h)?;
    compressed_size += HEADER_SIZE as u64;
    if h[0..3] != MAGIC {
        return Err(Error::Corrupt("bad magic bytes".into()));
    }
    if FormatVersion::from_u8(h[3]).is_none() {
        return Err(Error::Corrupt(format!("unsupported version {}", h[3])));
    }
    if h[5] & FLAG_ENCRYPTED != 0 {
        return Err(Error::PasswordRequired);
    }
    if h[5] & FLAG_FOOTER == 0 {
        return Err(Error::Corrupt("missing footer flag".into()));
    }
    let has_dictionary = h[5] & FLAG_DICT != 0;
    if has_dictionary {
        let mut dcrc = [0u8; DICT_CRC_SIZE];
        reader.read_exact(&mut dcrc)?;
        compressed_size += DICT_CRC_SIZE as u64;
    }
    let level = h[4];

    // 复用缓冲，用于跳过块数据（comp_len 上限为 BLOCK_SIZE）。
    let mut skip = [0u8; 64 * 1024];

    // 块。
    loop {
        let mut bh = [0u8; BLOCK_HEADER_SIZE];
        reader.read_exact(&mut bh)?;
        compressed_size += BLOCK_HEADER_SIZE as u64;
        let raw_len = u32::from_le_bytes([bh[0], bh[1], bh[2], bh[3]]) as usize;
        let comp_len = u32::from_le_bytes([bh[4], bh[5], bh[6], bh[7]]) as usize;
        let final_flag = bh[8];
        let btype = bh[9];

        if raw_len > MAX_BLOCK_SIZE || comp_len > MAX_BLOCK_SIZE {
            return Err(Error::InvalidSize(format!(
                "block size out of range: raw={raw_len} comp={comp_len}"
            )));
        }
        match btype {
            BTYPE_STORED => stored_blocks += 1,
            BTYPE_COMPRESSED | BTYPE_FIXED | BTYPE_FSE_DYNAMIC | BTYPE_FSE_FIXED => {
                compressed_blocks += 1
            }
            _ => return Err(Error::Corrupt(format!("unknown block type {btype}"))),
        }

        // 跳过块数据（复用缓冲，避免每块堆分配）。
        let mut remaining = comp_len;
        while remaining > 0 {
            let n = remaining.min(skip.len());
            reader.read_exact(&mut skip[..n])?;
            remaining -= n;
        }
        compressed_size += comp_len as u64;
        raw_sum += raw_len as u64;
        block_count += 1;

        if final_flag != 0 {
            let fsize = footer_size(h[5]);
            let mut foot = vec![0u8; fsize];
            reader.read_exact(&mut foot)?;
            compressed_size += fsize as u64;
            let raw_size = u64::from_le_bytes(foot[fsize - 8..].try_into().unwrap());
            if raw_size != raw_sum {
                return Err(Error::InvalidSize(format!(
                    "size mismatch: footer says {raw_size}, blocks sum {raw_sum}"
                )));
            }
            return Ok(Info {
                level: Level::from_u8(level),
                raw_size,
                compressed_size,
                block_count,
                stored_blocks,
                compressed_blocks,
                has_dictionary,
            });
        }
    }
}

/// 密码加密选项。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CryptoOptions {
    /// Argon2id 内存成本（KiB，`1..=ARGON2_MAX_MEMORY_KIB`）。
    pub memory_kib: u32,
    /// Argon2id 时间成本（迭代次数，`1..=ARGON2_MAX_ITERATIONS`）。
    pub iterations: u32,
    /// Argon2id 并行度（车道数，`1..=ARGON2_MAX_LANES`）。
    pub lanes: u32,
    /// 可选盐（16 字节）；`None` 时使用系统随机源生成。
    pub salt: Option<[u8; 16]>,
}

impl Default for CryptoOptions {
    fn default() -> Self {
        CryptoOptions {
            memory_kib: ARGON2_DEFAULT_MEMORY_KIB,
            iterations: ARGON2_DEFAULT_ITERATIONS,
            lanes: ARGON2_DEFAULT_LANES,
            salt: None,
        }
    }
}

/// 用密码一次性压缩为加密信封（默认选项）。
pub fn compress_encrypted(data: &[u8], level: Level, password: &[u8]) -> Result<Vec<u8>> {
    compress_encrypted_with_options(data, level, password, &[], &CryptoOptions::default())
}

/// 使用预设字典 + 密码一次性压缩为加密信封（默认选项）。
pub fn compress_encrypted_with_dictionary(
    data: &[u8],
    level: Level,
    password: &[u8],
    dict: &[u8],
) -> Result<Vec<u8>> {
    compress_encrypted_with_options(data, level, password, dict, &CryptoOptions::default())
}

/// 用密码 + 可选预设字典一次性压缩为「目录归档」加密信封（默认选项）。
///
/// 与 [`compress_encrypted_with_dictionary`] 的区别在于，内层流头会设置
/// `FLAG_DIR`，解压端据此把结果还原为目录树而非单文件。
pub fn compress_encrypted_with_directory(
    data: &[u8],
    level: Level,
    password: &[u8],
    dict: &[u8],
) -> Result<Vec<u8>> {
    use std::io::Write;
    let mut enc = Encoder::with_directory(Vec::new(), level, dict);
    enc.write_all(data).expect("writing into a Vec cannot fail");
    let inner = enc.finish().expect("finishing into a Vec cannot fail");
    crypto::encrypt_envelope(
        &inner,
        level.as_u8(),
        password,
        ARGON2_DEFAULT_MEMORY_KIB,
        ARGON2_DEFAULT_ITERATIONS,
        ARGON2_DEFAULT_LANES,
        None,
    )
}

/// 使用自定义 [`CryptoOptions`] 与预设字典，一次性压缩为加密信封。
pub fn compress_encrypted_with_options(
    data: &[u8],
    level: Level,
    password: &[u8],
    dict: &[u8],
    options: &CryptoOptions,
) -> Result<Vec<u8>> {
    let inner = compress_with_dictionary(data, level, dict);
    crypto::encrypt_envelope(
        &inner,
        level.as_u8(),
        password,
        options.memory_kib,
        options.iterations,
        options.lanes,
        options.salt,
    )
}

/// 用密码把一段已压缩的内层 RZP 流加密为信封（默认 Argon2id 参数）。
///
/// 供需要自定义编码参数（如块大小）后再加密的场景使用；等价于把
/// [`compress_encrypted`] 拆成「先压缩、后加密」两步。
pub fn encrypt_with_password(inner: &[u8], level: Level, password: &[u8]) -> Result<Vec<u8>> {
    crypto::encrypt_envelope(
        inner,
        level.as_u8(),
        password,
        ARGON2_DEFAULT_MEMORY_KIB,
        ARGON2_DEFAULT_ITERATIONS,
        ARGON2_DEFAULT_LANES,
        None,
    )
}

/// 用密码一次性解压加密信封。
pub fn decompress_encrypted(data: &[u8], password: &[u8]) -> Result<Vec<u8>> {
    decompress_encrypted_with_dictionary(data, password, &[])
}

/// 使用预设字典 + 密码一次性解压加密信封。
pub fn decompress_encrypted_with_dictionary(
    data: &[u8],
    password: &[u8],
    dict: &[u8],
) -> Result<Vec<u8>> {
    let inner = crypto::decrypt_envelope(data, password)?;
    decompress_with_dictionary(&inner, dict)
}

/// 解压加密信封并返回 `(是否目录归档, 解压后的原始字节)`。
///
/// 单次解密后先读取内层流头的 `FLAG_DIR`，再解压，供调用方决定把结果还原
/// 为目录树还是单文件；避免二次 Argon2id 派生。
pub fn decompress_encrypted_with_kind(
    data: &[u8],
    password: &[u8],
    dict: &[u8],
) -> Result<(bool, Vec<u8>)> {
    let inner = crypto::decrypt_envelope(data, password)?;
    let is_dir = inner.len() >= format::HEADER_SIZE
        && inner[0..3] == format::MAGIC[..]
        && inner[5] & format::FLAG_DIR != 0;
    let restored = decompress_with_dictionary(&inner, dict)?;
    Ok((is_dir, restored))
}

/// 使用预设字典 + 密码，按指定线程数一次性压缩为加密信封（默认选项）。
pub fn compress_encrypted_with_dictionary_and_threads(
    data: &[u8],
    level: Level,
    password: &[u8],
    dict: &[u8],
    threads: usize,
) -> Result<Vec<u8>> {
    let inner = compress_with_dictionary_and_threads(data, level, dict, threads);
    crypto::encrypt_envelope(
        &inner,
        level.as_u8(),
        password,
        ARGON2_DEFAULT_MEMORY_KIB,
        ARGON2_DEFAULT_ITERATIONS,
        ARGON2_DEFAULT_LANES,
        None,
    )
}

/// 用密码 + 可选预设字典，按指定线程数一次性压缩为「目录归档」加密信封（默认选项）。
pub fn compress_encrypted_with_directory_and_threads(
    data: &[u8],
    level: Level,
    password: &[u8],
    dict: &[u8],
    threads: usize,
) -> Result<Vec<u8>> {
    use std::io::Write;
    let mut enc = Encoder::with_directory(Vec::new(), level, dict).with_threads(threads);
    enc.write_all(data).expect("writing into a Vec cannot fail");
    let inner = enc.finish().expect("finishing into a Vec cannot fail");
    crypto::encrypt_envelope(
        &inner,
        level.as_u8(),
        password,
        ARGON2_DEFAULT_MEMORY_KIB,
        ARGON2_DEFAULT_ITERATIONS,
        ARGON2_DEFAULT_LANES,
        None,
    )
}

/// 使用预设字典 + 密码，按指定线程数一次性解压加密信封。
pub fn decompress_encrypted_with_dictionary_and_threads(
    data: &[u8],
    password: &[u8],
    dict: &[u8],
    threads: usize,
) -> Result<Vec<u8>> {
    let inner = crypto::decrypt_envelope(data, password)?;
    decompress_with_dictionary_and_threads(&inner, dict, threads)
}

/// 解压加密信封并按指定线程数返回 `(是否目录归档, 解压后的原始字节)`。
///
/// 与 [`decompress_encrypted_with_kind`] 相同，但解压阶段使用 `threads` 个工作线程。
pub fn decompress_encrypted_with_kind_and_threads(
    data: &[u8],
    password: &[u8],
    dict: &[u8],
    threads: usize,
) -> Result<(bool, Vec<u8>)> {
    let inner = crypto::decrypt_envelope(data, password)?;
    let is_dir = inner.len() >= format::HEADER_SIZE
        && inner[0..3] == format::MAGIC[..]
        && inner[5] & format::FLAG_DIR != 0;
    let restored = decompress_with_dictionary_and_threads(&inner, dict, threads)?;
    Ok((is_dir, restored))
}

/// 用密码解密信封并返回内层 RZP 流的元信息。
pub fn inspect_encrypted(data: &[u8], password: &[u8]) -> Result<Info> {
    let inner = crypto::decrypt_envelope(data, password)?;
    let mut slice = inner.as_slice();
    inspect(&mut slice)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inspect_matches_roundtrip() {
        let mut data = Vec::new();
        let mut seed = 0x9e37_79b9u32;
        for _ in 0..200_000 {
            seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            data.push((seed >> 24) as u8);
        }
        data.extend_from_slice(&[7u8; 60_000]);

        let packed = compress(&data, Level::L6);
        let mut slice = packed.as_slice();
        let info = inspect(&mut slice).unwrap();
        assert_eq!(info.raw_size, data.len() as u64);
        assert_eq!(info.compressed_size, packed.len() as u64);
        assert_eq!(info.level, Level::L6);
        assert!(info.block_count > 0);
        assert_eq!(
            info.stored_blocks + info.compressed_blocks,
            info.block_count
        );
    }

    #[test]
    fn encode_decode_aliases() {
        let data = b"alias check ".repeat(100);
        let packed = encode(&data, Level::L6);
        assert_eq!(packed, compress(&data, Level::L6));
        assert_eq!(decode(&packed).unwrap(), decompress(&packed).unwrap());
    }

    #[test]
    fn inspect_strong_checksum() {
        use std::io::Write;
        let data: Vec<u8> = (0..50_000u32).map(|i| (i % 251) as u8).collect();
        let mut enc = Encoder::new(Vec::new(), Level::L6).with_strong_checksum();
        enc.write_all(&data).unwrap();
        let packed = enc.finish().unwrap();

        let mut slice = packed.as_slice();
        let info = inspect(&mut slice).unwrap();
        assert_eq!(info.raw_size, data.len() as u64);
        assert_eq!(info.compressed_size, packed.len() as u64);
    }

    #[test]
    fn decode_len_matches() {
        let data = vec![0x5Au8; 10_000];
        let packed = compress(&data, Level::L6);
        assert_eq!(decode_len(&packed).unwrap(), data.len() as u64);
    }

    #[test]
    fn dictionary_roundtrip_and_inspect() {
        let dict: Vec<u8> = (0..200u32).map(|i| (i % 251) as u8).collect();
        let data: Vec<u8> = dict[50..].to_vec();

        let packed = compress_with_dictionary(&data, Level::L6, &dict);
        assert_eq!(decompress_with_dictionary(&packed, &dict).unwrap(), data);

        // 无字典时 inspect 不标 has_dictionary。
        let plain = compress(&data, Level::L6);
        let mut slice = plain.as_slice();
        assert!(!inspect(&mut slice).unwrap().has_dictionary);

        // 有字典时 inspect 标 has_dictionary，且 compressed_size 含 4 字节字典 CRC。
        let mut slice = packed.as_slice();
        let info = inspect(&mut slice).unwrap();
        assert!(info.has_dictionary);
        assert_eq!(info.compressed_size, packed.len() as u64);
    }
}

#[cfg(test)]
mod crypto_api_tests {
    use super::*;

    fn sample_data() -> Vec<u8> {
        let mut data = Vec::new();
        let mut seed = 0xdead_beefu32;
        for _ in 0..50_000 {
            seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            data.push((seed >> 24) as u8);
        }
        data.extend_from_slice(&[7u8; 20_000]);
        data
    }

    #[test]
    fn encrypted_roundtrip_all_levels() {
        let data = sample_data();
        for lvl in 0..=9 {
            let packed = compress_encrypted(&data, Level::from_u8(lvl), b"pw").unwrap();
            assert_eq!(decompress_encrypted(&packed, b"pw").unwrap(), data);
        }
    }

    #[test]
    fn encrypted_roundtrip_empty() {
        let packed = compress_encrypted(b"", Level::L6, b"pw").unwrap();
        assert_eq!(decompress_encrypted(&packed, b"pw").unwrap(), b"");
    }

    #[test]
    fn encrypted_roundtrip_with_dictionary() {
        let dict: Vec<u8> = (0..200u32).map(|i| (i % 251) as u8).collect();
        let data: Vec<u8> = dict[50..].to_vec();

        let packed = compress_encrypted_with_dictionary(&data, Level::L6, b"pw", &dict).unwrap();
        assert_eq!(
            decompress_encrypted_with_dictionary(&packed, b"pw", &dict).unwrap(),
            data
        );

        // 用错字典应报错（认证通过后 CRC/字典校验失败）。
        let wrong: Vec<u8> = dict.iter().map(|b| b ^ 0xff).collect();
        assert!(decompress_encrypted_with_dictionary(&packed, b"pw", &wrong).is_err());
    }

    #[test]
    fn encrypted_wrong_password_fails() {
        let packed = compress_encrypted(b"data", Level::L6, b"right").unwrap();
        assert!(matches!(
            decompress_encrypted(&packed, b"wrong"),
            Err(Error::AuthFailed)
        ));
    }

    #[test]
    fn encrypted_tamper_ciphertext_and_tag_fails() {
        let data = b"important data".repeat(100);
        let packed = compress_encrypted(&data, Level::L6, b"pw").unwrap();

        // 篡改密文。
        let mut ct_tampered = packed.clone();
        let mid = ct_tampered.len() / 2;
        ct_tampered[mid] ^= 0xff;
        assert!(matches!(
            decompress_encrypted(&ct_tampered, b"pw"),
            Err(Error::AuthFailed)
        ));

        // 篡改 tag。
        let mut tag_tampered = packed.clone();
        let n = tag_tampered.len();
        tag_tampered[n - 1] ^= 0xff;
        assert!(matches!(
            decompress_encrypted(&tag_tampered, b"pw"),
            Err(Error::AuthFailed)
        ));
    }

    #[test]
    fn encrypted_requires_password() {
        let packed = compress_encrypted(b"data", Level::L6, b"pw").unwrap();

        // inspect 返回 PasswordRequired。
        let mut slice = packed.as_slice();
        assert!(matches!(inspect(&mut slice), Err(Error::PasswordRequired)));

        // 一次性 decompress 返回 PasswordRequired。
        assert!(matches!(decompress(&packed), Err(Error::PasswordRequired)));

        // Decoder::read_into 返回 PasswordRequired。
        let mut dec = Decoder::new(std::io::Cursor::new(&packed));
        let mut buf = [0u8; 16];
        assert!(matches!(
            dec.read_into(&mut buf),
            Err(Error::PasswordRequired)
        ));
    }

    #[test]
    fn encrypted_deterministic_with_salt() {
        let data = b"deterministic";
        let opts = CryptoOptions {
            memory_kib: 32,
            iterations: 1,
            lanes: 1,
            salt: Some([0x5au8; 16]),
        };
        let a = compress_encrypted_with_options(data, Level::L6, b"pw", &[], &opts).unwrap();
        let b = compress_encrypted_with_options(data, Level::L6, b"pw", &[], &opts).unwrap();
        // 相同盐与密钥时，nonce 仍为随机，密文可能不同但均可解回原文。
        assert_eq!(decompress_encrypted(&a, b"pw").unwrap(), data);
        assert_eq!(decompress_encrypted(&b, b"pw").unwrap(), data);
    }

    #[test]
    fn inspect_encrypted_reports_inner_info() {
        let data = sample_data();
        let packed = compress_encrypted(&data, Level::L6, b"pw").unwrap();
        let info = inspect_encrypted(&packed, b"pw").unwrap();
        assert_eq!(info.raw_size, data.len() as u64);
        assert_eq!(info.level, Level::L6);
        // 内层压缩大小应小于信封总大小。
        assert!(info.compressed_size < packed.len() as u64);
    }
}
