//! 流式编码/解码器。
//!
//! [`Encoder`] 实现 [`std::io::Write`]，把输入缓冲成块后增量压缩写出；
//! [`Decoder`] 实现 [`std::io::Read`]，按需读取并解压。二者都支持增量完整性
//! 校验，默认 CRC-32，可通过 [`Encoder::with_strong_checksum`] 改用 BLAKE2b-256，
//! 解码端按头标志自动选择对应算法验证。

use std::collections::VecDeque;
use std::io::{self, Read, Write};

use crate::codec;
use crate::crc32::{crc32, Crc32};
use crate::crypto::blake2b::Blake2b;
use crate::error::{Error, Result};
use crate::format::{
    FormatVersion, BLAKE2B_DIGEST_SIZE, BLOCK_HEADER_SIZE, BLOCK_SIZE, BTYPE_STORED, DICT_CRC_SIZE,
    FLAG_BLAKE2B, FLAG_DICT, FLAG_DIR, FLAG_ENCRYPTED, FLAG_FOOTER, FOOTER_SIZE,
    FOOTER_STRONG_SIZE, HEADER_SIZE, MAGIC, MAX_BLOCK_SIZE, MAX_WINDOW_SIZE,
};
use crate::lz77::MatchConfig;
use crate::Level;

/// 把内部错误转换为 `io::Error`（供 `Read`/`Write` trait 使用）。
fn rzp_to_io(e: Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e.to_string())
}

/// 把 `io::Error` 转换为内部错误。
fn io_to_rzp(e: io::Error) -> Error {
    Error::Io(e.to_string())
}

/// 取字典中真正参与匹配的后缀（最多 [`MAX_WINDOW_SIZE`] 字节）。
fn effective_dict(dict: &[u8]) -> &[u8] {
    if dict.len() > MAX_WINDOW_SIZE {
        &dict[dict.len() - MAX_WINDOW_SIZE..]
    } else {
        dict
    }
}

/// 编码器收尾后的统计信息（由 [`Encoder::finish_with_stats`] 返回）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EncoderStats {
    /// 原始（未压缩）字节数。
    pub raw_size: u64,
    /// 压缩后字节数。
    pub compressed_size: u64,
}

impl EncoderStats {
    /// 压缩率（压缩后 / 原始，百分比）；原始为空时返回 `None`。
    pub fn ratio(&self) -> Option<f64> {
        if self.raw_size == 0 {
            None
        } else {
            Some(100.0 * self.compressed_size as f64 / self.raw_size as f64)
        }
    }
}

/// 流式完整性校验累加器：CRC-32（默认）或 BLAKE2b-256（更强）。
enum Checksum {
    Crc32(Crc32),
    Blake2b(Box<Blake2b>),
}

impl Checksum {
    fn crc32() -> Self {
        Checksum::Crc32(Crc32::new())
    }

    fn blake2b() -> Self {
        Checksum::Blake2b(Box::new(Blake2b::new(BLAKE2B_DIGEST_SIZE)))
    }

    fn is_strong(&self) -> bool {
        matches!(self, Checksum::Blake2b(_))
    }

    fn update(&mut self, data: &[u8]) {
        match self {
            Checksum::Crc32(c) => c.update(data),
            Checksum::Blake2b(b) => b.update(data),
        }
    }
}

/// 块规格：`(块类型, 块数据, 原始长度)`。
type BlockSpec = (u8, Vec<u8>, usize);

/// RZP 流式编码器。
pub struct Encoder<W: Write> {
    inner: W,
    cfg: Option<MatchConfig>,
    level: Level,
    buf: Vec<u8>,
    /// 目标块大小（未压缩字节数），`1..=MAX_BLOCK_SIZE`。
    block_size: usize,
    /// 已切出、待并行压缩的完整块。
    pending: Vec<Vec<u8>>,
    /// 参与压缩的工作线程数（1 表示单线程）。
    threads: usize,
    checksum: Checksum,
    raw_total: u64,
    comp_total: u64,
    header_written: bool,
    dict: Vec<u8>,
    dir: bool,
    /// 输出格式版本（默认见 [`FormatVersion::default`]）。
    format_version: FormatVersion,
}

/// 已预取的一批块规格。
struct PrefetchedBatch {
    /// 块规格列表。
    specs: Vec<BlockSpec>,
    /// 该批是否读到结束块（`final_flag`）。
    final_seen: bool,
}

/// 读取一批块规格：返回 `(specs, final_seen)`。最多读取 `threads` 个块；
/// 读到结束块即停止（不再继续读，把尾部留给调用方）。
fn read_specs<R: Read>(
    inner: &mut R,
    threads: usize,
    comp_total: &mut u64,
) -> Result<(Vec<BlockSpec>, bool)> {
    let mut specs: Vec<(u8, Vec<u8>, usize)> = Vec::with_capacity(threads);
    let mut final_seen = false;

    for _ in 0..threads {
        let mut bh = [0u8; BLOCK_HEADER_SIZE];
        inner.read_exact(&mut bh).map_err(io_to_rzp)?;
        *comp_total += BLOCK_HEADER_SIZE as u64;
        let raw_len = u32::from_le_bytes([bh[0], bh[1], bh[2], bh[3]]) as usize;
        let comp_len = u32::from_le_bytes([bh[4], bh[5], bh[6], bh[7]]) as usize;
        let final_flag = bh[8];
        let btype = bh[9];

        // 健壮性：拒绝异常尺寸，防止损坏输入导致超量分配。
        if raw_len > MAX_BLOCK_SIZE || comp_len > MAX_BLOCK_SIZE {
            return Err(Error::InvalidSize(format!(
                "block size out of range: raw={raw_len} comp={comp_len}"
            )));
        }

        let mut cdata = vec![0u8; comp_len];
        inner.read_exact(&mut cdata).map_err(io_to_rzp)?;
        *comp_total += comp_len as u64;

        specs.push((btype, cdata, raw_len));
        if final_flag != 0 {
            final_seen = true;
            break;
        }
    }

    Ok((specs, final_seen))
}

impl<W: Write> Encoder<W> {
    /// 以指定压缩级别创建编码器（不使用预设字典）。
    pub fn new(inner: W, level: Level) -> Self {
        Self::with_dictionary(inner, level, &[])
    }

    /// 以指定压缩级别与预设字典创建编码器。
    ///
    /// `dict` 作为输入的前置历史参与 LZ77 匹配，可显著提升小文件或共享
    /// 前缀文件的压缩率；超过 [`MAX_WINDOW_SIZE`] 的部分只取最后 [`MAX_WINDOW_SIZE`] 字节。
    pub fn with_dictionary(inner: W, level: Level, dict: &[u8]) -> Self {
        Self::with_config(inner, level, dict, false)
    }

    /// 创建标记负载为「目录归档」的编码器（可带预设字典）。
    ///
    /// 会在流头设置 `FLAG_DIR`，解压端据此把结果还原为目录树而非单文件。
    pub fn with_directory(inner: W, level: Level, dict: &[u8]) -> Self {
        Self::with_config(inner, level, dict, true)
    }

    fn with_config(inner: W, level: Level, dict: &[u8], dir: bool) -> Self {
        Encoder {
            inner,
            cfg: level.match_config(),
            level,
            buf: Vec::with_capacity(BLOCK_SIZE * 2),
            block_size: BLOCK_SIZE,
            pending: Vec::new(),
            threads: crate::default_threads(),
            checksum: Checksum::crc32(),
            raw_total: 0,
            comp_total: 0,
            header_written: false,
            dict: effective_dict(dict).to_vec(),
            dir,
            format_version: FormatVersion::default(),
        }
    }

    /// 设置参与压缩的工作线程数（1 表示单线程）。
    ///
    /// 消费式构造器，便于链式调用，如
    /// `Encoder::with_dictionary(w, level, dict).with_threads(4)`。
    pub fn with_threads(mut self, threads: usize) -> Self {
        self.threads = threads.max(1);
        self
    }

    /// 改用 BLAKE2b-256 作为尾部完整性校验（默认 CRC-32）。
    ///
    /// 消费式构造器，便于链式调用。写入的流会在头标志位设置 `FLAG_BLAKE2B`，
    /// 解压端据此自动选择强校验；旧 CRC-32 流仍完全兼容。
    pub fn with_strong_checksum(mut self) -> Self {
        self.checksum = Checksum::blake2b();
        self
    }

    /// 设置输出格式版本（默认 [`FormatVersion::default`]）。
    ///
    /// 消费式构造器，便于链式调用。V4 仅用于回退输出；V5 为 M3 的新格式。
    /// 解码端对 V4 永久只读兼容。
    pub fn with_format_version(mut self, version: FormatVersion) -> Self {
        self.format_version = version;
        self
    }

    /// 强制按历史 V4 格式输出（与旧版本解码器兼容）。
    ///
    /// 等价于 [`with_format_version`](Self::with_format_version)`(FormatVersion::V4)`，
    /// 供 M3 升级期间回退使用。
    pub fn with_legacy_v4(self) -> Self {
        self.with_format_version(FormatVersion::V4)
    }

    /// 设置目标块大小（未压缩字节数），范围 `1..=MAX_BLOCK_SIZE`。
    ///
    /// 消费式构造器，便于链式调用，如
    /// `Encoder::with_dictionary(w, level, dict).with_block_size(256 * 1024)?`。
    /// 块大小只影响分块粒度与压缩率，不影响解码兼容性。
    pub fn with_block_size(mut self, block_size: usize) -> Result<Self> {
        if block_size == 0 || block_size > MAX_BLOCK_SIZE {
            return Err(Error::InvalidSize(format!(
                "block size {block_size} out of range (1..={MAX_BLOCK_SIZE})"
            )));
        }
        self.block_size = block_size;
        if self.buf.capacity() < block_size * 2 {
            self.buf.reserve(block_size * 2 - self.buf.capacity());
        }
        Ok(self)
    }

    /// 已写入（未压缩）的总字节数。
    pub fn total_in(&self) -> u64 {
        self.raw_total
    }

    /// 已写出（压缩后）的总字节数；调用 [`finish`](Self::finish) 后才完整。
    pub fn total_out(&self) -> u64 {
        self.comp_total
    }

    /// 当前压缩率（压缩后 / 原始，百分比）；尚无输入时为 `None`。
    pub fn compression_ratio(&self) -> Option<f64> {
        if self.raw_total == 0 {
            None
        } else {
            Some(100.0 * self.comp_total as f64 / self.raw_total as f64)
        }
    }

    /// 借用底层写入器。
    pub fn get_ref(&self) -> &W {
        &self.inner
    }

    /// 可变借用底层写入器。
    pub fn get_mut(&mut self) -> &mut W {
        &mut self.inner
    }

    /// 放弃编码，取出底层写入器（不写出尾部，流不完整）。
    pub fn into_inner(self) -> W {
        self.inner
    }

    /// 结束编码：写出最后一块与尾部，返回底层写入器。
    ///
    /// 调用后不可再继续写入。
    pub fn finish(self) -> Result<W> {
        Ok(self.finish_with_stats()?.0)
    }

    /// 结束编码并返回底层写入器与统计信息。
    ///
    /// 调用后不可再继续写入。等价于 [`finish`](Self::finish)，同时给出最终的
    /// 原始/压缩字节数与压缩率。
    pub fn finish_with_stats(mut self) -> Result<(W, EncoderStats)> {
        self.finish_inner()?;
        let stats = EncoderStats {
            raw_size: self.raw_total,
            compressed_size: self.comp_total,
        };
        Ok((self.inner, stats))
    }

    fn write_header(&mut self) -> Result<()> {
        if self.header_written {
            return Ok(());
        }
        let mut h = [0u8; HEADER_SIZE];
        h[0..3].copy_from_slice(&MAGIC);
        h[3] = self.format_version.as_u8();
        h[4] = self.level.as_u8();
        h[5] = FLAG_FOOTER; // bit0：存在尾部（校验和 + 总长）。
        if self.checksum.is_strong() {
            h[5] |= FLAG_BLAKE2B;
        }
        if !self.dict.is_empty() {
            h[5] |= FLAG_DICT;
        }
        if self.dir {
            h[5] |= FLAG_DIR;
        }
        self.inner.write_all(&h).map_err(io_to_rzp)?;
        self.comp_total += HEADER_SIZE as u64;
        if !self.dict.is_empty() {
            let dict_crc = crc32(&self.dict);
            self.inner
                .write_all(&dict_crc.to_le_bytes())
                .map_err(io_to_rzp)?;
            self.comp_total += DICT_CRC_SIZE as u64;
        }
        self.header_written = true;
        Ok(())
    }

    fn write_block(
        &mut self,
        data: &[u8],
        btype: u8,
        cdata: &[u8],
        final_flag: bool,
    ) -> Result<()> {
        let mut h = [0u8; BLOCK_HEADER_SIZE];
        h[0..4].copy_from_slice(&(data.len() as u32).to_le_bytes());
        h[4..8].copy_from_slice(&(cdata.len() as u32).to_le_bytes());
        h[8] = final_flag as u8;
        h[9] = btype;
        self.inner.write_all(&h).map_err(io_to_rzp)?;
        self.inner.write_all(cdata).map_err(io_to_rzp)?;

        self.comp_total += BLOCK_HEADER_SIZE as u64 + cdata.len() as u64;
        self.checksum.update(data);
        self.raw_total += data.len() as u64;
        Ok(())
    }

    /// 并行压缩 `pending` 中的完整块并顺序写出。
    ///
    /// `final_batch` 为真时，最后一个块会被标记为结束块（`final_flag`）。
    fn flush_pending(&mut self, final_batch: bool) -> Result<()> {
        if self.pending.is_empty() {
            return Ok(());
        }
        let blocks = std::mem::take(&mut self.pending);
        let n = blocks.len();

        // 解构 `self`，得到互不相交的字段借用：压缩流水线的工作线程只读 `dict`，
        // 主线程回调写出则独占 `inner`/`checksum`/计数器，避免借用冲突。
        let Encoder {
            inner,
            cfg,
            threads,
            checksum,
            raw_total,
            comp_total,
            dict,
            format_version,
            ..
        } = self;

        match cfg {
            Some(mcfg) => {
                let mcfg = *mcfg;
                let threads = *threads;
                let fv = *format_version;
                codec::compress_blocks_parallel_stream(
                    dict.as_slice(),
                    &blocks,
                    &mcfg,
                    threads,
                    fv,
                    &mut |i, btype, cdata| {
                        let data = &blocks[i];
                        let mut h = [0u8; BLOCK_HEADER_SIZE];
                        h[0..4].copy_from_slice(&(data.len() as u32).to_le_bytes());
                        h[4..8].copy_from_slice(&(cdata.len() as u32).to_le_bytes());
                        h[8] = (final_batch && i == n - 1) as u8;
                        h[9] = btype;
                        inner.write_all(&h).map_err(io_to_rzp)?;
                        inner.write_all(&cdata).map_err(io_to_rzp)?;
                        *comp_total += BLOCK_HEADER_SIZE as u64 + cdata.len() as u64;
                        checksum.update(data);
                        *raw_total += data.len() as u64;
                        Ok(())
                    },
                )?;
            }
            None => {
                // 存储模式无压缩，直接顺序写出。
                for (i, block) in blocks.iter().enumerate() {
                    let mut h = [0u8; BLOCK_HEADER_SIZE];
                    h[0..4].copy_from_slice(&(block.len() as u32).to_le_bytes());
                    h[4..8].copy_from_slice(&(block.len() as u32).to_le_bytes());
                    h[8] = (final_batch && i == n - 1) as u8;
                    h[9] = BTYPE_STORED;
                    inner.write_all(&h).map_err(io_to_rzp)?;
                    inner.write_all(block).map_err(io_to_rzp)?;
                    *comp_total += BLOCK_HEADER_SIZE as u64 + block.len() as u64;
                    checksum.update(block);
                    *raw_total += block.len() as u64;
                }
            }
        }
        Ok(())
    }

    fn finish_inner(&mut self) -> Result<()> {
        self.write_header()?;
        let remaining = std::mem::take(&mut self.buf);
        if self.cfg.is_none() {
            // 存储模式无压缩可并行，直接写出。
            self.write_block(&remaining, BTYPE_STORED, &remaining, true)?;
        } else {
            self.pending.push(remaining);
            self.flush_pending(true)?;
        }

        if self.checksum.is_strong() {
            let mut foot = [0u8; FOOTER_STRONG_SIZE];
            let digest = match &mut self.checksum {
                Checksum::Blake2b(b) => b.finalize(),
                _ => unreachable!(),
            };
            foot[..BLAKE2B_DIGEST_SIZE].copy_from_slice(&digest);
            foot[BLAKE2B_DIGEST_SIZE..].copy_from_slice(&self.raw_total.to_le_bytes());
            self.inner.write_all(&foot).map_err(io_to_rzp)?;
            self.comp_total += FOOTER_STRONG_SIZE as u64;
        } else {
            let mut foot = [0u8; FOOTER_SIZE];
            let crc = match &self.checksum {
                Checksum::Crc32(c) => c.finalize(),
                _ => unreachable!(),
            };
            foot[0..4].copy_from_slice(&crc.to_le_bytes());
            foot[4..12].copy_from_slice(&self.raw_total.to_le_bytes());
            self.inner.write_all(&foot).map_err(io_to_rzp)?;
            self.comp_total += FOOTER_SIZE as u64;
        }
        Ok(())
    }
}

impl<W: Write> Encoder<W> {
    /// 写入一个完整块：存储模式直接写出，压缩模式送入待压缩队列并在队列
    /// 达到线程数时并行刷出。供 [`Write::write`](Self::write) 复用，避免重复逻辑。
    fn push_block(&mut self, block: Vec<u8>) -> Result<()> {
        if self.cfg.is_none() {
            // 存储模式无压缩可并行，直接写出。
            self.write_block(&block, BTYPE_STORED, &block, false)
        } else {
            self.pending.push(block);
            if self.pending.len() >= self.threads {
                self.flush_pending(false)
            } else {
                Ok(())
            }
        }
    }
}

impl<W: Write> Write for Encoder<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_header().map_err(rzp_to_io)?;

        let mut rest = buf;

        // 先补齐已有的部分块（若有），避免大块写入时反复搬移整个缓冲。
        if !self.buf.is_empty() {
            let need = self.block_size - self.buf.len();
            let take = need.min(rest.len());
            self.buf.extend_from_slice(&rest[..take]);
            rest = &rest[take..];
            if self.buf.len() == self.block_size {
                let block = std::mem::take(&mut self.buf);
                self.push_block(block).map_err(rzp_to_io)?;
            }
        }

        // 直接按完整块切分剩余数据，避免 `Vec::drain` 从头部搬移造成的 O(n²)。
        while rest.len() >= self.block_size {
            let block: Vec<u8> = rest[..self.block_size].to_vec();
            rest = &rest[self.block_size..];
            self.push_block(block).map_err(rzp_to_io)?;
        }

        // 剩余不足一个块的部分暂存，等待后续写入补齐。
        self.buf.extend_from_slice(rest);

        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// RZP 流式解码器。
pub struct Decoder<R: Read + Send> {
    inner: R,
    header_read: bool,
    finished: bool,
    level: u8,
    /// 流头中记录的格式版本。
    format_version: FormatVersion,
    /// 待输出的解压块队列（按原始顺序，队首为下一个要输出的块）。
    out: VecDeque<Vec<u8>>,
    /// 队首块内已输出的字节位置。
    out_pos: usize,
    /// 参与解压的工作线程数（1 表示单线程）。
    threads: usize,
    checksum: Checksum,
    strong: bool,
    raw_total: u64,
    comp_total: u64,
    dict: Vec<u8>,
    dir: bool,
    /// 已预取的下一批块规格（读入-解压重叠）。
    prefetched: Option<PrefetchedBatch>,
}

impl<R: Read + Send> Decoder<R> {
    /// 从读取器创建解码器（不使用预设字典）。
    pub fn new(inner: R) -> Self {
        Self::with_dictionary(inner, &[])
    }

    /// 以预设字典创建解码器。
    ///
    /// 若流头标记使用了字典，将校验头部记录的字典 CRC 与 `dict` 是否一致；
    /// 一致则把 `dict` 作为解码时的前置历史，否则报错（防止用错字典）。
    pub fn with_dictionary(inner: R, dict: &[u8]) -> Self {
        Decoder {
            inner,
            header_read: false,
            finished: false,
            level: 0,
            format_version: FormatVersion::V4,
            out: VecDeque::new(),
            out_pos: 0,
            threads: crate::default_threads(),
            checksum: Checksum::crc32(),
            strong: false,
            raw_total: 0,
            comp_total: 0,
            dict: effective_dict(dict).to_vec(),
            dir: false,
            prefetched: None,
        }
    }

    /// 设置参与解压的工作线程数（1 表示单线程）。
    ///
    /// 消费式构造器，便于链式调用，如
    /// `Decoder::with_dictionary(r, dict).with_threads(4)`。
    pub fn with_threads(mut self, threads: usize) -> Self {
        self.threads = threads.max(1);
        self
    }

    /// 已解压出的总字节数。
    pub fn total_out(&self) -> u64 {
        self.raw_total
    }

    /// 已读入（压缩后）的总字节数。
    pub fn total_in(&self) -> u64 {
        self.comp_total
    }

    /// 流头中记录的压缩级别。
    pub fn level(&self) -> Level {
        Level::from_u8(self.level)
    }

    /// 流头中记录的格式版本。
    pub fn format_version(&mut self) -> Result<FormatVersion> {
        self.read_header()?;
        Ok(self.format_version)
    }

    /// 是否为「目录归档」负载（流头 `FLAG_DIR` 标志）。
    ///
    /// 会先读取并校验流头；之后即可决定把解压结果还原为目录树还是单文件。
    pub fn is_directory_archive(&mut self) -> Result<bool> {
        self.read_header()?;
        Ok(self.dir)
    }

    /// 借用底层读取器。
    pub fn get_ref(&self) -> &R {
        &self.inner
    }

    /// 可变借用底层读取器。
    pub fn get_mut(&mut self) -> &mut R {
        &mut self.inner
    }

    /// 取出底层读取器。
    pub fn into_inner(self) -> R {
        self.inner
    }

    fn read_header(&mut self) -> Result<()> {
        if self.header_read {
            return Ok(());
        }
        let mut h = [0u8; HEADER_SIZE];
        self.inner.read_exact(&mut h).map_err(io_to_rzp)?;
        self.comp_total += HEADER_SIZE as u64;
        if h[0..3] != MAGIC[..] {
            return Err(Error::Corrupt("bad magic bytes".into()));
        }
        let format_version = FormatVersion::from_u8(h[3])
            .ok_or_else(|| Error::Corrupt(format!("unsupported version {}", h[3])))?;
        if h[5] & FLAG_ENCRYPTED != 0 {
            return Err(Error::PasswordRequired);
        }
        if h[5] & FLAG_FOOTER == 0 {
            return Err(Error::Corrupt("missing footer flag".into()));
        }
        if h[5] & FLAG_DICT != 0 {
            let mut dcrc = [0u8; DICT_CRC_SIZE];
            self.inner.read_exact(&mut dcrc).map_err(io_to_rzp)?;
            self.comp_total += DICT_CRC_SIZE as u64;
            let expected = u32::from_le_bytes(dcrc);
            let actual = crc32(&self.dict);
            if actual != expected {
                return Err(Error::ChecksumMismatch);
            }
        }
        self.level = h[4];
        self.dir = h[5] & FLAG_DIR != 0;
        self.strong = h[5] & FLAG_BLAKE2B != 0;
        self.format_version = format_version;
        self.checksum = if self.strong {
            Checksum::blake2b()
        } else {
            Checksum::crc32()
        };
        self.header_read = true;
        Ok(())
    }

    /// 读取并解压一批块（含可能的尾部校验），填充 `out`。
    ///
    /// 每次最多读取 `threads` 个块；解压与「读入下一批」在同一 [`std::thread::scope`]
    /// 内并发进行，使磁盘读入与解压延迟重叠，解压结果仍按原始顺序输出。健壮性校验
    /// （块尺寸上限、尾部校验、字典 CRC、损坏检测）语义不变。
    fn read_batch(&mut self) -> Result<()> {
        self.read_header()?;

        // 解构 `self`，取得互不相交的字段借用：解压工作线程只读 `dict`，预取读线程
        // 独占 `inner`/`comp_total`，主线程回调则操作 `out`/`checksum`/计数器。
        let Decoder {
            inner,
            header_read: _,
            finished,
            level: _,
            format_version,
            out,
            out_pos,
            threads,
            checksum,
            strong,
            raw_total,
            comp_total,
            dict,
            dir: _,
            prefetched,
        } = self;

        // 当前批：优先用上次预取的规格，否则现读。
        let (current_specs, current_final) = match prefetched.take() {
            Some(p) => (p.specs, p.final_seen),
            None => read_specs(inner, *threads, comp_total)?,
        };

        let threads = *threads;
        let format_version = *format_version;
        let current_len = current_specs.len();
        let dict_slice: &[u8] = dict.as_slice();

        let (raws, next_prefetched): (Vec<Vec<u8>>, Option<PrefetchedBatch>) =
            std::thread::scope(|scope| -> Result<_> {
                // 解压工作线程：并行解压当前批，保持块顺序。
                let mut handles = Vec::with_capacity(threads.max(1));
                let chunk_size = current_len.div_ceil(threads.max(1));
                for chunk in current_specs.chunks(chunk_size) {
                    handles.push(scope.spawn(move || {
                        chunk
                            .iter()
                            .map(|(bt, cd, rl)| {
                                codec::decompress_block(*bt, cd, *rl, dict_slice, format_version)
                            })
                            .collect::<Result<Vec<_>>>()
                    }));
                }

                // 预取下一批（仅当本批未读到结束块）。
                let prefetch_handle = if current_final {
                    None
                } else {
                    let inner = &mut *inner;
                    let comp_total = &mut *comp_total;
                    Some(scope.spawn(move || read_specs(inner, threads, comp_total)))
                };

                // 按顺序收集解压结果（释放压缩数据，只保留解压块队列，避免峰值翻倍）。
                let mut raws = Vec::with_capacity(current_len);
                for h in handles {
                    raws.extend(h.join().expect("decompress worker panicked")?);
                }

                let next_prefetched = match prefetch_handle {
                    Some(h) => {
                        let (specs, final_seen) = h.join().expect("prefetch reader panicked")?;
                        Some(PrefetchedBatch { specs, final_seen })
                    }
                    None => None,
                };

                Ok((raws, next_prefetched))
            })?;

        *prefetched = next_prefetched;

        for raw in &raws {
            checksum.update(raw);
            *raw_total += raw.len() as u64;
        }
        *out = raws.into_iter().collect();
        *out_pos = 0;

        if current_final {
            if *strong {
                let mut foot = [0u8; FOOTER_STRONG_SIZE];
                inner.read_exact(&mut foot).map_err(io_to_rzp)?;
                *comp_total += FOOTER_STRONG_SIZE as u64;
                let digest = match checksum {
                    Checksum::Blake2b(b) => b.finalize(),
                    _ => unreachable!(),
                };
                if digest.as_slice() != &foot[..BLAKE2B_DIGEST_SIZE] {
                    return Err(Error::ChecksumMismatch);
                }
                let total = u64::from_le_bytes(
                    foot[BLAKE2B_DIGEST_SIZE..]
                        .try_into()
                        .expect("footer total is 8 bytes"),
                );
                if *raw_total != total {
                    return Err(Error::InvalidSize(format!(
                        "size mismatch: expected {total}, got {}",
                        *raw_total
                    )));
                }
            } else {
                let mut foot = [0u8; FOOTER_SIZE];
                inner.read_exact(&mut foot).map_err(io_to_rzp)?;
                *comp_total += FOOTER_SIZE as u64;
                let crc = u32::from_le_bytes([foot[0], foot[1], foot[2], foot[3]]);
                let total = u64::from_le_bytes([
                    foot[4], foot[5], foot[6], foot[7], foot[8], foot[9], foot[10], foot[11],
                ]);
                let actual = match checksum {
                    Checksum::Crc32(c) => c.finalize(),
                    _ => unreachable!(),
                };
                if actual != crc {
                    return Err(Error::ChecksumMismatch);
                }
                if *raw_total != total {
                    return Err(Error::InvalidSize(format!(
                        "size mismatch: expected {total}, got {}",
                        *raw_total
                    )));
                }
            }
            *finished = true;
        }

        Ok(())
    }

    /// 读取并解压到 `buf`，返回写入的字节数（0 表示结束）。
    ///
    /// 与 [`Read::read`] 行为一致，但直接返回 crate 内部 [`Result`]，
    /// 保留具体错误类型（如 [`Error::PasswordRequired`]、[`Error::ChecksumMismatch`]），
    /// 便于调用方做精确错误分类。
    pub fn read_into(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.pump(buf)
    }

    /// 核心泵：填充 `buf`，返回写入的字节数（0 表示结束）。返回内部错误。
    pub(crate) fn pump(&mut self, buf: &mut [u8]) -> Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut written = 0;
        while written < buf.len() {
            if self.out.is_empty() {
                if self.finished {
                    break;
                }
                self.read_batch()?;
                continue;
            }
            let front_len = self.out.front().unwrap().len();
            if self.out_pos >= front_len {
                self.out.pop_front();
                self.out_pos = 0;
                continue;
            }
            let front = self.out.front().unwrap();
            let avail = front_len - self.out_pos;
            let n = avail.min(buf.len() - written);
            buf[written..written + n].copy_from_slice(&front[self.out_pos..self.out_pos + n]);
            self.out_pos += n;
            written += n;
        }
        Ok(written)
    }
}

impl<R: Read + Send> Read for Decoder<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.pump(buf).map_err(rzp_to_io)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn roundtrip(data: &[u8], level: Level) {
        let mut enc = Encoder::new(Vec::new(), level);
        enc.write_all(data).unwrap();
        let compressed = enc.finish().unwrap();

        let mut dec = Decoder::new(Cursor::new(compressed));
        let mut out = Vec::new();
        dec.read_to_end(&mut out).unwrap();
        assert_eq!(out, data);
    }

    #[test]
    fn roundtrip_all_levels() {
        let mut data = Vec::new();
        let mut seed = 0x1234_5678u32;
        for _ in 0..300_000 {
            seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            data.push((seed >> 24) as u8);
        }
        // 加入一段高重复数据。
        data.extend_from_slice(&[7u8; 50_000]);

        for lvl in 0..=9 {
            roundtrip(&data, Level::from_u8(lvl));
        }
    }

    #[test]
    fn roundtrip_empty() {
        roundtrip(b"", Level::L6);
    }

    #[test]
    fn pipeline_large_file_roundtrip() {
        // 多块 + 多线程流水线：验证大文件经生产者-消费者流水线压缩后仍可无损往返，
        // 且多线程不改变输出（checksum 也在解码端被校验）。
        let mut data = Vec::new();
        let mut seed = 0xdead_beefu32;
        let total = BLOCK_SIZE * 3; // 3 MiB，横跨 3 个块、多次 flush。
        for _ in 0..total {
            seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            data.push((seed >> 24) as u8);
        }
        data.extend_from_slice(&[7u8; BLOCK_SIZE / 2]);

        for threads in [1usize, 4] {
            let mut enc = Encoder::new(Vec::new(), Level::L6).with_threads(threads);
            enc.write_all(&data).unwrap();
            let packed = enc.finish().unwrap();

            let mut dec = Decoder::new(std::io::Cursor::new(packed)).with_threads(threads);
            let mut out = Vec::new();
            dec.read_to_end(&mut out).unwrap();
            assert_eq!(out, data, "threads={threads}");
        }
    }

    #[test]
    fn decoder_threads_consistent() {
        // 同一段压缩数据，用不同线程数解压（含读入预取路径），结果必须逐字节一致。
        let mut data = Vec::new();
        let mut seed = 0x1234_5678u32;
        for _ in 0..(BLOCK_SIZE * 3) {
            seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            data.push((seed >> 24) as u8);
        }
        data.extend_from_slice(&[7u8; BLOCK_SIZE / 2]);

        let packed = crate::compress(&data, Level::L6);

        let mut results = Vec::new();
        for threads in [1usize, 2, 4] {
            let mut dec = Decoder::new(Cursor::new(packed.clone())).with_threads(threads);
            let mut out = Vec::new();
            dec.read_to_end(&mut out).unwrap();
            assert_eq!(out, data, "threads={threads}");
            results.push(out);
        }
        assert_eq!(results[0], results[1]);
        assert_eq!(results[0], results[2]);
    }

    #[test]
    fn chunked_write_read() {
        let data: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
        let mut enc = Encoder::new(Vec::new(), Level::L6);
        // 随机小块写入。
        for chunk in data.chunks(137) {
            enc.write_all(chunk).unwrap();
        }
        let compressed = enc.finish().unwrap();

        let mut dec = Decoder::new(Cursor::new(compressed));
        let mut out = Vec::new();
        let mut buf = [0u8; 1000];
        loop {
            let n = dec.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n]);
        }
        assert_eq!(out, data);
    }

    #[test]
    fn checksum_detects_corruption() {
        let data = b"important data that must not be corrupted".repeat(100);
        let mut enc = Encoder::new(Vec::new(), Level::L6);
        enc.write_all(&data).unwrap();
        let mut compressed = enc.finish().unwrap();

        // 翻转一个字节。
        let mid = compressed.len() / 2;
        compressed[mid] ^= 0xff;

        let mut dec = Decoder::new(Cursor::new(compressed));
        let mut out = Vec::new();
        let err = dec.read_to_end(&mut out);
        assert!(err.is_err(), "corruption should be detected");
    }

    #[test]
    fn rejects_bad_magic() {
        let mut dec = Decoder::new(Cursor::new(b"NOTRZP".to_vec()));
        let mut out = Vec::new();
        assert!(dec.read_to_end(&mut out).is_err());
    }

    #[test]
    fn rejects_unknown_version() {
        // 版本 99 应被拒绝。
        let mut bad = b"RZP".to_vec();
        bad.push(99u8);
        bad.extend_from_slice(&[6, 0x01, 0, 0]);
        let mut dec = Decoder::new(Cursor::new(bad));
        let mut out = Vec::new();
        assert!(dec.read_to_end(&mut out).is_err());
    }

    #[test]
    fn strong_checksum_roundtrip() {
        let data: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let mut enc = Encoder::new(Vec::new(), Level::L6).with_strong_checksum();
        enc.write_all(&data).unwrap();
        let compressed = enc.finish().unwrap();

        // 头标志位应置强校验位。
        assert_eq!(compressed[5] & FLAG_BLAKE2B, FLAG_BLAKE2B);

        let mut dec = Decoder::new(Cursor::new(compressed));
        let mut out = Vec::new();
        dec.read_to_end(&mut out).unwrap();
        assert_eq!(out, data);
    }

    #[test]
    fn strong_checksum_detects_corruption() {
        let data = b"important data that must not be corrupted".repeat(100);
        let mut enc = Encoder::new(Vec::new(), Level::L6).with_strong_checksum();
        enc.write_all(&data).unwrap();
        let mut compressed = enc.finish().unwrap();

        // 翻转正文中的一个字节（非尾部）。
        let mid = compressed.len() / 2;
        compressed[mid] ^= 0xff;

        let mut dec = Decoder::new(Cursor::new(compressed));
        let mut out = Vec::new();
        assert!(dec.read_to_end(&mut out).is_err());
    }

    #[test]
    fn strong_checksum_footer_size() {
        // 存储模式精确字节数：头 8 + 数据块头/块 + 结束空块头 + 强校验尾部 40。
        let data = vec![0x5Au8; BLOCK_SIZE];
        let mut enc = Encoder::new(Vec::new(), Level::L0).with_strong_checksum();
        enc.write_all(&data).unwrap();
        let packed = enc.finish().unwrap();
        assert_eq!(
            packed.len() as u64,
            (HEADER_SIZE + 2 * BLOCK_HEADER_SIZE + BLOCK_SIZE + FOOTER_STRONG_SIZE) as u64
        );
    }

    #[test]
    fn encoder_totals() {
        // 恰好两个完整块，便于精确预测字节数。
        let data = vec![0x41u8; BLOCK_SIZE * 2];
        let mut enc = Encoder::new(Vec::new(), Level::L0);
        enc.write_all(&data).unwrap();

        assert_eq!(enc.total_in(), data.len() as u64);
        let out_before = enc.total_out();
        assert_eq!(
            out_before,
            (HEADER_SIZE + 2 * (BLOCK_HEADER_SIZE + BLOCK_SIZE)) as u64
        );
        assert!(enc.compression_ratio().unwrap() > 0.0);

        // finish 只再追加一个空块头与尾部。
        let packed = enc.finish().unwrap();
        assert_eq!(
            packed.len() as u64,
            out_before + (BLOCK_HEADER_SIZE + FOOTER_SIZE) as u64
        );
    }

    #[test]
    fn decoder_totals_and_into_inner() {
        let data = vec![0x42u8; 100_000];
        let packed = crate::compress(&data, Level::L6);

        let mut dec = Decoder::new(Cursor::new(packed.clone()));
        let mut out = Vec::new();
        dec.read_to_end(&mut out).unwrap();
        assert_eq!(out, data);
        assert_eq!(dec.total_out(), data.len() as u64);
        assert_eq!(dec.total_in(), packed.len() as u64);

        let cursor = dec.into_inner();
        assert_eq!(cursor.position(), packed.len() as u64);
    }

    #[test]
    fn encoder_into_inner_returns_inner() {
        let mut enc = Encoder::new(Vec::new(), Level::L6);
        enc.write_all(b"partial").unwrap();
        // 尚未 finish，仅写出头部。
        let inner = enc.into_inner();
        assert_eq!(inner.len(), HEADER_SIZE);
    }

    #[test]
    fn finish_with_stats_reports_final_sizes() {
        let data = vec![0x43u8; 100_000];
        let mut enc = Encoder::new(Vec::new(), Level::L0);
        enc.write_all(&data).unwrap();
        let (packed, stats) = enc.finish_with_stats().unwrap();

        assert_eq!(stats.raw_size, data.len() as u64);
        assert_eq!(stats.compressed_size, packed.len() as u64);
        assert!(stats.ratio().unwrap() > 0.0);
    }

    #[test]
    fn dictionary_roundtrip() {
        // 字典为数据的前缀历史，数据跨边界引用字典。
        let dict: Vec<u8> = (0..200u32).map(|i| (i % 251) as u8).collect();
        let data: Vec<u8> = dict[50..].to_vec();

        let mut enc = Encoder::with_dictionary(Vec::new(), Level::L6, &dict);
        enc.write_all(&data).unwrap();
        let packed = enc.finish().unwrap();

        let mut dec = Decoder::with_dictionary(Cursor::new(packed), &dict);
        let mut out = Vec::new();
        dec.read_to_end(&mut out).unwrap();
        assert_eq!(out, data);
    }

    #[test]
    fn dictionary_crc_mismatch_detected() {
        let dict: Vec<u8> = (0..200u32).map(|i| (i % 251) as u8).collect();
        let data: Vec<u8> = dict[50..].to_vec();

        let mut enc = Encoder::with_dictionary(Vec::new(), Level::L6, &dict);
        enc.write_all(&data).unwrap();
        let packed = enc.finish().unwrap();

        // 用错误的字典解码应报错，而非静默产出损坏数据。
        let wrong: Vec<u8> = dict.iter().map(|b| b ^ 0xff).collect();
        let mut dec = Decoder::with_dictionary(Cursor::new(packed), &wrong);
        let mut out = Vec::new();
        assert!(dec.read_to_end(&mut out).is_err());
    }

    #[test]
    fn custom_block_size_roundtrip() {
        let data: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
        for bs in [1usize, 1000, 64 * 1024, 2 * 1024 * 1024] {
            let mut enc = Encoder::new(Vec::new(), Level::L6)
                .with_block_size(bs)
                .unwrap();
            enc.write_all(&data).unwrap();
            let packed = enc.finish().unwrap();

            let mut dec = Decoder::new(Cursor::new(packed));
            let mut out = Vec::new();
            dec.read_to_end(&mut out).unwrap();
            assert_eq!(out, data, "block size {bs}");
        }
    }

    #[test]
    fn block_size_out_of_range_rejected() {
        assert!(Encoder::new(Vec::new(), Level::L6)
            .with_block_size(0)
            .is_err());
        assert!(Encoder::new(Vec::new(), Level::L6)
            .with_block_size(MAX_BLOCK_SIZE + 1)
            .is_err());
    }

    /// 确定性伪随机数生成器（xorshift64），避免引入第三方依赖。
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }

        fn below(&mut self, n: u64) -> u64 {
            debug_assert!(n > 0);
            self.next() % n
        }
    }

    /// 生成既含随机块又含高重复块的语料。
    fn fuzz_corpus(rng: &mut Rng) -> Vec<u8> {
        let mut data = Vec::new();
        let chunks = 1 + rng.below(4) as usize;
        for _ in 0..chunks {
            let n = 1000 + rng.below(4000) as usize;
            for _ in 0..n {
                data.push(rng.next() as u8);
            }
            let b = rng.next() as u8;
            let rep = 500 + rng.below(2500) as usize;
            data.extend(std::iter::repeat_n(b, rep));
        }
        data
    }

    /// 属性测试：任意级别 × 多种块大小下，随机语料压缩再解压必须逐字节还原。
    #[test]
    fn random_roundtrip_all_levels_and_blocks() {
        let mut rng = Rng(0x0DDC_0FFE_E000_0001);
        for _ in 0..120 {
            let data = fuzz_corpus(&mut rng);
            let level = Level::from_u8(rng.below(10) as u8);
            let bs = [1024usize, 65536, BLOCK_SIZE][rng.below(3) as usize];

            let mut enc = Encoder::new(Vec::new(), level).with_block_size(bs).unwrap();
            enc.write_all(&data).unwrap();
            let packed = enc.finish().unwrap();

            let mut dec = Decoder::new(Cursor::new(packed));
            let mut out = Vec::new();
            dec.read_to_end(&mut out).unwrap();
            assert_eq!(out, data, "level {level:?} block_size {bs}");
        }
    }

    #[test]
    fn fuzz_corruption_never_panics() {
        let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
        for _ in 0..300 {
            let data = fuzz_corpus(&mut rng);
            let level = Level::from_u8(rng.below(10) as u8);
            let packed = crate::compress(&data, level);

            // 截断到各种前缀。
            for cut in [0usize, 1, 3, packed.len() / 2, packed.len()] {
                if cut <= packed.len() {
                    let _ = crate::decompress(&packed[..cut]);
                    let _ = crate::inspect(&mut Cursor::new(&packed[..cut]));
                }
            }

            // 随机位翻转。
            let mut flipped = packed.clone();
            for _ in 0..12 {
                let pos = rng.below(flipped.len() as u64) as usize;
                flipped[pos] ^= 1u8 << (rng.below(8) as u32);
            }
            let _ = crate::decompress(&flipped);
            let _ = crate::inspect(&mut Cursor::new(&flipped));

            // 随机字节覆盖。
            let mut scribbled = packed.clone();
            for _ in 0..8 {
                let pos = rng.below(scribbled.len() as u64) as usize;
                scribbled[pos] = rng.next() as u8;
            }
            let _ = crate::decompress(&scribbled);
            let _ = crate::inspect(&mut Cursor::new(&scribbled));
        }
    }
}
