//! MSB-first 位读写器，供 Huffman 码流与额外位使用。

use crate::error::{corrupt, Result};

/// 位写入器：按最高有效位在前（MSB-first）累积比特，凑满一个字节后写出。
pub struct BitWriter {
    buf: Vec<u8>,
    acc: u32,
    nbits: u32,
}

impl BitWriter {
    pub fn new() -> Self {
        BitWriter {
            buf: Vec::with_capacity(1024),
            acc: 0,
            nbits: 0,
        }
    }

    /// 写入 `value` 的低 `count` 位，MSB-first。
    #[inline]
    pub fn write_bits(&mut self, value: u32, count: u32) {
        debug_assert!(count <= 32);
        debug_assert!(
            count == 0 || (value as u64) < (1u64 << count),
            "value out of range"
        );
        let mut remaining = count;
        let mut v = value;
        while remaining > 0 {
            // 本次能放入 acc 的位数。
            let space = 8 - self.nbits;
            if space == 0 {
                self.buf.push(self.acc as u8);
                self.acc = 0;
                self.nbits = 0;
                continue;
            }
            let take = remaining.min(space);
            // 取 v 的高 take 位。
            let shift = remaining - take;
            let bits = (v >> shift) & ((1 << take) - 1);
            // 放入 acc 的高位之后：acc 已占 nbits 位，新位接在其后。
            self.acc = (self.acc << take) | bits;
            self.nbits += take;
            remaining -= take;
            // 清掉已取出的高位，避免下一次移位错乱。
            v &= (1 << shift) - 1;
        }
        if self.nbits == 8 {
            self.buf.push(self.acc as u8);
            self.acc = 0;
            self.nbits = 0;
        }
    }

    /// 结束写入：将剩余的不足一字节按 MSB-first 左对齐后写出。
    pub fn finish(mut self) -> Vec<u8> {
        if self.nbits > 0 {
            self.acc <<= 8 - self.nbits;
            self.buf.push(self.acc as u8);
            self.acc = 0;
            self.nbits = 0;
        }
        self.buf
    }
}

impl Default for BitWriter {
    fn default() -> Self {
        Self::new()
    }
}

/// 位读取器：按 MSB-first 从字节切片中读取比特。
pub struct BitReader<'a> {
    data: &'a [u8],
    /// 当前字节内的剩余位。
    pos_bit: usize,
    /// 当前读取到的字节索引。
    pos_byte: usize,
}

impl<'a> BitReader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        BitReader {
            data,
            pos_bit: 0,
            pos_byte: 0,
        }
    }

    /// 已读出的总位数。
    pub fn bits_read(&self) -> usize {
        self.pos_byte * 8 + self.pos_bit
    }

    /// 剩余可读位数。
    pub fn remaining_bits(&self) -> usize {
        self.data.len() * 8 - self.bits_read()
    }

    /// 读取 `count` 位，MSB-first。
    pub fn read_bits(&mut self, count: usize) -> Result<u32> {
        if count > 32 {
            return corrupt("read_bits: too many bits requested");
        }
        if self.remaining_bits() < count {
            return corrupt("unexpected end of bitstream");
        }
        let mut value: u32 = 0;
        let mut remaining = count;
        while remaining > 0 {
            if self.pos_bit == 8 {
                self.pos_bit = 0;
                self.pos_byte += 1;
            }
            let byte = self.data[self.pos_byte];
            let avail = 8 - self.pos_bit;
            let take = remaining.min(avail);
            // 从当前字节取高 take 位（自 pos_bit 起）。
            let shift = avail - take;
            let bits = ((byte >> shift) as u32) & ((1 << take) - 1);
            value = (value << take) | bits;
            self.pos_bit += take;
            remaining -= take;
        }
        Ok(value)
    }

    /// 窥视 `count` 位（不消耗任何位），不足部分补零。
    ///
    /// 供查表式 Huffman 解码使用：一次取出 `MAX_BITS` 位做索引，再按实际码长跳过。
    #[inline]
    pub fn peek_bits_padded(&self, count: usize) -> u32 {
        debug_assert!(count <= 32);
        let mut value = 0u32;
        let mut remaining = count;
        let mut bit = self.pos_bit;
        let mut byte = self.pos_byte;
        while remaining > 0 && byte < self.data.len() {
            let avail = 8 - bit;
            let take = remaining.min(avail);
            let shift = avail - take;
            let bits = ((self.data[byte] >> shift) as u32) & ((1 << take) - 1);
            value = (value << take) | bits;
            bit += take;
            if bit == 8 {
                bit = 0;
                byte += 1;
            }
            remaining -= take;
        }
        value << remaining
    }

    /// 跳过 `count` 位；超过剩余位数则报错。
    #[inline]
    pub fn skip_bits(&mut self, count: usize) -> Result<()> {
        if self.remaining_bits() < count {
            return corrupt("unexpected end of bitstream");
        }
        let total = self.pos_bit + count;
        self.pos_byte += total / 8;
        self.pos_bit = total % 8;
        Ok(())
    }
}

/// 位写入器：按最低有效位在前（LSB-first）累积比特。
pub struct LsbWriter {
    buf: Vec<u8>,
    acc: u32,
    nbits: u32,
    /// 已写入的总位数。
    bit_count: usize,
}

impl LsbWriter {
    pub fn new() -> Self {
        LsbWriter {
            buf: Vec::with_capacity(1024),
            acc: 0,
            nbits: 0,
            bit_count: 0,
        }
    }

    /// 写入 `value` 的低 `count` 位，LSB-first（最低位先写出）。
    #[inline]
    pub fn write_bits(&mut self, value: u32, count: u32) {
        debug_assert!(count <= 32);
        self.bit_count += count as usize;
        let mut v = value;
        let mut remaining = count;
        while remaining > 0 {
            if self.nbits == 8 {
                self.buf.push(self.acc as u8);
                self.acc = 0;
                self.nbits = 0;
            }
            let space = 8 - self.nbits;
            let take = remaining.min(space);
            let bits = v & ((1u32 << take) - 1);
            self.acc |= bits << self.nbits;
            self.nbits += take;
            v >>= take;
            remaining -= take;
        }
    }

    /// 结束写入：剩余不足一字节的部分直接写出（低位对齐，高位补零）。
    pub fn finish(mut self) -> Vec<u8> {
        if self.nbits > 0 {
            self.buf.push(self.acc as u8);
        }
        self.buf
    }

    /// 结束写入，并把整段位序列反转后写出。
    ///
    /// 供 FSE 使用：zstd 的 FSE 符号流是「反向」的（编码时反向遍历符号，初始状态
    /// 最后写出），解码端正向读取。把位序列反转等价于「初始状态在前」，从而可用
    /// 正向 [`LsbReader`] 解码。
    pub fn finish_reversed(self) -> Vec<u8> {
        let total = self.bit_count;
        let mut out = vec![0u8; total.div_ceil(8)];
        for i in 0..total {
            let bit = self.get_bit(i);
            let dst = total - 1 - i;
            if bit {
                out[dst / 8] |= 1 << (dst % 8);
            }
        }
        out
    }

    /// 读取第 `idx` 个写入的位（0-based，按写入顺序）。
    fn get_bit(&self, idx: usize) -> bool {
        let byte_bits = self.buf.len() * 8;
        if idx < byte_bits {
            (self.buf[idx / 8] >> (idx % 8)) & 1 != 0
        } else {
            (self.acc >> (idx - byte_bits)) & 1 != 0
        }
    }
}

impl Default for LsbWriter {
    fn default() -> Self {
        Self::new()
    }
}

/// 位读取器：按 LSB-first 从字节切片读取比特。
pub struct LsbReader<'a> {
    data: &'a [u8],
    /// 当前字节内的已读位位置。
    pos_bit: usize,
    /// 当前读取到的字节索引。
    pos_byte: usize,
}

impl<'a> LsbReader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        LsbReader {
            data,
            pos_bit: 0,
            pos_byte: 0,
        }
    }

    /// 已读出的总位数。
    pub fn bits_read(&self) -> usize {
        self.pos_byte * 8 + self.pos_bit
    }

    /// 剩余可读位数。
    pub fn remaining_bits(&self) -> usize {
        self.data.len() * 8 - self.bits_read()
    }

    /// 读取 `count` 位，LSB-first。
    pub fn read_bits(&mut self, count: usize) -> Result<u32> {
        if count > 32 {
            return corrupt("read_bits: too many bits requested");
        }
        if self.remaining_bits() < count {
            return corrupt("unexpected end of bitstream");
        }
        let mut value = 0u32;
        let mut shift = 0usize;
        let mut remaining = count;
        while remaining > 0 {
            if self.pos_bit == 8 {
                self.pos_bit = 0;
                self.pos_byte += 1;
            }
            let byte = self.data[self.pos_byte];
            let avail = 8 - self.pos_bit;
            let take = remaining.min(avail);
            let bits = ((byte >> self.pos_bit) as u32) & ((1u32 << take) - 1);
            value |= bits << shift;
            shift += take;
            self.pos_bit += take;
            remaining -= take;
        }
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_bits() {
        let mut w = BitWriter::new();
        let values = [
            (0b101u32, 3u32),
            (0b11, 2),
            (0, 1),
            (0b1111_0000, 8),
            (0b1, 1),
        ];
        for &(v, n) in &values {
            w.write_bits(v, n);
        }
        let bytes = w.finish();
        let mut r = BitReader::new(&bytes);
        for &(v, n) in &values {
            assert_eq!(r.read_bits(n as usize).unwrap(), v);
        }
    }

    #[test]
    fn byte_boundaries() {
        let mut w = BitWriter::new();
        for i in 0..16u32 {
            w.write_bits(i, 8);
        }
        let bytes = w.finish();
        assert_eq!(bytes, (0..16u8).collect::<Vec<_>>());
        let mut r = BitReader::new(&bytes);
        for i in 0..16u32 {
            assert_eq!(r.read_bits(8).unwrap(), i);
        }
    }

    #[test]
    fn eof_error() {
        let mut r = BitReader::new(&[0xff]);
        r.read_bits(8).unwrap();
        assert!(r.read_bits(1).is_err());
    }
}
