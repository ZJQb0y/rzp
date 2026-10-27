# RZP 库 API 参考

> 版本：`rzp 2.1.0`。crate 名 `rzp`，主入口 `src/lib.rs`。
> 零第三方依赖，`std` only。

```rust
use rzp::{compress, decompress, Level};

let data = b"hello world, hello world, hello world";
let packed = compress(data, Level::L6);
let restored = decompress(&packed).unwrap();
assert_eq!(restored, data);
```

---

## 目录

- [类型](#类型)
  - [Level](#level)
  - [Error / Result](#error--result)
  - [Info](#info)
  - [CryptoOptions](#cryptooptions)
  - [EncoderStats](#encoderstats)
- [流式编解码](#流式编解码)
  - [Encoder](#encoder)
  - [Decoder](#decoder)
- [流式加密/解密](#流式加密解密)
  - [EncryptedEncoder](#encryptedencoder)
  - [EncryptedDecoder](#encrypteddecoder)
- [一次性便捷函数](#一次性便捷函数)
- [元信息与长度](#元信息与长度)
- [加密 API](#加密-api)
- [目录归档（archive 模块）](#目录归档archive-模块)
- [常量](#常量)

---

## 类型

### Level

压缩级别，`0`（仅存储）到 `9`（最慢最强）。

```rust
pub enum Level { L0 = 0, L1, L2, L3, L4, L5, L6, L7, L8, L9 }
```

| 方法 | 说明 |
|------|------|
| `Level::DEFAULT` | 默认级别 `L6` |
| `Level::from_u8(v: u8) -> Level` | 由 `u8` 构造，超出范围收敛到 `0..=9` |
| `level.as_u8() -> u8` | 返回对应 `u8` 值 |

各级别对应的匹配器配置（`window_size` / `max_chain` / `nice_len` / `lazy`）随级别递增而更激进，
详见 [`Level::match_config`](src/lib.rs)。

### Error / Result

```rust
pub enum Error {
    Corrupt(String),        // 非法 RZP 流（魔数/版本/块头/位流损坏）
    ChecksumMismatch,       // CRC-32 完整性校验失败
    InvalidSize(String),    // 长度/大小字段越界或不一致
    Io(String),             // 底层 I/O 错误
    PasswordRequired,       // 加密流但未提供密码
    AuthFailed,             // AEAD 认证失败（密码错或数据被篡改）
}

pub type Result<T> = std::result::Result<T, Error>;
```

实现 `Display`、`std::error::Error`、`From<std::io::Error>`、`Clone/PartialEq/Eq`。

### Info

由 [`inspect`](#inspect) 解析得到的流元信息（不解压内容）。

```rust
pub struct Info {
    pub level: Level,             // 压缩级别
    pub raw_size: u64,            // 原始数据总字节数
    pub compressed_size: u64,     // 压缩后字节数（头 + 块 + 尾）
    pub block_count: u64,         // 块总数
    pub stored_blocks: u64,       // 存储块数量
    pub compressed_blocks: u64,   // 压缩块数量
    pub has_dictionary: bool,     // 是否使用预设字典
}
```

### CryptoOptions

密码加密的 Argon2id 参数。

```rust
pub struct CryptoOptions {
    pub memory_kib: u32,          // 内存成本（KiB），1..=2 GiB
    pub iterations: u32,          // 时间成本（迭代次数），1..=1024
    pub lanes: u32,               // 并行度（车道数），1..=256
    pub salt: Option<[u8; 16]>,   // 可选盐；None 时使用系统随机源
}
```

实现 `Default`：`memory_kib = 64 MiB`、`iterations = 3`、`lanes = 4`、`salt = None`。

### EncoderStats

[`Encoder::finish_with_stats`](#encoder) 返回的统计信息。

```rust
pub struct EncoderStats {
    pub raw_size: u64,             // 原始字节数
    pub compressed_size: u64,      // 压缩后字节数
}
impl EncoderStats {
    pub fn ratio(&self) -> Option<f64>; // 压缩率（压缩/原始 × 100%）；原始为空返回 None
}
```

---

## 流式编解码

### Encoder

```rust
pub struct Encoder<W: Write> { /* ... */ }
```

实现 `std::io::Write`，把输入缓冲成块后增量压缩写出。构造方式：

| 方法 | 说明 |
|------|------|
| `Encoder::new(inner: W, level: Level) -> Self` | 以级别创建（无预设字典） |
| `Encoder::with_dictionary(inner: W, level: Level, dict: &[u8]) -> Self` | 带预设字典 |
| `Encoder::with_directory(inner: W, level: Level, dict: &[u8]) -> Self` | 标记负载为目录归档（设 `FLAG_DIR`） |

链式配置（消费式构造器）：

| 方法 | 说明 |
|------|------|
| `.with_threads(threads: usize) -> Self` | 设置压缩工作线程数（`1` 为单线程，内部 `max(1)`） |
| `.with_block_size(block_size: usize) -> Result<Self>` | 设置目标块大小 `1..=MAX_BLOCK_SIZE` |

运行期方法与收尾：

| 方法 | 说明 |
|------|------|
| `.total_in() -> u64` | 已写入（未压缩）总字节数 |
| `.total_out() -> u64` | 已写出（压缩后）总字节数（`finish` 后才完整） |
| `.compression_ratio() -> Option<f64>` | 当前压缩率 |
| `.get_ref() -> &W` / `.get_mut() -> &mut W` | 借用底层写入器 |
| `.into_inner() -> W` | 放弃编码，取出底层写入器（流不完整） |
| `.finish() -> Result<W>` | 结束编码，返回底层写入器 |
| `.finish_with_stats() -> Result<(W, EncoderStats)>` | 结束编码并返回统计 |

```rust
use std::io::Write;
use rzp::{Encoder, Level};

let mut enc = Encoder::new(Vec::new(), Level::L9)
    .with_threads(4);
enc.write_all(b"some data to compress")?;
let (packed, stats) = enc.finish_with_stats()?;
```

### Decoder

```rust
pub struct Decoder<R: Read + Send> { /* ... */ }
```

实现 `std::io::Read`，按需读取并解压，解码结束时校验 CRC 与总长。构造方式：

| 方法 | 说明 |
|------|------|
| `Decoder::new(inner: R) -> Self` | 从读取器创建（无预设字典） |
| `Decoder::with_dictionary(inner: R, dict: &[u8]) -> Self` | 带预设字典（头部字典 CRC 不一致时报 `ChecksumMismatch`） |
| `.with_threads(threads: usize) -> Self` | 设置解压工作线程数 |

运行期方法：

| 方法 | 说明 |
|------|------|
| `.total_out() -> u64` | 已解压总字节数 |
| `.total_in() -> u64` | 已读入（压缩后）总字节数 |
| `.level() -> Level` | 流头记录的压缩级别 |
| `.is_directory_archive() -> Result<bool>` | 是否为目录归档负载（会先读取校验流头） |
| `.read_into(&mut buf) -> Result<usize>` | 解压到 `buf`，返回写入字节数（`0` 表示结束）；保留精确错误类型 |
| `.get_ref() -> &R` / `.get_mut() -> &mut R` / `.into_inner() -> R` | 借用/取出底层读取器 |

```rust
use std::io::Read;
use rzp::Decoder;

let mut dec = Decoder::new(cursor);
let mut out = Vec::new();
dec.read_to_end(&mut out)?; // 结束时自动校验完整性
```

> `Decoder::read_into` 与 `Read::read` 行为一致，但直接返回 `rzp::Result`，
> 便于区分 `Error::PasswordRequired`、`Error::ChecksumMismatch` 等。

> 解压端在内部采用「读入预取」：解压当前批的同时于后台线程读入下一批块头/块数据，
> 使磁盘读入与解压延迟重叠；因此 `Decoder` 的读取器类型需满足 `Send`。解压结果仍按原始
> 顺序输出，健壮性校验（块尺寸上限、尾部校验、字典 CRC、损坏检测）语义不变。

---

## 流式加密/解密

与 [`compress_encrypted`](#加密-api) 等一次性函数产出的信封布局完全一致，区别在于按
`AEAD_CHUNK_SIZE`（1 MiB）逐块处理，内存占用有界。

### EncryptedEncoder

流式加密器（写侧），实现 `Write`。别名 `Encryptor`。

```rust
pub struct Encryptor<W: Write> { /* ... */ }

impl<W: Write> Encryptor<W> {
    pub fn new(
        inner: W,
        level: u8,
        password: &[u8],
        memory_kib: u32,
        iterations: u32,
        lanes: u32,
        salt: Option<[u8; SALT_LEN]>,
        total: u64,
    ) -> Result<Self>;

    pub fn finish(self) -> Result<W>;
}
```

由于信封头（含明文总长）须先于密文写出，构造时须告知 `total`。`finish` 前须恰好写入
`total` 字节，否则报错。典型用法是「先流式压缩到临时文件，再流式加密」。

### EncryptedDecoder

流式解密器（读侧），实现 `Read`。别名 `Decryptor`。

```rust
pub struct Decryptor<R: Read> { /* ... */ }

impl<R: Read> Decryptor<R> {
    pub fn new(inner: R, password: &[u8]) -> Result<Self>;
}
```

构造时读取并校验信封头、派生密钥并做 KCV 快速口令拒绝；随后按 1 MiB 逐块解密并认证。

---

## 一次性便捷函数

```rust
pub fn compress(data: &[u8], level: Level) -> Vec<u8>;
pub fn compress_with_dictionary(data: &[u8], level: Level, dict: &[u8]) -> Vec<u8>;

pub fn decompress(data: &[u8]) -> Result<Vec<u8>>;
pub fn decompress_with_dictionary(data: &[u8], dict: &[u8]) -> Result<Vec<u8>>;

pub fn encode(data: &[u8], level: Level) -> Vec<u8>;      // compress 的别名
pub fn decode(data: &[u8]) -> Result<Vec<u8>>;            // decompress 的别名
```

## 元信息与长度

```rust
pub fn decode_len(data: &[u8]) -> Result<u64>;
pub fn inspect<R: Read>(reader: &mut R) -> Result<Info>;
pub fn inspect_encrypted(data: &[u8], password: &[u8]) -> Result<Info>;
pub fn default_threads() -> usize;
```

- `decode_len`：不解压直接返回原始数据长度（等价于 `inspect` 后取 `Info::raw_size`），只做结构校验、不校验 CRC。
- `inspect`：解析头、块头与尾部，返回 `Info`；不解压、不校验 CRC。流头含 `FLAG_ENCRYPTED` 时返回 `Error::PasswordRequired`。
- `inspect_encrypted`：解密信封并返回内层 RZP 流元信息。
- `default_threads`：返回系统可用并行度（逻辑 CPU 数），探测失败返回 `1`。

---

## 加密 API

默认 Argon2id 参数：`64 MiB / 3 / 4`。

```rust
// 用密码一次性压缩/解压为加密信封
pub fn compress_encrypted(data: &[u8], level: Level, password: &[u8]) -> Result<Vec<u8>>;
pub fn compress_encrypted_with_dictionary(data: &[u8], level: Level, password: &[u8], dict: &[u8]) -> Result<Vec<u8>>;
pub fn compress_encrypted_with_options(data: &[u8], level: Level, password: &[u8], dict: &[u8], options: &CryptoOptions) -> Result<Vec<u8>>;

pub fn decompress_encrypted(data: &[u8], password: &[u8]) -> Result<Vec<u8>>;
pub fn decompress_encrypted_with_dictionary(data: &[u8], password: &[u8], dict: &[u8]) -> Result<Vec<u8>>;

// 目录归档信封（内层流头设 FLAG_DIR）
pub fn compress_encrypted_with_directory(data: &[u8], level: Level, password: &[u8], dict: &[u8]) -> Result<Vec<u8>>;

// 先压缩后加密两步（等价于 compress_encrypted 拆开）
pub fn encrypt_with_password(inner: &[u8], level: Level, password: &[u8]) -> Result<Vec<u8>>;

// 解压并返回 (是否目录归档, 原始字节)，避免二次 Argon2id 派生
pub fn decompress_encrypted_with_kind(data: &[u8], password: &[u8], dict: &[u8]) -> Result<(bool, Vec<u8>)>;

// 带线程数的变体（默认 Argon2id 参数）
pub fn compress_encrypted_with_dictionary_and_threads(data: &[u8], level: Level, password: &[u8], dict: &[u8], threads: usize) -> Result<Vec<u8>>;
pub fn compress_encrypted_with_directory_and_threads(data: &[u8], level: Level, password: &[u8], dict: &[u8], threads: usize) -> Result<Vec<u8>>;
pub fn decompress_encrypted_with_dictionary_and_threads(data: &[u8], password: &[u8], dict: &[u8], threads: usize) -> Result<Vec<u8>>;
pub fn decompress_encrypted_with_kind_and_threads(data: &[u8], password: &[u8], dict: &[u8], threads: usize) -> Result<(bool, Vec<u8>)>;
```

错误语义：错误密码或密文/tag 被篡改返回 `Error::AuthFailed`；加密流未提供密码返回
`Error::PasswordRequired`。

---

## 目录归档（archive 模块）

模块路径 `rzp::archive`，提供两种容器：顺序式（solid，旧式）与索引式（RZPA，非 solid）。

### 顺序式（solid）

```rust
pub fn write_dir<W: Write>(root: &Path, out: &mut W) -> io::Result<()>;
pub fn write_dir_filtered<W: Write>(root: &Path, out: &mut W, filter: &dyn Fn(&Path, bool) -> bool) -> io::Result<()>;

pub fn list<R: Read>(input: &mut R, f: impl FnMut(&Entry) -> io::Result<()>) -> io::Result<()>;
pub fn extract<R: Read>(input: &mut R, dest: &Path) -> io::Result<()>;
```

`filter` 回调参数为（相对 `root` 的路径, 是否目录）；返回 `false` 的目录连同子树一并跳过。

```rust
pub struct Entry {
    pub ty: u8,
    pub name: Vec<u8>,
    pub mode: u32,
    pub mtime_sec: i64,
    pub mtime_nsec: u32,
    pub size: u64,
}
impl Entry {
    pub fn path(&self) -> &Path;        // 按原始字节解释为 OS 路径
    pub fn type_name(&self) -> &'static str; // "file" | "dir" | "symlink" | "other"
}
```

### 索引式（RZPA）

```rust
pub fn write_indexed_dir<W: Write>(
    root: &Path,
    out: &mut W,
    filter: &dyn Fn(&Path, bool) -> bool,
    level: Level,
    dict: &[u8],
    threads: usize,
) -> crate::Result<()>;

pub fn read_index<R: Read + Seek>(r: &mut R) -> crate::Result<Vec<IndexEntry>>;
pub fn list_indexed<R: Read + Seek>(r: &mut R, f: impl FnMut(&IndexEntry) -> crate::Result<()>) -> crate::Result<()>;
pub fn verify_indexed<R: Read + Seek>(r: &mut R, dict: &[u8], threads: usize) -> crate::Result<()>;
pub fn extract_indexed<R: Read + Seek>(r: &mut R, dest: &Path, dict: &[u8], threads: usize) -> crate::Result<()>;
pub fn extract_indexed_entry<R: Read + Seek>(r: &mut R, e: &IndexEntry, dest: &Path, dict: &[u8], threads: usize) -> crate::Result<()>;
pub fn extract_indexed_path<R: Read + Seek>(r: &mut R, dest: &Path, name: &Path, dict: &[u8], threads: usize) -> crate::Result<()>;
```

```rust
pub struct IndexEntry {
    pub ty: u8, pub flags: u8, pub method: u8,
    pub name: Vec<u8>,
    pub mode: u32, pub uid: u32, pub gid: u32,
    pub mtime_sec: i64, pub mtime_nsec: u32,
    pub size: u64, pub comp_size: u64, pub xattr_len: u32,
    pub offset: u64,
}
impl IndexEntry {
    pub fn path(&self) -> &Path;
    pub fn type_name(&self) -> &'static str; // "file" | "dir" | "symlink" | "hardlink" | "other"
}
```

索引式归档保留：相对路径、内容、空目录、符号链接、权限、mtime、uid/gid、xattr（含 POSIX ACL）、
硬链接与稀疏文件布局。每个文件条目独立 RZP 压缩（压缩后不更小则原样存储），尾部追加中央目录与 EOCD，
支持不解压整个归档即可列目录或随机抽取单条目。

---

## 常量

由 `lib.rs` 重新导出：

| 常量 | 值 | 说明 |
|------|-----|------|
| `VERSION` | 4 | 格式版本 |
| `BLOCK_SIZE` | 1048576 | 默认块大小（字节） |
| `MAX_BLOCK_SIZE` | 67108864 | 块大小上限（字节） |
| `ARGON2_DEFAULT_MEMORY_KIB` | 65536 | 默认 Argon2id 内存成本 |
| `ARGON2_DEFAULT_ITERATIONS` | 3 | 默认 Argon2id 迭代次数 |
| `ARGON2_DEFAULT_LANES` | 4 | 默认 Argon2id 并行度 |

索引归档常量（`rzp::archive::*`）：`INDEX_MAGIC`、`INDEX_VERSION`、`INDEX_HEADER_SIZE`、
`INDEX_ENTRY_HEADER_SIZE`、`INDEX_CD_RECORD_SIZE`、`INDEX_EOCD_SIZE`、`INDEX_EOCD_MAGIC`。

其余格式常量（`MAGIC`、`FLAG_*`、`BTYPE_*`、`*_LEN`、长度/距离码表等）位于私有模块
`format` 内，不作为公共 API 暴露，详见 [`FORMAT.md`](./FORMAT.md)。
