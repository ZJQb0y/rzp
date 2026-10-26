# RZP 格式规范

> 当前可写格式：`FORMAT_V5 = 5`；历史格式：`VERSION_V4 = 4`（解码端永久只读兼容）。
> 所有多字节整数一律**小端序（little-endian）**；Huffman 位流为 **MSB-first**，
> FSE（tANS）位流为 **LSB-first**。

RZP 是流式压缩格式，由「头 + 若干块 + 尾部」组成。此外还定义了两种上层容器：

- **加密信封**：把一段内层 RZP 流用 `ChaCha20-Poly1305`（AEAD）加密并认证。
- **目录归档**：把整个目录树打包为一个字节流，再交给 RZP 压缩（或加密）。分**顺序式（solid）**与**索引式（RZPA，非 solid）**两种。

> **版本说明**：V5（M3 里程碑）引入 FSE/tANS 熵编码、32 MiB 搜索窗口与重复偏移
> （repcode）；V4 的 Huffman 块结构仍保留，仅供解码端只读兼容。

---

## 1. 基础 RZP 流

```
+--------+--------+---------+----------+--------+
| Header | DictCRC? | Block | Block ... | Footer |
+--------+--------+---------+----------+--------+
```

- `DictCRC` 仅当头部 `FLAG_DICT` 置位时存在。
- 至少一个块；最后一个块的 `final_flag = 1`。

### 1.1 头部 Header（8 字节）

| 偏移 | 长度 | 字段 | 说明 |
|------|------|------|------|
| 0 | 3 | `magic` | 固定为 `"RZP"`（`0x52 0x5A 0x50`） |
| 3 | 1 | `version` | `4`（历史，只读）或 `5`（当前可写） |
| 4 | 1 | `level` | 压缩级别 `0..=9` |
| 5 | 1 | `flags` | 位标志，见下 |
| 6 | 2 | `reserved` | 保留，须为 `0` |

**标志位（`flags`）：**

| 位 | 常量 | 值 | 含义 |
|----|------|-----|------|
| bit0 | `FLAG_FOOTER` | `0x01` | 存在尾部（校验和 + 总长）。RZP 流必须置位 |
| bit1 | `FLAG_DICT` | `0x02` | 使用预设字典；头后紧随 4 字节字典 CRC-32 |
| bit2 | `FLAG_ENCRYPTED` | `0x04` | 加密信封（仅出现在加密容器外层头） |
| bit3 | `FLAG_DIR` | `0x08` | 负载为目录归档（解压后按目录树还原） |
| bit4 | `FLAG_BLAKE2B` | `0x10` | 尾部使用 BLAKE2b-256 强校验（否则 CRC-32） |

### 1.2 字典 CRC（DictCRC，4 字节）

仅当 `FLAG_DICT` 置位时出现：预设字典（取其最后最多 `MAX_WINDOW_SIZE` 字节的
「有效字典」）的 **CRC-32**，`u32` 小端。解码端据此校验传入字典是否正确。

### 1.3 块头 Block Header（10 字节）

| 偏移 | 长度 | 字段 | 说明 |
|------|------|------|------|
| 0 | 4 | `raw_len` | 块解压后长度（`u32` LE），`<= MAX_BLOCK_SIZE` |
| 4 | 4 | `comp_len` | 块数据（压缩后）长度（`u32` LE） |
| 8 | 1 | `final_flag` | 非零表示流的最后一个块 |
| 9 | 1 | `btype` | 块类型，见下 |

**块类型（`btype`）：**

| 值 | 常量 | 含义 |
|----|------|------|
| 0 | `BTYPE_STORED` | 直接存储，`comp_len == raw_len`，数据原样 |
| 1 | `BTYPE_COMPRESSED` | LZ77 + 动态 Huffman（V4） |
| 2 | `BTYPE_FIXED` | LZ77 + 静态（固定）Huffman（V4） |
| 3 | `BTYPE_FSE_DYNAMIC` | LZ77 + 动态 FSE（V5） |
| 4 | `BTYPE_FSE_FIXED` | LZ77 + 静态（固定）FSE（V5） |

### 1.4 尾部 Footer

尾部大小由 `flags` 的 `FLAG_BLAKE2B` 决定：

- **CRC-32 尾部（12 字节，默认）**：`FLAG_BLAKE2B` 未置位。

| 偏移 | 长度 | 字段 | 说明 |
|------|------|------|------|
| 0 | 4 | `crc32` | 整个原始数据流的 CRC-32（`u32` LE） |
| 4 | 8 | `raw_size` | 原始数据总字节数（`u64` LE） |

- **BLAKE2b-256 尾部（40 字节，强校验）**：`FLAG_BLAKE2B` 置位。

| 偏移 | 长度 | 字段 | 说明 |
|------|------|------|------|
| 0 | 32 | `digest` | 整个原始数据流的 BLAKE2b-256 摘要 |
| 32 | 8 | `raw_size` | 原始数据总字节数（`u64` LE） |

解码结束须校验：校验和一致，且各块 `raw_len` 之和等于 `raw_size`。

---

## 2. V5 压缩块（LZ77 + FSE）

V5 压缩块由 LZ77 令牌流经 **FSE（tANS）** 熵编码得到。字面量/长度与距离分别使用
两张独立 FSE 表。距离字母表含重复偏移（repcode）。

### 2.1 字母表与符号

| 表 | 符号范围 | 大小 | 说明 |
|----|----------|------|------|
| 字面量/长度（litlen） | `0..=255` | 256 | 原始字节 |
| 块结束（EOB） | `256` | 1 | 块结束标记 |
| 长度码 | `257..=285` | 29 | `LEN_SYMBOL_BASE = 257` |
| 重复偏移（repcode） | `0..=2` | 3 | `REP_SYMBOLS = 3` |
| 距离码 | `3..=52` | 50 | `V5_DIST_SYMBOLS = 50`（覆盖 1..=MAX_WINDOW_SIZE） |

**长度码表**（`LENGTH_BASE` / `LENGTH_EXTRA_BITS`）与 V4 相同。

**V5 距离码表**（符号 `3 + dist_code`）：

| 距离码 | 基准距离 | 额外位 |
|--------|----------|--------|
| 0..3 | 1,2,3,4 | 0 |
| 4..5 | 5,7 | 1 |
| 6..7 | 9,13 | 2 |
| …（几何增长） | … | … |
| 48..49 | 16777217, 25165825 | 23 |

距离码沿几何增长规律扩展到额外位 23、覆盖 `2^25 = 32 MiB`。匹配长度范围
`3..=258`，最大回溯距离 `MAX_WINDOW_SIZE = 32 MiB`。

### 2.2 重复偏移（repcode）

解码端维护「最近 3 个距离」（初始 `[1, 1, 1]`）：

- 符号 `0` = `rep0`：使用最近距离，数组不变。
- 符号 `1` = `rep1`：使用次近距离，并与 `rep0` 交换。
- 符号 `2` = `rep2`：使用第三近距离，并提到 `rep0` 首位。
- 符号 `>= 3`：字面量距离码，真实距离 = `V5_DIST_BASE[code] + extra`，并成为新 `rep0`。

编码端对称维护最近距离，命中时改发 repcode 符号。

### 2.3 FSE 归一化计数

FSE 表大小 `1 << table_log`，归一化计数总和等于表大小，每个出现符号至少计数 1。
计数序列用类 zstd `FSE_readNCount` 的 RLE 格式写入（LSB-first）：

```
table_log(4) + last_symbol(9) + 计数序列
计数序列：每个符号写 1 位标记（0=直接计数，1=零游程），
  直接计数：count-1（table_log 位）
  零游程：run-1（9 位）
```

### 2.4 动态 FSE 块（`BTYPE_FSE_DYNAMIC`）

```
u32 counts_len
u32 litlen_stream_len
u32 dist_stream_len
u32 extra_stream_len
counts_bytes        (litlen 归一化计数 + dist 归一化计数，LSB-first)
litlen_stream       (litlen 符号流，反向位序)
dist_stream         (dist 符号流，反向位序)
extra_stream        (长度/距离额外位，LSB-first)
```

FSE 符号流采用「反向位序」：编码时反向遍历符号、初始状态最后写出，整体位序列
再反转，使解码端可正向读取（先读初始状态）。

### 2.5 静态 FSE 块（`BTYPE_FSE_FIXED`）

```
u32 litlen_stream_len
u32 dist_stream_len
u32 extra_stream_len
litlen_stream
dist_stream
extra_stream
```

固定 FSE 表不发送计数：

- 字面量/长度表（`table_log = 9`，`512` 状态）：前 226 符号计数 2、其余计数 1。
- 距离表（`table_log = 6`，`64` 状态）：前 11 符号计数 2、其余计数 1。

---

## 3. V4 压缩块（LZ77 + Huffman，历史只读）

V4 块与历史版本相同，保留仅供解码。字面量/长度与距离分别使用两张独立 Huffman
表；位序 **MSB-first**。距离码表 40 个（`DIST_SYMBOLS = 40`），最大回溯距离
`MAX_DIST = 1 MiB`。动态块先写两段码长序列（RLE），静态块用固定码长。

---

## 4. 加密信封（Encrypted Envelope）

加密信封把一段内层明文 RZP 流加密为信封，用于密码保护。KDF 为 **Argon2id**，
AEAD 为 **ChaCha20-Poly1305**，按 **1 MiB** 分块流式认证。信封版本与内层流版本
**解耦**，恒为 `ENVELOPE_VERSION = 4`。

```
+----------------+--------+--------+--------+-----------------------------------+
| Outer Header   | Salt   | Nonce  | Total  | [ciphertext chunk + tag]* ...    |
+----------------+--------+--------+--------+-----------------------------------+
```

外层头 28 字节，字段与 V4 相同（`version = 4`、`FLAG_ENCRYPTED`、`kdf`、`aead`、
`m_cost`、`t_cost`、`p_cost`、`kcv`）。KDF/分块 AEAD 细节不变。

---

## 5. 目录归档

目录归档分两种容器：**顺序式（solid）** 与 **索引式（RZPA）**。结构不变，与 V4 相同。

---

## 6. 常量汇总

| 常量 | 值 | 说明 |
|------|-----|------|
| `VERSION_V4` | 4 | 历史格式版本（只读兼容） |
| `FORMAT_V5` | 5 | 当前可写格式版本 |
| `ENVELOPE_VERSION` | 4 | 加密信封版本（与流版本解耦） |
| `HEADER_SIZE` | 8 | RZP 流头 |
| `BLOCK_HEADER_SIZE` | 10 | 块头 |
| `FOOTER_SIZE` | 12 | 尾部（CRC-32） |
| `FOOTER_STRONG_SIZE` | 40 | 尾部（BLAKE2b-256） |
| `DICT_CRC_SIZE` | 4 | 字典 CRC |
| `ENC_HEADER_SIZE` | 28 | 加密外层头 |
| `AEAD_CHUNK_SIZE` | 1 MiB | 加密分块 |
| `BLOCK_SIZE` | 1 MiB | 默认块大小 |
| `MAX_BLOCK_SIZE` | 64 MiB | 块大小上限 |
| `MIN_MATCH` / `MAX_MATCH` | 3 / 258 | 匹配长度 |
| `MAX_DIST` | 1 MiB | V4 最大回溯距离 |
| `MAX_WINDOW_SIZE` | 32 MiB | V5 最大回溯距离 |
| `MAX_BITS` | 15 | Huffman 码长上限 |
| `LITLEN_SYMBOLS` | 286 | 字面量/长度表大小 |
| `DIST_SYMBOLS` | 40 | V4 距离表大小 |
| `V5_DIST_SYMBOLS` | 50 | V5 字面量距离码数量 |
| `REP_SYMBOLS` | 3 | V5 重复偏移数量 |
| `V5_DIST_ALPHABET` | 53 | V5 距离字母表总大小 |
| `FSE_MIN_TABLELOG` / `FSE_MAX_TABLELOG` | 5 / 15 | FSE 表对数值范围 |
