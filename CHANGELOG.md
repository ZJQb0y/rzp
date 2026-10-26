# 变更日志（Changelog）

本项目遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 的格式，
并使用[语义化版本](https://semver.org/lang/zh-CN/)。

> 说明：本文件自 `1.5.7` 起开始维护；更早版本未逐条记录。

## [Unreleased]

## [2.0.0] - 2026-10-25

### 格式（VERSION 5：FSE + 32 MiB 窗口 + repcode）

- 引入 `FormatVersion` 枚举（`V4` 只读 / `V5` 可写）与 `VERSION_V4 = 4`、
  `FORMAT_V5 = 5`、`ENVELOPE_VERSION = 4` 常量；加密信封改用 `ENVELOPE_VERSION`，
  与内层流版本解耦（信封布局保持不变）。
- `Encoder` 新增 `with_format_version` / `with_legacy_v4` 开关，可按 V4 回退输出；
  `Decoder` / `inspect` 同时接受版本 4 与 5。
- 熵编码由 Huffman 替换为 FSE（tANS，`src/fse.rs`）：频率归一化到 `2^k`、spread
  表、单级查表解码、反向状态机编码、类 zstd 的 RLE 归一化计数；新增块类型
  `BTYPE_FSE_DYNAMIC`（3）与 `BTYPE_FSE_FIXED`（4），V4 的 Huffman 块仅保留只读解码。
- 搜索窗口由 1 MiB 扩大到 32 MiB：新增 `MAX_WINDOW_SIZE` 与 V5 距离码表
  （额外位扩展到 23、覆盖 `2^25`），高等级（L7–L9）使用更大窗口。
- 距离字母表新增重复偏移（repcode）：符号 `0/1/2` 表示最近 3 个距离，符号 `3..=52`
  为扩展字面量距离码；编解码端对称维护最近距离。
- 新增 V4 黄金字节向量、长距离窗口、repcode 与 FSE 往返/损坏/属性模糊回归测试。

### 性能

- 解压端匹配拷贝由逐字节循环改为分块 `copy_within` 批量搬移（重叠安全），长匹配
  （尤其是小距离重叠匹配）解压速度显著提升。
- LZ77 匹配查找器新增 4 字节哈希（L6+ 启用）：位置满足 `i + 4 <= total` 时用 4 字节
  哈希插入/查找，减少哈希碰撞，在同等 `max_chain` 下提升匹配质量与速度。
- LZ77 匹配查找器新增经典二分树（L7–L9 启用）：维护每个位置的左右儿子指针，沿树
  双向遍历并按窗口/`nice_len` 剪枝；采用「最新者为根」的尾插切分，配合末尾填充与
  稳定全序保持 BST 合法，同长度优先命中最近距离，进一步改善高等级压缩率。
- 单流压缩改为「有序生产者-消费者流水线」：主线程把 `(序号, 块)` 送入有界工作队列，
  工作线程按需压缩后回传，主线程按序号重排并立即写出，使「压缩第 N+1 块」与「写第 N
  块」重叠，并让工作队列动态取活获得更好的负载均衡；输出与顺序压缩逐字节一致。
- 单流解压引入读入预取（read-ahead）：解压当前批的同时在后台线程读入下一批块头/块
  数据，使磁盘读入与解压延迟重叠，解压结果仍按原始顺序输出。

### 工程化

- 新增基准设施（`benches/bench.rs`，`cargo bench --bench bench`）：对确定性语料
  测量 RZP L1/L6/L9 的压缩率与吞吐量，并在系统装有 gzip/zstd 时输出对比表。

## [1.7.0] - 2026-10-24

### 新增

- 为 RZP 增加彭罗斯三角图标。
- 新增 i18n 模块（简体中文 / 英文自动检测）。

### 工程化

- 支持单语言多平台编译：目录归档的 Unix 专属能力（xattr、属主、权限、符号链接、
  硬链接、稀疏文件）按平台抽象，新增 Windows 交叉编译支持；`package.sh` 同时产出
  Linux 与 Windows 可移植包，并在装有 NSIS 时生成 Windows 安装包（`*-setup.exe`）。
- 为 Windows 的 `rzp.exe` 嵌入图标与文件版本资源（`build.rs`，MSVC 用 `rc.exe`、
  mingw 交叉编译用 `windres`），并保留 `package.ps1` 供 Windows 用户原生打包。
- 移除 GitHub Actions CI 工作流。

## [1.6.0] - 2026-10-23

### 新增

- 可选强完整性校验 BLAKE2b-256：头部新增 `FLAG_BLAKE2B` 标志位，尾部 40 字节；
  旧 CRC-32 流完全兼容。新增 `Encoder::with_strong_checksum()` 与
  `archive::write_indexed_dir_with_strong_checksum()`。
- CLI 新增 `--strong-checksum` 开关（单文件与目录归档均可产出强校验流）。
- CLI 暴露 Argon2id 参数 `--argon2-memory` / `--argon2-iters` / `--argon2-lanes`。

### 压缩率

- 修复 LZ77 惰性匹配退化：原先「多步跳跃」会一次性把中间字节输出为字面量、
  跳去取远处更长的匹配，忽略字面量编码成本，导致 L6–L9 压缩率反而劣于 L5。
  改为标准「单步惰性匹配」后，高等级压缩率恢复单调且显著提升（如 text 语料
  L9 由 0.345 降至 0.150）。
- 新增 LZ77 最优解析并接入 L6–L9。

### 性能

- CRC-32 增加 PCLMULQDQ SIMD 折叠路径，运行时 CPU 特性检测，标量 slicing-by-8 回退。
- ChaCha20 增加 AVX2 8 块并行路径，余数回退标量。
- 解密端输出改为分块队列（VecDeque），降低峰值内存占用。

### 工程化

- 新增本文件与版本一致性校验脚本（`scripts/check-version.sh`）。
- 新增 GitHub Actions CI（构建 / 测试 / clippy / fmt / fuzz 冒烟）。
- 新增压缩率回归测试（`tests/compression_ratio.rs`）。

## [1.5.7] - 2026-10-22

当前稳定版本，格式 `VERSION = 4`。

### 新增

- LZ77 匹配 + 限长规范 Huffman 熵编码（动态 + 静态两种块），压缩级别 `0–9`。
- CRC-32 完整性校验。
- ChaCha20-Poly1305 AEAD + Argon2id KDF 密码加密（含 KCV 快速口令拒绝）。
- 预设字典支持。
- 目录归档：solid 与索引式（RZPA，支持随机访问）。
- 多线程块级并行压缩/解压。
- shell 补全与 man page。

---

## 发版检查清单

每次发版需同步更新以下位置，并以 `scripts/check-version.sh` 自动校对：

| 文件 | 需更新内容 |
|------|-----------|
| `Cargo.toml` | `version` |
| `API.md` | 头部 `rzp <版本>` |
| `man/rzp.1` | `.TH` 行中的 `rzp <版本>` 与日期 |
| `README.md` | 克隆路径 `RZP_<版本>` |
| 若破坏格式 | `src/format.rs` 的 `VERSION` 与 `FORMAT.md` |
