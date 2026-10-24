# 变更日志（Changelog）

本项目遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 的格式，
并使用[语义化版本](https://semver.org/lang/zh-CN/)。

> 说明：本文件自 `1.5.7` 起开始维护；更早版本未逐条记录。

## [Unreleased]

### 工程化

- 支持单语言多平台编译：目录归档的 Unix 专属能力（xattr、属主、权限、符号链接、
  硬链接、稀疏文件）按平台抽象，新增 Windows 交叉编译支持；`package.sh` 同时产出
  Linux 与 Windows 可移植包，并在装有 NSIS 时生成 Windows 安装包（`*-setup.exe`）。
- 为 Windows 的 `rzp.exe` 嵌入图标与文件版本资源（`build.rs`，MSVC 用 `rc.exe`、
  mingw 交叉编译用 `windres`），并保留 `package.ps1` 供 Windows 用户原生打包。

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

## [1.7.0] - 2026-10-24

### [新增]

- 为RZP增加了彭罗斯三角的图标
- 新增了i18n模块
