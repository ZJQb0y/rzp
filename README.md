# RZP

从零实现的流式、带完整性校验的压缩格式与命令行工具，用 Rust 编写，**零第三方依赖**。

- **压缩/解压**：LZ77 匹配 + 限长规范 Huffman 熵编码（动态 + 静态两种块）。
- **完整性校验**：流尾部携带 CRC-32，解码结束自动校验。
- **密码加密**：ChaCha20-Poly1305 AEAD + Argon2id KDF（含 KCV 快速口令拒绝），分块流式、内存有界。
- **压缩级别**：0（仅存储）到 9（最慢最强）。
- **目录归档**：打包目录树为单个 `.rzp`，保留目录结构/空目录/符号链接/权限/mtime/uid/gid/xattr/硬链接/稀疏文件。
- **随机访问**：索引式归档（RZPA）支持不解压整个归档即可列目录或抽取单个条目。
- **多线程**：块级并行压缩/解压，线程数默认按 CPU 核数自动检测。

---

## 安装

### 从源码构建

```bash
git clone <repo>
cd RZP_1.6.1
cargo build --release          # 产物在 target/release/rzp

# 交叉编译 Windows 版本（需先安装对应目标与 mingw-w64 链接器）
rustup target add x86_64-pc-windows-gnu
cargo build --release --target x86_64-pc-windows-gnu   # 产物在 target/x86_64-pc-windows-gnu/release/rzp.exe
```

### 通过 Cargo 安装

```bash
cargo install rzp
```

### 一键打包

Linux（可同时产出 Linux 与 Windows 产物）：

```bash
./package.sh
```

生成 Linux 可移植 `dist/rzp-<版本>-<架构>.tar.gz`（含二进制 + 文档 + 补全脚本 + man page），
若装有 `cargo-deb` 还会生成 Debian 安装包 `.deb`。

若已安装 `x86_64-pc-windows-gnu` 目标与 mingw-w64 链接器，还会额外生成
Windows 可移植 `dist/rzp-<版本>-x86_64-windows.zip`（含 `rzp.exe` + 文档 + 图标）；
若装有 NSIS（`makensis`），还会生成 Windows 安装包
`dist/rzp-<版本>-x86_64-windows-setup.exe`。

Windows（原生编译打包，需 PowerShell）：

```powershell
.\package.ps1            # 生成 Windows zip + NSIS 安装包
.\package.ps1 -SkipInstaller   # 仅生成 zip
```

`rzp.exe` 的图标与文件版本信息由 [build.rs](build.rs) 在编译时嵌入（MSVC 用
`rc.exe`，mingw 交叉编译用 `windres`）。

---

## 命令行用法

```text
rzp <命令> [选项] <输入>...
```

| 命令 | 说明 |
|------|------|
| `c` | 压缩文件或目录（目录打包为单个 `.rzp`） |
| `d` | 解压文件或目录归档（目录输入递归处理其中的 `.rzp`） |
| `i` | 查看归档信息（不解压） |
| `l` | 列出目录归档内容（不解出内容） |
| `t` | 校验文件完整性（不解出内容） |
| `x` | 从目录归档随机抽取单个条目 |
| `bench` | 与 gzip/zstd 对比压缩率与速度（文件或目录） |
| `completion` | 输出 shell 补全脚本（bash/zsh/fish） |
| `--help` / `--version` | 帮助 / 版本 |

输入/输出路径可用 `-` 表示 stdin/stdout（仅限单个输入）。

### 常用选项（`c` / `d`）

| 选项 | 说明 |
|------|------|
| `-o <路径>` | 指定输出文件（仅单个输入） |
| `-l <0-9>` | 压缩级别（仅 `c`，默认 6） |
| `-b <块大小>` | 目标块大小（字节，仅 `c`，默认 1048576，上限 67108864） |
| `-j <线程数>` | 工作线程数（默认按 CPU 核数自动检测） |
| `-D <字典文件>` | 预设字典（压缩/解压共用，提升小文件压缩率） |
| `-p <密码>` | 用密码加密（`c`）或处理加密归档（`d/i/l/t`） |
| `--password <密码>` | 同 `-p`（密码会出现在进程列表） |
| `--password-file <路径>` | 从文件读取密码（忽略末尾换行） |
| `--ask-pass` | 交互式输入密码（无回显） |
| `--include <模式>` | 仅处理匹配该通配模式的路径（可多次，`*`/`?`） |
| `--exclude <模式>` | 跳过匹配该通配模式的路径（可多次，`*`/`?`） |
| `-f, --force` | 允许覆盖已存在的输出文件 |
| `-k, --keep` | 保留输入文件（默认压缩/解压成功后删除输入） |
| `-c, --progress` | 显示进度条 |

密码也可通过环境变量 `RZP_PASSWORD` 提供，优先级低于 `-p`/`--password`/`--password-file` 等显式选项。

### 示例

```bash
rzp c data.txt              # 生成 data.txt.rzp（删除 data.txt）
rzp c -k data.txt           # 生成 data.txt.rzp（保留 data.txt）
rzp c -l 9 -o out data.txt  # 最高级别压缩到 out
rzp c -D dict.bin x.txt     # 用预设字典压缩
rzp c -p secret data.txt    # 用密码加密压缩
rzp c dir/                  # 把目录打包为 dir.rzp

rzp d data.txt.rzp          # 解压回 data.txt
rzp d -D dict.bin x.rzp     # 用预设字典解压
rzp d -p secret x.rzp       # 用密码解压
rzp d dir.rzp               # 还原目录结构到 dir/

rzp i archive.rzp           # 查看归档信息
rzp l dir.rzp               # 列出目录归档内容
rzp t archive.rzp           # 校验完整性
rzp x dir.rzp sub/a.txt     # 随机抽取单个条目

cat a.txt | rzp c - > a.rzp # 从 stdin 压缩到 stdout
```

---

## 作为库使用

```rust
use rzp::{compress, decompress, Level};

let data = b"hello world, hello world, hello world";
let packed = compress(data, Level::L6);
let restored = decompress(&packed).unwrap();
assert_eq!(restored, data);
```

支持流式 `Write`/`Read`（`Encoder`/`Decoder`）、预设字典、密码加密、目录归档等，详见
[API.md](./API.md)。

---

## 文档

- [FORMAT.md](./FORMAT.md) — RZP 流 / 加密信封 / 目录归档容器的二进制格式规范。
- [API.md](./API.md) — 库公开 API 参考。
- [man/rzp.1](./man/rzp.1) — 命令行手册页。
- [ROADMAP.md](./ROADMAP.md) — 后续开发清单。

---

## 测试与模糊测试

```bash
cargo test                      # 单元测试（往返/损坏/属性测试）
cargo build --release && cargo run --release -- bench <输入>   # 与 gzip/zstd 对比
```

`fuzz/` 目录下包含基于 `cargo-fuzz` 的解压模糊测试目标（`fuzz_decompress`）与语料：

```bash
cargo install cargo-fuzz
cargo fuzz run fuzz_decompress
```

---

## 项目结构

```text
src/
├── lib.rs           # 公共 API 与便捷函数
├── bin/rzp.rs       # 命令行工具
├── stream.rs        # 流式 Encoder / Decoder
├── codec.rs         # 块级编解码
├── lz77.rs          # LZ77 匹配器
├── huffman.rs       # 限长规范 Huffman
├── bitio.rs         # MSB-first 位读写
├── crc32.rs         # CRC-32
├── format.rs        # 格式常量与查找表
├── error.rs         # 错误类型
├── archive.rs       # 目录归档容器
├── xattr.rs         # 扩展属性
└── crypto/          # ChaCha20 / Poly1305 / Argon2id / BLAKE2b / SHA-256 等原语
```

---

## 许可证

`MIT OR Apache-2.0`，详见 [LICENSE](./LICENSE)。

作者：张俊琦 `<mokaifurry@outlook.com>`
