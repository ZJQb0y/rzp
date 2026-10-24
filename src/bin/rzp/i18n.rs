//! 命令行文案的国际化：自动检测系统语言，优先支持简体中文，其余回退英文。
//!
//! 保持零第三方依赖：Unix 上读取 locale 环境变量，Windows 上调用
//! `GetUserDefaultUILanguage`（kernel32）。

use std::sync::OnceLock;

/// 当前支持的语言。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Lang {
    ZhCn,
    En,
}

/// Unix：按优先级读取 `LC_ALL` > `LC_MESSAGES` > `LANG`。
/// 仅简体中文（zh-CN / zh-SG / 无地域的 zh）映射为中文，繁体中文本地化回退英文。
#[cfg(unix)]
fn detect() -> Lang {
    for var in ["LC_ALL", "LC_MESSAGES", "LANG"] {
        if let Ok(v) = std::env::var(var) {
            if v.is_empty() {
                continue;
            }
            let lower = v.to_ascii_lowercase();
            if lower.starts_with("zh") && !is_traditional_chinese(&lower) {
                return Lang::ZhCn;
            }
            // 首个非空 locale 即决定语言，不再回退到更低优先级的变量。
            return Lang::En;
        }
    }
    Lang::En
}

/// 判断是否为繁体中文本地化（不在支持范围内，回退英文）。
#[cfg(unix)]
fn is_traditional_chinese(lower: &str) -> bool {
    lower.contains("tw")
        || lower.contains("hk")
        || lower.contains("mo")
        || lower.contains("hant")
}

/// Windows：`GetUserDefaultUILanguage` 返回 LANGID，简体中文（zh-CN / zh-SG）映射为中文。
#[cfg(windows)]
fn detect() -> Lang {
    const LANG_CHINESE: u16 = 0x04;
    const SUBLANG_CHINESE_SIMPLIFIED: u16 = 0x02;
    const SUBLANG_CHINESE_SINGAPORE: u16 = 0x04;

    #[link(name = "kernel32")]
    extern "system" {
        fn GetUserDefaultUILanguage() -> u16;
    }

    let langid = unsafe { GetUserDefaultUILanguage() };
    let primary = langid & 0x03FF;
    let sublang = (langid >> 10) & 0x003F;
    if primary == LANG_CHINESE
        && (sublang == SUBLANG_CHINESE_SIMPLIFIED || sublang == SUBLANG_CHINESE_SINGAPORE)
    {
        Lang::ZhCn
    } else {
        Lang::En
    }
}

/// 其他平台默认英文。
#[cfg(not(any(unix, windows)))]
fn detect() -> Lang {
    Lang::En
}

/// 全部可翻译文案。
pub struct Messages {
    pub usage: &'static str,
    pub error: &'static str,
    pub err_password_required: &'static str,
    pub err_auth_failed: &'static str,
    pub prompt_password: &'static str,
    pub ask_pass_requires_tty: &'static str,
    pub cannot_read_password_file: &'static str,
    pub password_empty: &'static str,
    pub unknown_command: &'static str,
    pub opt_o_requires_path: &'static str,
    pub opt_l_requires_level: &'static str,
    pub invalid_level: &'static str,
    pub opt_b_requires_size: &'static str,
    pub invalid_block_size: &'static str,
    pub block_size_range: &'static str,
    pub opt_j_requires_threads: &'static str,
    pub invalid_threads: &'static str,
    pub threads_at_least_one: &'static str,
    pub opt_d_requires_dict: &'static str,
    pub opt_p_requires_password: &'static str,
    pub opt_password_file_requires_path: &'static str,
    pub opt_include_requires_pattern: &'static str,
    pub opt_exclude_requires_pattern: &'static str,
    pub opt_argon2_memory_requires_kib: &'static str,
    pub invalid_argon2_memory: &'static str,
    pub argon2_memory_range: &'static str,
    pub opt_argon2_iters_requires_n: &'static str,
    pub invalid_argon2_iters: &'static str,
    pub argon2_iters_range: &'static str,
    pub opt_argon2_lanes_requires_n: &'static str,
    pub invalid_argon2_lanes: &'static str,
    pub argon2_lanes_range: &'static str,
    pub unknown_option: &'static str,
    pub missing_input: &'static str,
    pub stdin_multi_input: &'static str,
    pub output_single_input: &'static str,
    pub cannot_read_dir: &'static str,
    pub read_dir_entry_failed: &'static str,
    pub cannot_read_metadata: &'static str,
    pub status_compressed: &'static str,
    pub status_decompressed: &'static str,
    pub bytes: &'static str,
    pub dir_archive: &'static str,
    pub dir_archive_bytes: &'static str,
    pub file: &'static str,
    pub level: &'static str,
    pub raw_size: &'static str,
    pub compressed_size: &'static str,
    pub ratio: &'static str,
    pub dictionary: &'static str,
    pub blocks: &'static str,
    pub yes: &'static str,
    pub no: &'static str,
    pub compressed_word: &'static str,
    pub stored_word: &'static str,
    pub type_label: &'static str,
    pub indexed_dir_archive: &'static str,
    pub entry_count: &'static str,
    pub composition: &'static str,
    pub composition_files: &'static str,
    pub entry_data_size: &'static str,
    pub archive_size: &'static str,
    pub encrypted: &'static str,
    pub outer_archive_size: &'static str,
    pub verified: &'static str,
    pub indexed_dir_archive_short: &'static str,
    pub verified_detail: &'static str,
    pub archive: &'static str,
    pub not_dir_archive: &'static str,
    pub extract_usage: &'static str,
    pub extract_requires_indexed: &'static str,
    pub extracted: &'static str,
    pub bench_no_input: &'static str,
    pub bench_no_files: &'static str,
    pub cannot_read_file: &'static str,
    pub cannot_access: &'static str,
    pub not_file_or_dir: &'static str,
    pub cannot_start_program: &'static str,
    pub cannot_get_stdin: &'static str,
    pub program_nonzero_exit: &'static str,
    pub bench_title: &'static str,
    pub bench_header_file: &'static str,
    pub bench_header_orig: &'static str,
    pub bench_header_comp_size: &'static str,
    pub bench_header_ratio: &'static str,
    pub bench_header_comp_time: &'static str,
    pub bench_header_decomp_time: &'static str,
    pub bench_header_verify: &'static str,
    pub bench_summary: &'static str,
    pub bench_summary_fmt: &'static str,
    pub bench_na: &'static str,
    pub cannot_read_dict: &'static str,
    pub output_exists: &'static str,
    pub cannot_read_temp: &'static str,
    pub warn_cannot_remove_input: &'static str,
    pub warn_output_inside_input: &'static str,
    pub warn_cannot_remove_dir: &'static str,
    pub dir_archive_no_stdout: &'static str,
    pub output_exists_force: &'static str,
    pub completion_usage: &'static str,
    pub unknown_shell: &'static str,
    pub corrupt_data: &'static str,
    pub bash_completion: &'static str,
    pub zsh_completion: &'static str,
    pub fish_completion: &'static str,
}

/// 返回当前语言对应的文案表（探测结果缓存）。
pub fn messages() -> &'static Messages {
    static LANG: OnceLock<Lang> = OnceLock::new();
    if *LANG.get_or_init(detect) == Lang::ZhCn {
        &ZH
    } else {
        &EN
    }
}

/// 依次用 `args` 替换模板中的 `{}` 占位符，返回完整字符串。
/// 由于 `format!` 要求字面量格式串，这里用少量替换逻辑避免引入依赖。
pub fn fmt(template: &str, args: &[String]) -> String {
    let mut out = String::with_capacity(template.len() + 16);
    let mut rest = template;
    for arg in args {
        if let Some(pos) = rest.find("{}") {
            out.push_str(&rest[..pos]);
            out.push_str(arg);
            rest = &rest[pos + 2..];
        } else {
            break;
        }
    }
    out.push_str(rest);
    out
}

const ZH: Messages = Messages {
    usage: r#"RZP 压缩工具

用法:
  rzp c [选项] <输入>...    压缩文件或目录（目录打包为单个 .rzp）
  rzp d [选项] <输入>...    解压文件或目录归档（目录输入递归处理其中的 .rzp）
  rzp i <输入>...           查看归档信息（不解压）
  rzp l <输入>...           列出目录归档内容（不解出内容）
  rzp t <输入>...           校验文件完整性（不解出内容）
  rzp x <归档> <条目路径>    从目录归档随机抽取单个条目
  rzp bench [选项] <输入>...  与 gzip/zstd 对比压缩率与速度（文件或目录）
  rzp completion <shell>    输出 shell 补全脚本（bash/zsh/fish）
  rzp --help                显示帮助
  rzp --version             显示版本

输入/输出路径可用 "-" 表示 stdin/stdout（仅限单个输入）。

命令选项 (c / d):
  -o <路径>       指定输出文件（仅单个输入）
  -l <0-9>        压缩级别（仅 c，默认 6）
  -b <块大小>     目标块大小（字节，仅 c，默认 1048576，上限 67108864）
  -j <线程数>     工作线程数（默认按 CPU 核数自动检测）
  -D <字典文件>   预设字典（压缩/解压共用，提升小文件压缩率）
  -p <密码>       用密码加密（c）或处理加密归档（d/i/l/t）
  --password <密码>  同 -p（密码会出现在进程列表，注意安全）
  --password-file <路径>  从文件读取密码（忽略末尾换行）
  --ask-pass       交互式输入密码（无回显）
  （环境变量 RZP_PASSWORD 也可提供密码，优先级低于上述显式选项）
  --argon2-memory <KiB>  Argon2id 内存成本（仅 c，默认 65536，上限 2097152）
  --argon2-iters <n>     Argon2id 迭代次数（仅 c，默认 3，上限 1024）
  --argon2-lanes <n>     Argon2id 并行度（仅 c，默认 4，上限 256）
  --strong-checksum     使用 BLAKE2b-256 强校验（仅 c，默认 CRC-32）
  --include <模式>  仅处理匹配该通配模式的路径（可多次，`*`/`?`）
  --exclude <模式>  跳过匹配该通配模式的路径（可多次，`*`/`?`）
  -f, --force     允许覆盖已存在的输出文件
  -k, --keep      保留输入文件（默认压缩/解压成功后删除输入文件）
  -c, --progress  显示进度条

示例:
  rzp c data.txt              -> 生成 data.txt.rzp（删除 data.txt）
  rzp c -k data.txt           -> 生成 data.txt.rzp（保留 data.txt）
  rzp c -l 9 -o out data.txt  -> 以最高级别压缩到 out
  rzp c -D dict.bin x.txt     -> 用预设字典压缩
  rzp c -p secret data.txt    -> 用密码加密压缩
  rzp c dir/                  -> 把目录打包为 dir.rzp（保留目录结构/空目录/符号链接/权限/时间戳）
  rzp d -D dict.bin x.rzp     -> 用预设字典解压
  rzp d -p secret x.rzp       -> 用密码解压
  rzp d data.txt.rzp          -> 解压回 data.txt（删除 data.txt.rzp）
  rzp d dir.rzp               -> 还原目录结构到 dir/
  rzp d dir/                  -> 递归解压目录下所有 .rzp 文件
  rzp i archive.rzp           -> 查看归档信息
  rzp i -p secret archive.rzp -> 查看加密归档信息
  rzp t archive.rzp           -> 校验完整性
  rzp t -p secret archive.rzp -> 校验加密归档
  cat a.txt | rzp c - > a.rzp -> 从 stdin 压缩到 stdout
"#,
    error: "错误",
    err_password_required: "归档已加密，请用 -p/--password/--password-file/RZP_PASSWORD 或 --ask-pass 提供密码",
    err_auth_failed: "密码错误或归档数据被篡改（认证失败）",
    prompt_password: "请输入密码: ",
    ask_pass_requires_tty: "--ask-pass 需要交互式终端（stdin 不是终端）",
    cannot_read_password_file: "无法读取密码文件 {}: {}",
    password_empty: "密码不能为空",
    unknown_command: "未知命令",
    opt_o_requires_path: "-o 需要一个路径参数",
    opt_l_requires_level: "-l 需要一个 0-9 的级别参数",
    invalid_level: "无效的压缩级别: {}",
    opt_b_requires_size: "-b/--block-size 需要一个块大小参数",
    invalid_block_size: "无效的块大小: {}",
    block_size_range: "块大小必须在 1..={} 之间",
    opt_j_requires_threads: "-j/--threads 需要一个线程数参数",
    invalid_threads: "无效的线程数: {}",
    threads_at_least_one: "线程数必须 >= 1",
    opt_d_requires_dict: "-D 需要一个字典文件参数",
    opt_p_requires_password: "-p/--password 需要一个密码参数",
    opt_password_file_requires_path: "--password-file 需要一个文件路径参数",
    opt_include_requires_pattern: "--include 需要一个模式参数",
    opt_exclude_requires_pattern: "--exclude 需要一个模式参数",
    opt_argon2_memory_requires_kib: "--argon2-memory 需要一个 KiB 参数",
    invalid_argon2_memory: "无效的 Argon2id 内存成本: {}",
    argon2_memory_range: "Argon2id 内存成本必须在 1..={} KiB 之间",
    opt_argon2_iters_requires_n: "--argon2-iters 需要一个迭代次数参数",
    invalid_argon2_iters: "无效的 Argon2id 迭代次数: {}",
    argon2_iters_range: "Argon2id 迭代次数必须在 1..={} 之间",
    opt_argon2_lanes_requires_n: "--argon2-lanes 需要一个车道数参数",
    invalid_argon2_lanes: "无效的 Argon2id 车道数: {}",
    argon2_lanes_range: "Argon2id 车道数必须在 1..={} 之间",
    unknown_option: "未知选项: {}",
    missing_input: "缺少输入文件",
    stdin_multi_input: "stdin（-）不能与多个输入一起使用",
    output_single_input: "-o 只能用于单个输入",
    cannot_read_dir: "无法读取目录 {}: {}",
    read_dir_entry_failed: "读取目录项失败: {}",
    cannot_read_metadata: "无法读取元数据 {}: {}",
    status_compressed: "压缩完成",
    status_decompressed: "解压完成",
    bytes: "字节",
    dir_archive: "（目录归档）",
    dir_archive_bytes: "（目录归档, {} 字节）",
    file: "文件",
    level: "压缩级别",
    raw_size: "原始大小",
    compressed_size: "压缩大小",
    ratio: "压缩率",
    dictionary: "预设字典",
    blocks: "块数",
    yes: "是",
    no: "否",
    compressed_word: "压缩",
    stored_word: "存储",
    type_label: "类型",
    indexed_dir_archive: "索引目录归档（RZPA）",
    entry_count: "条目数",
    composition: "构成",
    composition_files: "{} 文件 / {} 目录 / {} 符号链接",
    entry_data_size: "条目数据大小",
    archive_size: "归档大小",
    encrypted: "加密",
    outer_archive_size: "外层归档大小",
    verified: "校验通过",
    indexed_dir_archive_short: "（索引目录归档）",
    verified_detail: "(级别 {}, 共 {} 字节)",
    archive: "归档",
    not_dir_archive: "{} 不是目录归档",
    extract_usage: "rzp x 需要两个参数：归档文件 与 条目路径",
    extract_requires_indexed: "按条目抽取需要索引式目录归档（旧式 solid 归档请先整体解压）",
    extracted: "已抽取",
    bench_no_input: "rzp bench 需要至少一个输入文件或目录",
    bench_no_files: "未找到可基准测试的文件",
    cannot_read_file: "无法读取 {}: {}",
    cannot_access: "无法访问 {}: {}",
    not_file_or_dir: "不是文件或目录: {}",
    cannot_start_program: "无法启动 {}: {}",
    cannot_get_stdin: "无法获取子进程 stdin",
    program_nonzero_exit: "{} 退出码非零",
    bench_title: "RZP 基准对比（压缩率越低越好，时间越短越好）",
    bench_header_file: "文件",
    bench_header_orig: "原始",
    bench_header_comp_size: "压缩大小",
    bench_header_ratio: "压缩比",
    bench_header_comp_time: "压缩耗时",
    bench_header_decomp_time: "解压耗时",
    bench_header_verify: "校验",
    bench_summary: "汇总",
    bench_summary_fmt: "原始: {}    rzp: {} ({})    gzip: {} ({})    zstd: {} ({})",
    bench_na: "n/a（未安装）",
    cannot_read_dict: "无法读取字典 {}: {}",
    output_exists: "输出文件已存在: {}（使用 -f 覆盖）",
    cannot_read_temp: "无法读取临时文件 {}: {}",
    warn_cannot_remove_input: "警告: 无法删除输入文件 {}: {}",
    warn_output_inside_input: "警告: 输出归档位于输入目录内，未删除输入目录 {}",
    warn_cannot_remove_dir: "警告: 无法删除输入目录 {}: {}",
    dir_archive_no_stdout: "目录归档无法解压到 stdout",
    output_exists_force: "输出已存在: {}（使用 -f 覆盖）",
    completion_usage: "用法: rzp completion <shell>（支持: bash zsh fish）",
    unknown_shell: "未知 shell: {}（支持: bash zsh fish）",
    corrupt_data: "未知或损坏的 RZP 数据",
    bash_completion: r##"# rzp 补全（bash）
_rzp_complete() {
    local cur prev sub i
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    local subcmds="c d i l t x bench completion"
    local opts="-o -l -b -j -D -p --password --password-file --ask-pass --argon2-memory --argon2-iters --argon2-lanes --strong-checksum --include --exclude -f --force -k --keep --progress"

    sub=""
    for ((i = 1; i < COMP_CWORD; i++)); do
        case "${COMP_WORDS[i]}" in
            c|d|i|l|t|x|bench|completion) sub="${COMP_WORDS[i]}" ;;
        esac
    done

    if [[ -z "$sub" ]]; then
        COMPREPLY=( $(compgen -W "$subcmds" -- "$cur") )
        return 0
    fi

    case "$prev" in
        -o|-D|--password-file) COMPREPLY=( $(compgen -f -- "$cur") ); return 0 ;;
        -l) COMPREPLY=( $(compgen -W "0 1 2 3 4 5 6 7 8 9" -- "$cur") ); return 0 ;;
    esac

    if [[ "$cur" == -* ]]; then
        COMPREPLY=( $(compgen -W "$opts" -- "$cur") )
    else
        COMPREPLY=( $(compgen -f -- "$cur") )
    fi
}
complete -F _rzp_complete rzp
"##,
    zsh_completion: r##"#compdef rzp
_rzp() {
    local -a subcmds
    subcmds=(c d i l t x bench completion)
    if (( CURRENT == 2 )); then
        _describe 'command' subcmds
        return
    fi
    _arguments \
        '-o[输出文件]:文件:_files' \
        '-l[压缩级别 0-9]:级别:(0 1 2 3 4 5 6 7 8 9)' \
        '--block-size[目标块大小]:字节数:' \
        '-j[工作线程数]:线程数:' \
        '-D[预设字典文件]:字典:_files' \
        '--password[密码]:密码:' \
        '--password-file[从文件读取密码]:密码文件:_files' \
        '--ask-pass[交互式输入密码]' \
        '--argon2-memory[Argon2id 内存成本(KiB)]:KiB:' \
        '--argon2-iters[Argon2id 迭代次数]:次数:' \
        '--argon2-lanes[Argon2id 并行度]:车道数:' \
        '--strong-checksum[使用 BLAKE2b-256 强校验]' \
        '--include[包含通配模式]:模式:' \
        '--exclude[排除通配模式]:模式:' \
        '--force[覆盖已存在文件]' \
        '--keep[保留输入文件]' \
        '--progress[显示进度条]' \
        '*:文件:_files'
}
_rzp "$@"
"##,
    fish_completion: r##"# rzp 补全（fish）
complete -c rzp -f

complete -c rzp -n '__fish_use_subcommand' -a c -d '压缩'
complete -c rzp -n '__fish_use_subcommand' -a d -d '解压'
complete -c rzp -n '__fish_use_subcommand' -a i -d '查看归档信息'
complete -c rzp -n '__fish_use_subcommand' -a l -d '列出目录归档内容'
complete -c rzp -n '__fish_use_subcommand' -a t -d '校验完整性'
complete -c rzp -n '__fish_use_subcommand' -a x -d '随机抽取单个条目'
complete -c rzp -n '__fish_use_subcommand' -a bench -d '基准对比'
complete -c rzp -n '__fish_use_subcommand' -a completion -d '输出补全脚本'

complete -c rzp -s o -r -d '指定输出文件'
complete -c rzp -s l -r -a '0 1 2 3 4 5 6 7 8 9' -d '压缩级别'
complete -c rzp -s b -r -d '目标块大小（字节）'
complete -c rzp -s j -r -d '工作线程数'
complete -c rzp -s D -r -d '预设字典文件'
complete -c rzp -s p -r -d '密码'
complete -c rzp -l password -r -d '密码'
complete -c rzp -l password-file -r -d '从文件读取密码'
complete -c rzp -l ask-pass -d '交互式输入密码'
complete -c rzp -l argon2-memory -r -d 'Argon2id 内存成本(KiB)'
complete -c rzp -l argon2-iters -r -d 'Argon2id 迭代次数'
complete -c rzp -l argon2-lanes -r -d 'Argon2id 并行度'
complete -c rzp -l strong-checksum -d '使用 BLAKE2b-256 强校验'
complete -c rzp -l include -r -d '包含通配模式'
complete -c rzp -l exclude -r -d '排除通配模式'
complete -c rzp -s f -l force -d '覆盖已存在文件'
complete -c rzp -s k -l keep -d '保留输入文件'
complete -c rzp -l progress -d '显示进度条'
"##,
};

const EN: Messages = Messages {
    usage: r#"RZP compression tool

Usage:
  rzp c [options] <input>...    Compress files or directories (a directory is packed into a single .rzp)
  rzp d [options] <input>...    Decompress files or directory archives (a directory input recursively processes .rzp files inside)
  rzp i <input>...              Show archive information (without decompressing)
  rzp l <input>...              List directory archive contents (without extracting)
  rzp t <input>...              Verify file integrity (without extracting)
  rzp x <archive> <entry>       Extract a single entry from a directory archive
  rzp bench [options] <input>...  Compare compression ratio and speed against gzip/zstd (file or directory)
  rzp completion <shell>        Print a shell completion script (bash/zsh/fish)
  rzp --help                    Show help
  rzp --version                 Show version

Input/output paths may use "-" for stdin/stdout (single input only).

Command options (c / d):
  -o <path>         Specify output file (single input only)
  -l <0-9>          Compression level (c only, default 6)
  -b <block size>   Target block size in bytes (c only, default 1048576, max 67108864)
  -j <threads>      Worker thread count (auto-detected from CPU cores by default)
  -D <dict file>    Preset dictionary (shared by compress/decompress, improves small-file ratio)
  -p <password>     Encrypt with password (c) or process encrypted archives (d/i/l/t)
  --password <password>  Same as -p (password appears in the process list; use with care)
  --password-file <path>  Read password from file (trailing newline ignored)
  --ask-pass        Prompt for password interactively (no echo)
  (environment variable RZP_PASSWORD can also provide a password, with lower priority than the explicit options above)
  --argon2-memory <KiB>  Argon2id memory cost (c only, default 65536, max 2097152)
  --argon2-iters <n>     Argon2id iteration count (c only, default 3, max 1024)
  --argon2-lanes <n>     Argon2id parallelism (c only, default 4, max 256)
  --strong-checksum     Use BLAKE2b-256 strong checksum (c only, default CRC-32)
  --include <pattern>  Only process paths matching this glob (repeatable, `*`/`?`)
  --exclude <pattern>  Skip paths matching this glob (repeatable, `*`/`?`)
  -f, --force     Allow overwriting an existing output file
  -k, --keep      Keep input files (by default inputs are removed after successful compress/decompress)
  -c, --progress  Show a progress bar

Examples:
  rzp c data.txt              -> create data.txt.rzp (remove data.txt)
  rzp c -k data.txt           -> create data.txt.rzp (keep data.txt)
  rzp c -l 9 -o out data.txt  -> compress to out at the highest level
  rzp c -D dict.bin x.txt     -> compress with a preset dictionary
  rzp c -p secret data.txt    -> compress with password encryption
  rzp c dir/                  -> pack dir into dir.rzp (preserving structure/empty dirs/symlinks/permissions/timestamps)
  rzp d -D dict.bin x.rzp     -> decompress with a preset dictionary
  rzp d -p secret x.rzp       -> decompress with a password
  rzp d data.txt.rzp          -> decompress back to data.txt (remove data.txt.rzp)
  rzp d dir.rzp               -> restore directory structure to dir/
  rzp d dir/                  -> recursively decompress all .rzp files under dir
  rzp i archive.rzp           -> show archive information
  rzp i -p secret archive.rzp -> show encrypted archive information
  rzp t archive.rzp           -> verify integrity
  rzp t -p secret archive.rzp -> verify an encrypted archive
  cat a.txt | rzp c - > a.rzp -> compress from stdin to stdout
"#,
    error: "error",
    err_password_required: "archive is encrypted; provide a password via -p/--password/--password-file/RZP_PASSWORD or --ask-pass",
    err_auth_failed: "wrong password or corrupted archive data (authentication failed)",
    prompt_password: "Enter password: ",
    ask_pass_requires_tty: "--ask-pass requires an interactive terminal (stdin is not a terminal)",
    cannot_read_password_file: "cannot read password file {}: {}",
    password_empty: "password must not be empty",
    unknown_command: "Unknown command",
    opt_o_requires_path: "-o requires a path argument",
    opt_l_requires_level: "-l requires a level argument (0-9)",
    invalid_level: "invalid compression level: {}",
    opt_b_requires_size: "-b/--block-size requires a block size argument",
    invalid_block_size: "invalid block size: {}",
    block_size_range: "block size must be between 1..={}",
    opt_j_requires_threads: "-j/--threads requires a thread count argument",
    invalid_threads: "invalid thread count: {}",
    threads_at_least_one: "thread count must be >= 1",
    opt_d_requires_dict: "-D requires a dictionary file argument",
    opt_p_requires_password: "-p/--password requires a password argument",
    opt_password_file_requires_path: "--password-file requires a file path argument",
    opt_include_requires_pattern: "--include requires a pattern argument",
    opt_exclude_requires_pattern: "--exclude requires a pattern argument",
    opt_argon2_memory_requires_kib: "--argon2-memory requires a KiB argument",
    invalid_argon2_memory: "invalid Argon2id memory cost: {}",
    argon2_memory_range: "Argon2id memory cost must be between 1..={} KiB",
    opt_argon2_iters_requires_n: "--argon2-iters requires an iteration count argument",
    invalid_argon2_iters: "invalid Argon2id iteration count: {}",
    argon2_iters_range: "Argon2id iteration count must be between 1..={}",
    opt_argon2_lanes_requires_n: "--argon2-lanes requires a lane count argument",
    invalid_argon2_lanes: "invalid Argon2id lane count: {}",
    argon2_lanes_range: "Argon2id lane count must be between 1..={}",
    unknown_option: "unknown option: {}",
    missing_input: "missing input file",
    stdin_multi_input: "stdin (-) cannot be combined with multiple inputs",
    output_single_input: "-o can only be used with a single input",
    cannot_read_dir: "cannot read directory {}: {}",
    read_dir_entry_failed: "failed to read directory entry: {}",
    cannot_read_metadata: "cannot read metadata {}: {}",
    status_compressed: "Compressed",
    status_decompressed: "Decompressed",
    bytes: "bytes",
    dir_archive: "(directory archive)",
    dir_archive_bytes: "(directory archive, {} bytes)",
    file: "File",
    level: "Compression level",
    raw_size: "Original size",
    compressed_size: "Compressed size",
    ratio: "Compression ratio",
    dictionary: "Preset dictionary",
    blocks: "Blocks",
    yes: "yes",
    no: "no",
    compressed_word: "compressed",
    stored_word: "stored",
    type_label: "Type",
    indexed_dir_archive: "indexed directory archive (RZPA)",
    entry_count: "Entries",
    composition: "Composition",
    composition_files: "{} files / {} dirs / {} symlinks",
    entry_data_size: "Entry data size",
    archive_size: "Archive size",
    encrypted: "Encrypted",
    outer_archive_size: "Outer archive size",
    verified: "Verified",
    indexed_dir_archive_short: "(indexed directory archive)",
    verified_detail: "(level {}, {} bytes total)",
    archive: "Archive",
    not_dir_archive: "{} is not a directory archive",
    extract_usage: "rzp x requires two arguments: archive file and entry path",
    extract_requires_indexed: "extracting by entry requires an indexed directory archive (for legacy solid archives, decompress the whole archive first)",
    extracted: "Extracted",
    bench_no_input: "rzp bench requires at least one input file or directory",
    bench_no_files: "no files found to benchmark",
    cannot_read_file: "cannot read {}: {}",
    cannot_access: "cannot access {}: {}",
    not_file_or_dir: "not a file or directory: {}",
    cannot_start_program: "cannot start {}: {}",
    cannot_get_stdin: "cannot get child process stdin",
    program_nonzero_exit: "{} exited with non-zero status",
    bench_title: "RZP benchmark (lower ratio is better, shorter time is better)",
    bench_header_file: "file",
    bench_header_orig: "orig",
    bench_header_comp_size: "comp size",
    bench_header_ratio: "ratio",
    bench_header_comp_time: "comp time",
    bench_header_decomp_time: "decomp time",
    bench_header_verify: "verify",
    bench_summary: "Summary",
    bench_summary_fmt: "orig: {}    rzp: {} ({})    gzip: {} ({})    zstd: {} ({})",
    bench_na: "n/a (not installed)",
    cannot_read_dict: "cannot read dictionary {}: {}",
    output_exists: "output file already exists: {} (use -f to overwrite)",
    cannot_read_temp: "cannot read temp file {}: {}",
    warn_cannot_remove_input: "warning: cannot remove input file {}: {}",
    warn_output_inside_input: "warning: output archive is inside the input directory; input directory {} not removed",
    warn_cannot_remove_dir: "warning: cannot remove input directory {}: {}",
    dir_archive_no_stdout: "directory archive cannot be decompressed to stdout",
    output_exists_force: "output already exists: {} (use -f to overwrite)",
    completion_usage: "usage: rzp completion <shell> (supported: bash zsh fish)",
    unknown_shell: "unknown shell: {} (supported: bash zsh fish)",
    corrupt_data: "unknown or corrupted RZP data",
    bash_completion: r##"# rzp completion (bash)
_rzp_complete() {
    local cur prev sub i
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    local subcmds="c d i l t x bench completion"
    local opts="-o -l -b -j -D -p --password --password-file --ask-pass --argon2-memory --argon2-iters --argon2-lanes --strong-checksum --include --exclude -f --force -k --keep --progress"

    sub=""
    for ((i = 1; i < COMP_CWORD; i++)); do
        case "${COMP_WORDS[i]}" in
            c|d|i|l|t|x|bench|completion) sub="${COMP_WORDS[i]}" ;;
        esac
    done

    if [[ -z "$sub" ]]; then
        COMPREPLY=( $(compgen -W "$subcmds" -- "$cur") )
        return 0
    fi

    case "$prev" in
        -o|-D|--password-file) COMPREPLY=( $(compgen -f -- "$cur") ); return 0 ;;
        -l) COMPREPLY=( $(compgen -W "0 1 2 3 4 5 6 7 8 9" -- "$cur") ); return 0 ;;
    esac

    if [[ "$cur" == -* ]]; then
        COMPREPLY=( $(compgen -W "$opts" -- "$cur") )
    else
        COMPREPLY=( $(compgen -f -- "$cur") )
    fi
}
complete -F _rzp_complete rzp
"##,
    zsh_completion: r##"#compdef rzp
_rzp() {
    local -a subcmds
    subcmds=(c d i l t x bench completion)
    if (( CURRENT == 2 )); then
        _describe 'command' subcmds
        return
    fi
    _arguments \
        '-o[output file]:file:_files' \
        '-l[compression level 0-9]:level:(0 1 2 3 4 5 6 7 8 9)' \
        '--block-size[target block size]:bytes:' \
        '-j[worker threads]:threads:' \
        '-D[preset dictionary file]:dictionary:_files' \
        '--password[password]:password:' \
        '--password-file[read password from file]:password file:_files' \
        '--ask-pass[prompt for password interactively]' \
        '--argon2-memory[Argon2id memory cost (KiB)]:KiB:' \
        '--argon2-iters[Argon2id iteration count]:count:' \
        '--argon2-lanes[Argon2id parallelism]:lanes:' \
        '--strong-checksum[use BLAKE2b-256 strong checksum]' \
        '--include[include glob pattern]:pattern:' \
        '--exclude[exclude glob pattern]:pattern:' \
        '--force[overwrite existing files]' \
        '--keep[keep input files]' \
        '--progress[show progress bar]' \
        '*:file:_files'
}
_rzp "$@"
"##,
    fish_completion: r##"# rzp completion (fish)
complete -c rzp -f

complete -c rzp -n '__fish_use_subcommand' -a c -d 'Compress'
complete -c rzp -n '__fish_use_subcommand' -a d -d 'Decompress'
complete -c rzp -n '__fish_use_subcommand' -a i -d 'Show archive information'
complete -c rzp -n '__fish_use_subcommand' -a l -d 'List directory archive contents'
complete -c rzp -n '__fish_use_subcommand' -a t -d 'Verify integrity'
complete -c rzp -n '__fish_use_subcommand' -a x -d 'Extract a single entry'
complete -c rzp -n '__fish_use_subcommand' -a bench -d 'Benchmark comparison'
complete -c rzp -n '__fish_use_subcommand' -a completion -d 'Print completion script'

complete -c rzp -s o -r -d 'Specify output file'
complete -c rzp -s l -r -a '0 1 2 3 4 5 6 7 8 9' -d 'Compression level'
complete -c rzp -s b -r -d 'Target block size (bytes)'
complete -c rzp -s j -r -d 'Worker thread count'
complete -c rzp -s D -r -d 'Preset dictionary file'
complete -c rzp -s p -r -d 'Password'
complete -c rzp -l password -r -d 'Password'
complete -c rzp -l password-file -r -d 'Read password from file'
complete -c rzp -l ask-pass -d 'Prompt for password interactively'
complete -c rzp -l argon2-memory -r -d 'Argon2id memory cost (KiB)'
complete -c rzp -l argon2-iters -r -d 'Argon2id iteration count'
complete -c rzp -l argon2-lanes -r -d 'Argon2id parallelism'
complete -c rzp -l strong-checksum -d 'Use BLAKE2b-256 strong checksum'
complete -c rzp -l include -r -d 'Include glob pattern'
complete -c rzp -l exclude -r -d 'Exclude glob pattern'
complete -c rzp -s f -l force -d 'Overwrite existing files'
complete -c rzp -s k -l keep -d 'Keep input files'
complete -c rzp -l progress -d 'Show progress bar'
"##,
};
