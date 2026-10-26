//! RZP 命令行工具（无第三方依赖）。

use std::fs::File;
use std::io::{BufReader, BufWriter, IsTerminal, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use rzp::{Decoder, Encoder, Level, Result};

#[path = "rzp/i18n.rs"]
mod i18n;

/// 用模板中的 `{}` 占位符依次替换参数（参数自动字符串化）。
macro_rules! tr {
    ($template:expr $(, $arg:expr)* $(,)?) => {
        i18n::fmt($template, &[$($arg.to_string()),*])
    };
}

/// 当前语言的文案表（自动检测系统语言，结果缓存）。
fn msgs() -> &'static i18n::Messages {
    i18n::messages()
}

/// 终端 ANSI 颜色支持：零依赖，非终端（重定向/管道）自动禁用。
mod style {
    use std::io::IsTerminal;
    use std::sync::OnceLock;

    const RESET: &str = "\x1b[0m";

    #[derive(Clone, Copy)]
    pub enum Color {
        Red,
        Green,
        Yellow,
        Cyan,
        Bold,
    }

    fn code(c: Color) -> &'static str {
        match c {
            Color::Red => "\x1b[31m",
            Color::Green => "\x1b[32m",
            Color::Yellow => "\x1b[33m",
            Color::Cyan => "\x1b[36m",
            Color::Bold => "\x1b[1m",
        }
    }

    /// `enabled` 为真时包裹 ANSI 转义，否则原样返回。
    pub fn paint(s: &str, c: Color, enabled: bool) -> String {
        if enabled {
            format!("{}{}{}", code(c), s, RESET)
        } else {
            s.to_string()
        }
    }

    pub fn stdout_tty() -> bool {
        static TTY: OnceLock<bool> = OnceLock::new();
        *TTY.get_or_init(|| std::io::stdout().is_terminal())
    }

    pub fn stderr_tty() -> bool {
        static TTY: OnceLock<bool> = OnceLock::new();
        *TTY.get_or_init(|| std::io::stderr().is_terminal())
    }
}

/// 把帮助文本渲染为带颜色的文本；`tty` 为真时上色，否则输出纯文本。
fn render_usage(tty: bool) -> String {
    let mut out = String::new();
    for line in msgs().usage.lines() {
        out.push_str(&highlight_line(line, tty));
        out.push('\n');
    }
    out
}

fn highlight_line(line: &str, tty: bool) -> String {
    let trimmed = line.trim_start();
    if trimmed.starts_with("RZP ") {
        style::paint(line, style::Color::Bold, tty)
    } else if trimmed.starts_with("rzp ") {
        highlight_rzp_line(line, tty)
    } else if trimmed.starts_with('-') {
        highlight_option_line(line, tty)
    } else {
        line.to_string()
    }
}

/// 给 `  rzp <命令> ...` 行上色：`rzp` 用青色、命令字用黄色。
fn highlight_rzp_line(line: &str, tty: bool) -> String {
    let lead = line.len() - line.trim_start().len();
    let body = &line[lead..];
    let cmd_end = body.find(' ').unwrap_or(body.len());
    let cmd = &body[..cmd_end];
    let after = body[cmd_end..].trim_start();
    let arg_end = after.find(' ').unwrap_or(after.len());
    let arg = &after[..arg_end];
    let tail = &after[arg_end..];
    format!(
        "{}{} {}{}",
        &line[..lead],
        style::paint(cmd, style::Color::Cyan, tty),
        style::paint(arg, style::Color::Yellow, tty),
        tail
    )
}

/// 给选项行上色：选项名（到说明文字前的双空格为止）用绿色。
fn highlight_option_line(line: &str, tty: bool) -> String {
    let lead = line.len() - line.trim_start().len();
    let body = &line[lead..];
    let opt_end = body
        .as_bytes()
        .windows(2)
        .position(|w| w == b"  ")
        .unwrap_or(body.len());
    format!(
        "{}{}{}",
        &line[..lead],
        style::paint(&body[..opt_end], style::Color::Green, tty),
        &body[opt_end..]
    )
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!(
                "{}: {}",
                style::paint(msgs().error, style::Color::Red, style::stderr_tty()),
                format_error(&e)
            );
            ExitCode::FAILURE
        }
    }
}

/// 把库错误映射为清晰的中文提示。
fn format_error(e: &rzp::Error) -> String {
    match e {
        rzp::Error::PasswordRequired => msgs().err_password_required.to_string(),
        rzp::Error::AuthFailed => msgs().err_auth_failed.to_string(),
        other => other.to_string(),
    }
}

/// 密码来源的环境变量名。
const PASSWORD_ENV: &str = "RZP_PASSWORD";

/// 按优先级解析密码：`-p`/`--password` > `--password-file` > `RZP_PASSWORD` >
/// 交互式无回显提示（仅当 `prompt_if_missing` 为真且 stdin 是终端）。
fn resolve_password(opts: &Opts, prompt_if_missing: bool) -> Result<Option<String>> {
    if let Some(pw) = &opts.password {
        return Ok(Some(pw.clone()));
    }
    if let Some(path) = &opts.password_file {
        return read_password_file(path).map(Some);
    }
    if let Ok(pw) = std::env::var(PASSWORD_ENV) {
        if !pw.is_empty() {
            return Ok(Some(pw));
        }
    }
    if prompt_if_missing && std::io::stdin().is_terminal() {
        return prompt_password(msgs().prompt_password).map(Some);
    }
    if opts.ask_pass && !std::io::stdin().is_terminal() {
        return Err(rzp::Error::Io(msgs().ask_pass_requires_tty.into()));
    }
    Ok(None)
}

/// 读取 `--password-file` 指定的密码文件，忽略末尾单个换行/回车。
fn read_password_file(path: &Path) -> Result<String> {
    let raw = std::fs::read(path)
        .map_err(|e| rzp::Error::Io(tr!(msgs().cannot_read_password_file, path.display(), e)))?;
    Ok(String::from_utf8_lossy(&raw)
        .trim_end_matches(['\n', '\r'])
        .to_string())
}

/// 交互式无回显读取一行密码。
fn prompt_password(prompt: &str) -> Result<String> {
    eprint!("{prompt}");
    std::io::stderr().flush()?;
    let pw = read_password_no_echo()?;
    eprintln!();
    if pw.is_empty() {
        return Err(rzp::Error::Io(msgs().password_empty.into()));
    }
    Ok(pw)
}

/// 从 stdin 读取一行并去掉行尾换行。Unix 上禁用回显；其他平台退回普通读行。
#[cfg(not(unix))]
fn read_password_no_echo() -> Result<String> {
    use std::io::BufRead;
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    Ok(line.trim_end_matches(['\n', '\r']).to_string())
}

/// Unix 上的无回显读取：临时清除终端 ECHO 标志，读完后恢复。
#[cfg(unix)]
fn read_password_no_echo() -> Result<String> {
    use std::io::BufRead;

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Termios {
        c_iflag: u32,
        c_oflag: u32,
        c_cflag: u32,
        c_lflag: u32,
        c_line: u8,
        c_cc: [u8; 32],
        c_ispeed: u32,
        c_ospeed: u32,
    }

    const ECHO: u32 = 0o0000010; // 0x0008
    const TCSANOW: i32 = 0;
    const STDIN_FILENO: i32 = 0;

    extern "C" {
        fn tcgetattr(fd: i32, termios_p: *mut Termios) -> i32;
        fn tcsetattr(fd: i32, optional_actions: i32, termios_p: *const Termios) -> i32;
    }

    struct TermiosGuard {
        fd: i32,
        original: Termios,
    }
    impl Drop for TermiosGuard {
        fn drop(&mut self) {
            unsafe {
                tcsetattr(self.fd, TCSANOW, &self.original);
            }
        }
    }

    fn read_line_plain() -> Result<String> {
        let mut line = String::new();
        std::io::stdin().lock().read_line(&mut line)?;
        Ok(line.trim_end_matches(['\n', '\r']).to_string())
    }

    let mut term: Termios = unsafe { std::mem::zeroed() };
    if unsafe { tcgetattr(STDIN_FILENO, &mut term) } != 0 {
        return read_line_plain();
    }
    let original = term;
    term.c_lflag &= !ECHO;
    unsafe {
        tcsetattr(STDIN_FILENO, TCSANOW, &term);
    }
    let _guard = TermiosGuard {
        fd: STDIN_FILENO,
        original,
    };
    read_line_plain()
}

fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        eprint!("{}", render_usage(style::stderr_tty()));
        return Ok(());
    }

    match args[0].as_str() {
        "--help" | "-h" => {
            print!("{}", render_usage(style::stdout_tty()));
            Ok(())
        }
        "--version" | "-V" => {
            println!("rzp {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        "c" => cmd_compress(&args[1..]),
        "d" => cmd_decompress(&args[1..]),
        "i" => cmd_info(&args[1..]),
        "l" => cmd_list(&args[1..]),
        "t" => cmd_test(&args[1..]),
        "x" => cmd_extract(&args[1..]),
        "bench" => cmd_bench(&args[1..]),
        "completion" | "completions" => cmd_completion(&args[1..]),
        other => Err(rzp::Error::Io(format!(
            "{}: {}\n\n{}",
            msgs().unknown_command,
            other,
            msgs().usage
        ))),
    }
}

/// 解析后的命令选项。
struct Opts {
    level: Level,
    block_size: usize,
    threads: usize,
    force: bool,
    keep: bool,
    dict: Option<PathBuf>,
    output: Option<PathBuf>,
    progress: bool,
    password: Option<String>,
    password_file: Option<PathBuf>,
    ask_pass: bool,
    include: Vec<String>,
    exclude: Vec<String>,
    argon2_memory_kib: u32,
    argon2_iterations: u32,
    argon2_lanes: u32,
    strong_checksum: bool,
}

impl Opts {
    /// 构造密码加密参数（盐始终由系统随机源生成）。
    fn crypto_options(&self) -> rzp::CryptoOptions {
        rzp::CryptoOptions {
            memory_kib: self.argon2_memory_kib,
            iterations: self.argon2_iterations,
            lanes: self.argon2_lanes,
            salt: None,
        }
    }
}

/// 解析选项与位置参数。位置参数（可多个）作为输入路径列表返回。
fn parse_opts(args: &[String]) -> Result<(Opts, Vec<String>)> {
    let mut level = Level::DEFAULT;
    let mut block_size = rzp::BLOCK_SIZE;
    let mut threads = rzp::default_threads();
    let mut force = false;
    let mut keep = false;
    let mut dict: Option<PathBuf> = None;
    let mut output: Option<PathBuf> = None;
    let mut progress = false;
    let mut password: Option<String> = None;
    let mut password_file: Option<PathBuf> = None;
    let mut ask_pass = false;
    let mut include: Vec<String> = Vec::new();
    let mut exclude: Vec<String> = Vec::new();
    let mut argon2_memory_kib = rzp::ARGON2_DEFAULT_MEMORY_KIB;
    let mut argon2_iterations = rzp::ARGON2_DEFAULT_ITERATIONS;
    let mut argon2_lanes = rzp::ARGON2_DEFAULT_LANES;
    let mut strong_checksum = false;
    let mut positional: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-o" => {
                i += 1;
                if i >= args.len() {
                    return Err(rzp::Error::Io(msgs().opt_o_requires_path.into()));
                }
                output = Some(PathBuf::from(&args[i]));
            }
            "-l" => {
                i += 1;
                if i >= args.len() {
                    return Err(rzp::Error::Io(msgs().opt_l_requires_level.into()));
                }
                let lvl: u8 = args[i]
                    .parse()
                    .map_err(|_| rzp::Error::Io(tr!(msgs().invalid_level, args[i])))?;
                level = Level::from_u8(lvl);
            }
            "-b" | "--block-size" => {
                i += 1;
                if i >= args.len() {
                    return Err(rzp::Error::Io(msgs().opt_b_requires_size.into()));
                }
                let n: usize = args[i]
                    .parse()
                    .map_err(|_| rzp::Error::Io(tr!(msgs().invalid_block_size, args[i])))?;
                if n == 0 || n > rzp::MAX_BLOCK_SIZE {
                    return Err(rzp::Error::Io(tr!(
                        msgs().block_size_range,
                        rzp::MAX_BLOCK_SIZE
                    )));
                }
                block_size = n;
            }
            "-j" | "--threads" => {
                i += 1;
                if i >= args.len() {
                    return Err(rzp::Error::Io(msgs().opt_j_requires_threads.into()));
                }
                let n: usize = args[i]
                    .parse()
                    .map_err(|_| rzp::Error::Io(tr!(msgs().invalid_threads, args[i])))?;
                if n == 0 {
                    return Err(rzp::Error::Io(msgs().threads_at_least_one.into()));
                }
                threads = n;
            }
            "-D" => {
                i += 1;
                if i >= args.len() {
                    return Err(rzp::Error::Io(msgs().opt_d_requires_dict.into()));
                }
                dict = Some(PathBuf::from(&args[i]));
            }
            "-p" | "--password" => {
                i += 1;
                if i >= args.len() {
                    return Err(rzp::Error::Io(msgs().opt_p_requires_password.into()));
                }
                password = Some(args[i].clone());
            }
            "--password-file" => {
                i += 1;
                if i >= args.len() {
                    return Err(rzp::Error::Io(
                        msgs().opt_password_file_requires_path.into(),
                    ));
                }
                password_file = Some(PathBuf::from(&args[i]));
            }
            "--ask-pass" => ask_pass = true,
            "--include" => {
                i += 1;
                if i >= args.len() {
                    return Err(rzp::Error::Io(msgs().opt_include_requires_pattern.into()));
                }
                include.push(args[i].clone());
            }
            "--exclude" => {
                i += 1;
                if i >= args.len() {
                    return Err(rzp::Error::Io(msgs().opt_exclude_requires_pattern.into()));
                }
                exclude.push(args[i].clone());
            }
            "--argon2-memory" => {
                i += 1;
                if i >= args.len() {
                    return Err(rzp::Error::Io(msgs().opt_argon2_memory_requires_kib.into()));
                }
                let n: u32 = args[i]
                    .parse()
                    .map_err(|_| rzp::Error::Io(tr!(msgs().invalid_argon2_memory, args[i])))?;
                if n == 0 || n > rzp::ARGON2_MAX_MEMORY_KIB {
                    return Err(rzp::Error::Io(tr!(
                        msgs().argon2_memory_range,
                        rzp::ARGON2_MAX_MEMORY_KIB
                    )));
                }
                argon2_memory_kib = n;
            }
            "--argon2-iters" => {
                i += 1;
                if i >= args.len() {
                    return Err(rzp::Error::Io(msgs().opt_argon2_iters_requires_n.into()));
                }
                let n: u32 = args[i]
                    .parse()
                    .map_err(|_| rzp::Error::Io(tr!(msgs().invalid_argon2_iters, args[i])))?;
                if n == 0 || n > rzp::ARGON2_MAX_ITERATIONS {
                    return Err(rzp::Error::Io(tr!(
                        msgs().argon2_iters_range,
                        rzp::ARGON2_MAX_ITERATIONS
                    )));
                }
                argon2_iterations = n;
            }
            "--argon2-lanes" => {
                i += 1;
                if i >= args.len() {
                    return Err(rzp::Error::Io(msgs().opt_argon2_lanes_requires_n.into()));
                }
                let n: u32 = args[i]
                    .parse()
                    .map_err(|_| rzp::Error::Io(tr!(msgs().invalid_argon2_lanes, args[i])))?;
                if n == 0 || n > rzp::ARGON2_MAX_LANES {
                    return Err(rzp::Error::Io(tr!(
                        msgs().argon2_lanes_range,
                        rzp::ARGON2_MAX_LANES
                    )));
                }
                argon2_lanes = n;
            }
            "-f" | "--force" => force = true,
            "-k" | "--keep" => keep = true,
            "-c" | "--progress" => progress = true,
            "--strong-checksum" => strong_checksum = true,
            "-" => positional.push("-".to_string()),
            s if s.starts_with('-') => {
                return Err(rzp::Error::Io(tr!(msgs().unknown_option, s)));
            }
            s => positional.push(s.to_string()),
        }
        i += 1;
    }

    Ok((
        Opts {
            level,
            block_size,
            threads,
            force,
            keep,
            dict,
            output,
            progress,
            password,
            password_file,
            ask_pass,
            include,
            exclude,
            argon2_memory_kib,
            argon2_iterations,
            argon2_lanes,
            strong_checksum,
        },
        positional,
    ))
}

/// 校验位置参数：必须有输入，且 stdin（`-`）不能与多个输入混用。
fn validate_inputs(positional: &[String]) -> Result<Vec<PathBuf>> {
    if positional.is_empty() {
        return Err(rzp::Error::Io(msgs().missing_input.into()));
    }
    if positional.len() > 1 && positional.iter().any(|s| s == "-") {
        return Err(rzp::Error::Io(msgs().stdin_multi_input.into()));
    }
    Ok(positional.iter().map(PathBuf::from).collect())
}

/// `-o` 只能用于单个输入。
fn ensure_single_output(opts: &Opts, inputs: &[PathBuf]) -> Result<()> {
    if opts.output.is_some() && inputs.len() > 1 {
        return Err(rzp::Error::Io(msgs().output_single_input.into()));
    }
    Ok(())
}

/// 去掉路径末尾的 `/`，使 `dir/` 与 `dir` 生成相同的输出名 `dir.rzp`。
fn trim_trailing_slash(path: &Path) -> PathBuf {
    let s = path.to_string_lossy();
    PathBuf::from(s.trim_end_matches('/'))
}

/// 是否以 `.rzp` 结尾。
fn is_rzp(path: &Path) -> bool {
    path.to_string_lossy().ends_with(".rzp")
}

/// 探测文件是否为加密信封：读取前 6 字节，检查魔数与 `FLAG_ENCRYPTED`。
/// stdin（`-`）或读取失败返回 `false`（无法预读）。
fn is_encrypted_file(path: &Path) -> bool {
    if path == Path::new("-") {
        return false;
    }
    let mut f = match File::open(path) {
        Ok(f) => f,
        Err(_) => return false,
    };
    let mut hdr = [0u8; 6];
    if f.read_exact(&mut hdr).is_err() {
        return false;
    }
    hdr[0..3] == *b"RZP" && hdr[5] & 0x04 != 0
}

/// 给路径追加后缀。
fn add_suffix(input: &Path, suffix: &str) -> PathBuf {
    let mut o = input.as_os_str().to_os_string();
    o.push(suffix);
    PathBuf::from(o)
}

/// 递归收集目录下的所有文件（不跟随符号链接，结果按路径排序）。
fn collect_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    let entries = std::fs::read_dir(dir)
        .map_err(|e| rzp::Error::Io(tr!(msgs().cannot_read_dir, dir.display(), e)))?;
    let mut paths: Vec<PathBuf> = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| rzp::Error::Io(tr!(msgs().read_dir_entry_failed, e)))?;
        paths.push(entry.path());
    }
    paths.sort();
    for path in paths {
        let meta = std::fs::symlink_metadata(&path)
            .map_err(|e| rzp::Error::Io(tr!(msgs().cannot_read_metadata, path.display(), e)))?;
        if meta.is_dir() {
            collect_files(&path, out)?;
        } else if meta.is_file() {
            out.push(path);
        }
    }
    Ok(())
}

/// 把输入路径展开为文件列表：目录递归展开（按 `filter` 过滤），其余原样保留。
fn expand_inputs(paths: &[PathBuf], filter: &dyn Fn(&Path) -> bool) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for p in paths {
        if p.as_path() == Path::new("-") {
            out.push(p.clone());
            continue;
        }
        match std::fs::symlink_metadata(p) {
            Ok(m) if m.is_dir() => {
                let mut files = Vec::new();
                collect_files(p, &mut files)?;
                out.extend(files.into_iter().filter(|p| filter(p.as_path())));
            }
            _ => out.push(p.clone()),
        }
    }
    Ok(out)
}

/// 读取预设字典文件（空字典用 `&[]` 表示）。
fn load_dict(path: &Option<PathBuf>) -> Result<Vec<u8>> {
    match path {
        Some(p) => read_dict(p),
        None => Ok(Vec::new()),
    }
}

/// 输入文件字节数；`-`（stdin）返回 0，表示无法显示总量。
fn file_len(path: &Path) -> u64 {
    if path == Path::new("-") {
        0
    } else {
        std::fs::metadata(path).map(|m| m.len()).unwrap_or(0)
    }
}

/// 终端进度条：在 stderr 上用 `\r` 覆盖重绘，仅在整数百分比变化时更新。
struct Progress {
    enabled: bool,
    total: u64,
    last_pct: u8,
    width: usize,
}

impl Progress {
    fn new(enabled: bool, total: u64) -> Self {
        Progress {
            enabled,
            total,
            last_pct: u8::MAX,
            width: 30,
        }
    }

    fn update(&mut self, done: u64) {
        if !self.enabled || self.total == 0 {
            return;
        }
        let ratio = (done as f64 / self.total as f64).min(1.0);
        let pct = (ratio * 100.0) as u8;
        if pct != self.last_pct {
            self.last_pct = pct;
            eprint!("\r{}", render_bar(ratio, self.width));
            let _ = std::io::stderr().flush();
        }
    }

    fn finish(&mut self) {
        if self.enabled && self.last_pct != u8::MAX {
            eprintln!();
        }
    }
}

/// 渲染 `[===>      ]  42.0%` 样式的进度条。
fn render_bar(ratio: f64, width: usize) -> String {
    let filled = (ratio * width as f64) as usize;
    let mut bar = String::with_capacity(width + 8);
    bar.push('[');
    for i in 0..width {
        if i < filled {
            bar.push(if i + 1 == filled && filled < width {
                '>'
            } else {
                '='
            });
        } else {
            bar.push(' ');
        }
    }
    bar.push(']');
    format!("{bar} {:5.1}%", ratio * 100.0)
}

/// 简单通配符：`*` 匹配任意字符序列，`?` 匹配单个字符。
struct Pattern {
    raw: String,
}

impl Pattern {
    fn new(raw: String) -> Self {
        Pattern { raw }
    }

    fn matches(&self, s: &str) -> bool {
        glob_match(self.raw.as_bytes(), s.as_bytes())
    }
}

/// 迭代式通配符匹配（无递归，避免深层模式栈溢出）。
fn glob_match(pat: &[u8], text: &[u8]) -> bool {
    let (mut p, mut t) = (0usize, 0usize);
    let mut star: Option<usize> = None;
    let mut star_t = 0usize;
    while t < text.len() {
        if p < pat.len() && (pat[p] == b'?' || pat[p] == text[t]) {
            p += 1;
            t += 1;
        } else if p < pat.len() && pat[p] == b'*' {
            star = Some(p);
            star_t = t;
            p += 1;
        } else if let Some(sp) = star {
            p = sp + 1;
            star_t += 1;
            t = star_t;
        } else {
            return false;
        }
    }
    while p < pat.len() && pat[p] == b'*' {
        p += 1;
    }
    p == pat.len()
}

/// 由 `--include` / `--exclude` 得到的路径过滤器。
struct PathFilter {
    includes: Vec<Pattern>,
    excludes: Vec<Pattern>,
}

impl PathFilter {
    fn new(includes: &[String], excludes: &[String]) -> Self {
        PathFilter {
            includes: includes.iter().map(|s| Pattern::new(s.clone())).collect(),
            excludes: excludes.iter().map(|s| Pattern::new(s.clone())).collect(),
        }
    }

    /// 是否收录该路径：命中任一 `--exclude` 直接跳过；有 `--include` 时文件须命中其一。
    /// 目录不因 `--include` 被剪枝（仅由 `--exclude` 剪枝），以遍历可能匹配的后代。
    fn keep(&self, path: &Path, is_dir: bool) -> bool {
        let s = path.to_string_lossy();
        if self.excludes.iter().any(|p| p.matches(&s)) {
            return false;
        }
        if self.includes.is_empty() {
            return true;
        }
        if is_dir {
            return true;
        }
        self.includes.iter().any(|p| p.matches(&s))
    }
}

/// 待压缩/解压的单个任务。
enum Job {
    File { input: PathBuf, output: PathBuf },
    Dir { input: PathBuf, output: PathBuf },
}

/// 用固定数量的工作线程并行执行 `jobs`（每个任务调用一次 `f`），返回首个错误。
fn run_parallel<T, F>(jobs: Vec<T>, workers: usize, f: F) -> Result<()>
where
    T: Send,
    F: Fn(T) -> Result<()> + Sync,
{
    use std::collections::VecDeque;
    use std::sync::Mutex;

    if jobs.is_empty() {
        return Ok(());
    }
    let queue = Mutex::new(VecDeque::from(jobs));
    let first_error = Mutex::new(None::<rzp::Error>);

    std::thread::scope(|s| {
        for _ in 0..workers.max(1) {
            s.spawn(|| loop {
                let job = { queue.lock().unwrap().pop_front() };
                match job {
                    Some(j) => {
                        if let Err(e) = f(j) {
                            let mut err = first_error.lock().unwrap();
                            if err.is_none() {
                                *err = Some(e);
                            }
                        }
                    }
                    None => break,
                }
            });
        }
    });

    if let Some(e) = first_error.into_inner().unwrap() {
        return Err(e);
    }
    Ok(())
}

/// 由条目类型 + 权限位生成 `drwxr-xr-x` 样式的字符串。
fn mode_string(ty: u8, mode: u32) -> String {
    let mut s = String::with_capacity(10);
    s.push(match ty {
        1 => 'd',
        2 => 'l',
        _ => '-',
    });
    let bits = [
        (0o400, 'r'),
        (0o200, 'w'),
        (0o100, 'x'),
        (0o040, 'r'),
        (0o020, 'w'),
        (0o010, 'x'),
        (0o004, 'r'),
        (0o002, 'w'),
        (0o001, 'x'),
    ];
    for (mask, ch) in bits {
        s.push(if mode & mask != 0 { ch } else { '-' });
    }
    s
}

#[allow(clippy::too_many_arguments)]
fn compress_one(
    input: &Path,
    output: &Path,
    dict: &[u8],
    level: Level,
    block_size: usize,
    threads: usize,
    password: Option<&str>,
    crypto: &rzp::CryptoOptions,
    force: bool,
    keep: bool,
    progress: bool,
    strong_checksum: bool,
) -> Result<()> {
    // 密码模式：两趟流式（先压缩到临时内层文件，再流式加密写出），内存有界，
    // 可处理 GB 级文件。
    if let Some(pw) = password {
        let tmp = TempFile::create()?;
        let input_len = {
            let tmp_out = BufWriter::with_capacity(64 * 1024, File::create(tmp.path())?);
            let mut encoder = Encoder::with_dictionary(tmp_out, level, dict)
                .with_threads(threads)
                .with_block_size(block_size)?;
            if strong_checksum {
                encoder = encoder.with_strong_checksum();
            }
            let mut reader = open_input(input)?;
            let mut prog = Progress::new(progress, file_len(input));
            let mut buf = [0u8; 64 * 1024];
            let mut len = 0u64;
            loop {
                let n = reader.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                len += n as u64;
                encoder.write_all(&buf[..n])?;
                prog.update(len);
            }
            prog.finish();
            encoder.finish()?.flush()?;
            len
        };

        let out_len =
            encrypt_inner_to_output(tmp.path(), output, level.as_u8(), pw, crypto, force)?;

        maybe_remove_input(input, output, keep);

        let ratio = if input_len == 0 {
            0.0
        } else {
            100.0 * out_len as f64 / input_len as f64
        };
        eprintln!(
            "{}: {} -> {} ({input_len} -> {out_len} {}, {ratio:.1}%)",
            style::paint(
                msgs().status_compressed,
                style::Color::Green,
                style::stderr_tty()
            ),
            label(input, true),
            label(output, false),
            msgs().bytes
        );
        return Ok(());
    }

    let mut reader = open_input(input)?;
    let out_writer = create_output_writer(output, force)?;
    let mut encoder = Encoder::with_dictionary(CountingWriter::new(out_writer), level, dict)
        .with_threads(threads)
        .with_block_size(block_size)?;
    if strong_checksum {
        encoder = encoder.with_strong_checksum();
    }

    let mut prog = Progress::new(progress, file_len(input));

    let mut buf = [0u8; 64 * 1024];
    let mut input_len = 0u64;
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        input_len += n as u64;
        encoder.write_all(&buf[..n])?;
        prog.update(input_len);
    }
    prog.finish();

    let mut writer = encoder.finish()?;
    writer.flush()?;
    let out_len = writer.count();

    maybe_remove_input(input, output, keep);

    let ratio = if input_len == 0 {
        0.0
    } else {
        100.0 * out_len as f64 / input_len as f64
    };
    eprintln!(
        "{}: {} -> {} ({input_len} -> {out_len} {}, {ratio:.1}%)",
        style::paint(
            msgs().status_compressed,
            style::Color::Green,
            style::stderr_tty()
        ),
        label(input, true),
        label(output, false),
        msgs().bytes
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn decompress_one(
    input: &Path,
    output: &Path,
    dict: &[u8],
    threads: usize,
    password: Option<&str>,
    force: bool,
    keep: bool,
    progress: bool,
) -> Result<()> {
    let (reader, kind) = open_payload(input, password)?;

    if kind == Kind::IndexedDir {
        ensure_dir_output(output, force)?;
        let mut r = reader;
        rzp::archive::extract_indexed(&mut r, output, dict, threads)?;
        maybe_remove_input(input, output, keep);
        eprintln!(
            "{}: {} -> {} {}",
            style::paint(
                msgs().status_decompressed,
                style::Color::Green,
                style::stderr_tty()
            ),
            label(input, true),
            label(output, false),
            msgs().dir_archive
        );
        return Ok(());
    }

    // 单文件流与旧式 solid 目录归档共用流式路径。
    let mut decoder = Decoder::with_dictionary(reader, dict).with_threads(threads);

    // 读取流头，判定是目录归档还是普通文件。
    if decoder.is_directory_archive()? {
        ensure_dir_output(output, force)?;
        rzp::archive::extract(&mut decoder, output)?;
        maybe_remove_input(input, output, keep);
        eprintln!(
            "{}: {} -> {} {}",
            style::paint(
                msgs().status_decompressed,
                style::Color::Green,
                style::stderr_tty()
            ),
            label(input, true),
            label(output, false),
            msgs().dir_archive
        );
        return Ok(());
    }

    let out_writer = create_output_writer(output, force)?;
    let mut writer = BufWriter::with_capacity(64 * 1024, out_writer);

    let mut prog = Progress::new(progress, file_len(input));
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = decoder.read_into(&mut buf)?;
        if n == 0 {
            break;
        }
        writer.write_all(&buf[..n])?;
        prog.update(decoder.total_in());
    }
    prog.finish();
    writer.flush()?;

    maybe_remove_input(input, output, keep);

    eprintln!(
        "{}: {} -> {} ({} {})",
        style::paint(
            msgs().status_decompressed,
            style::Color::Green,
            style::stderr_tty()
        ),
        label(input, true),
        label(output, false),
        decoder.total_out(),
        msgs().bytes
    );
    Ok(())
}

/// 打印 `Info` 的通用信息（级别、大小、压缩率、字典、块数）。
fn print_info(input: &Path, info: &rzp::Info) {
    let ratio = if info.raw_size == 0 {
        0.0
    } else {
        100.0 * info.compressed_size as f64 / info.raw_size as f64
    };
    eprintln!(
        "{}: {}",
        style::paint(msgs().file, style::Color::Cyan, style::stderr_tty()),
        label(input, true)
    );
    eprintln!(
        "{}: {}",
        style::paint(msgs().level, style::Color::Cyan, style::stderr_tty()),
        info.level.as_u8()
    );
    eprintln!(
        "{}: {} {}",
        style::paint(msgs().raw_size, style::Color::Cyan, style::stderr_tty()),
        info.raw_size,
        msgs().bytes
    );
    eprintln!(
        "{}: {} {}",
        style::paint(
            msgs().compressed_size,
            style::Color::Cyan,
            style::stderr_tty()
        ),
        info.compressed_size,
        msgs().bytes
    );
    eprintln!(
        "{}: {ratio:.1}%",
        style::paint(msgs().ratio, style::Color::Cyan, style::stderr_tty())
    );
    eprintln!(
        "{}: {}",
        style::paint(msgs().dictionary, style::Color::Cyan, style::stderr_tty()),
        if info.has_dictionary {
            msgs().yes
        } else {
            msgs().no
        }
    );
    eprintln!(
        "{}: {} ({} {}, {} {})",
        style::paint(msgs().blocks, style::Color::Cyan, style::stderr_tty()),
        info.block_count,
        msgs().compressed_word,
        info.compressed_blocks,
        msgs().stored_word,
        info.stored_blocks
    );
}

fn info_one(input: &Path, password: Option<&str>) -> Result<()> {
    let (mut reader, kind) = open_payload(input, password)?;
    if kind == Kind::IndexedDir {
        let entries = rzp::archive::read_index(&mut reader)?;
        let total_raw: u64 = entries.iter().map(|e| e.size).sum();
        let total_comp: u64 = entries.iter().map(|e| e.comp_size).sum();
        let files = entries.iter().filter(|e| e.ty == 0).count();
        let dirs = entries.iter().filter(|e| e.ty == 1).count();
        let links = entries.iter().filter(|e| e.ty == 2).count();
        let out_len = file_len(input);
        let ratio = if total_raw == 0 {
            0.0
        } else {
            100.0 * out_len as f64 / total_raw as f64
        };
        eprintln!(
            "{}: {}",
            style::paint(msgs().file, style::Color::Cyan, style::stderr_tty()),
            label(input, true)
        );
        eprintln!(
            "{}: {}",
            style::paint(msgs().type_label, style::Color::Cyan, style::stderr_tty()),
            msgs().indexed_dir_archive
        );
        eprintln!(
            "{}: {}",
            style::paint(msgs().entry_count, style::Color::Cyan, style::stderr_tty()),
            entries.len()
        );
        eprintln!(
            "{}: {}",
            style::paint(msgs().composition, style::Color::Cyan, style::stderr_tty()),
            tr!(msgs().composition_files, files, dirs, links)
        );
        eprintln!(
            "{}: {} {}",
            style::paint(msgs().raw_size, style::Color::Cyan, style::stderr_tty()),
            total_raw,
            msgs().bytes
        );
        eprintln!(
            "{}: {} {}",
            style::paint(
                msgs().entry_data_size,
                style::Color::Cyan,
                style::stderr_tty()
            ),
            total_comp,
            msgs().bytes
        );
        eprintln!(
            "{}: {} {} ({ratio:.1}%)",
            style::paint(msgs().archive_size, style::Color::Cyan, style::stderr_tty()),
            out_len,
            msgs().bytes
        );
        eprintln!(
            "{}: {}",
            style::paint(msgs().encrypted, style::Color::Cyan, style::stderr_tty()),
            if password.is_some() {
                msgs().yes
            } else {
                msgs().no
            }
        );
        return Ok(());
    }

    let info = rzp::inspect(&mut reader)?;
    print_info(input, &info);
    let encrypted = password.is_some();
    eprintln!(
        "{}: {}",
        style::paint(msgs().encrypted, style::Color::Cyan, style::stderr_tty()),
        if encrypted { msgs().yes } else { msgs().no }
    );
    if encrypted {
        eprintln!(
            "{}: {} {}",
            style::paint(
                msgs().outer_archive_size,
                style::Color::Cyan,
                style::stderr_tty()
            ),
            file_len(input),
            msgs().bytes
        );
    }
    Ok(())
}

fn test_one(input: &Path, dict: &[u8], threads: usize, password: Option<&str>) -> Result<()> {
    let (mut reader, kind) = open_payload(input, password)?;
    if kind == Kind::IndexedDir {
        rzp::archive::verify_indexed(&mut reader, dict, threads)?;
        eprintln!(
            "{}: {} {}",
            style::paint(msgs().verified, style::Color::Green, style::stderr_tty()),
            label(input, true),
            msgs().indexed_dir_archive_short
        );
        return Ok(());
    }

    let mut decoder = Decoder::with_dictionary(reader, dict).with_threads(threads);
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = decoder.read_into(&mut buf)?;
        if n == 0 {
            break;
        }
    }
    eprintln!(
        "{}: {} {}",
        style::paint(msgs().verified, style::Color::Green, style::stderr_tty()),
        label(input, true),
        tr!(
            msgs().verified_detail,
            decoder.level().as_u8(),
            decoder.total_out()
        )
    );
    Ok(())
}

fn list_one(input: &Path, dict: &[u8], threads: usize, password: Option<&str>) -> Result<()> {
    let (mut reader, kind) = open_payload(input, password)?;
    eprintln!(
        "{}: {}",
        style::paint(msgs().archive, style::Color::Cyan, style::stderr_tty()),
        label(input, true)
    );

    if kind == Kind::IndexedDir {
        rzp::archive::list_indexed(&mut reader, |e| {
            eprintln!(
                "{} {:>9} {}",
                mode_string(e.ty, e.mode),
                e.size,
                e.path().display()
            );
            Ok(())
        })?;
        return Ok(());
    }

    let mut decoder = Decoder::with_dictionary(reader, dict).with_threads(threads);
    if !decoder.is_directory_archive()? {
        return Err(rzp::Error::Io(tr!(
            msgs().not_dir_archive,
            label(input, true)
        )));
    }
    rzp::archive::list(&mut decoder, |e| {
        eprintln!(
            "{} {:>9} {}",
            mode_string(e.ty, e.mode),
            e.size,
            e.path().display()
        );
        Ok(())
    })?;
    Ok(())
}

fn cmd_compress(args: &[String]) -> Result<()> {
    let (opts, positional) = parse_opts(args)?;
    let inputs = validate_inputs(&positional)?;
    ensure_single_output(&opts, &inputs)?;
    let dict = load_dict(&opts.dict)?;
    let password = resolve_password(&opts, opts.ask_pass)?;
    let password = password.as_deref();
    let crypto = opts.crypto_options();
    let filter = PathFilter::new(&opts.include, &opts.exclude);

    // 构造待处理任务：目录打包为一个归档，文件/单流各自压缩。
    let mut jobs: Vec<Job> = Vec::new();
    for input in &inputs {
        let output = opts.output.clone().unwrap_or_else(|| {
            if input.as_path() == Path::new("-") {
                PathBuf::from("-")
            } else {
                add_suffix(&trim_trailing_slash(input), ".rzp")
            }
        });
        if input.as_path() == Path::new("-") {
            jobs.push(Job::File {
                input: input.clone(),
                output,
            });
            continue;
        }
        match std::fs::symlink_metadata(input) {
            Ok(m) if m.is_dir() => jobs.push(Job::Dir {
                input: input.clone(),
                output,
            }),
            _ => {
                // 跳过已有的 .rzp 文件与未命中过滤器的文件。
                if is_rzp(input) || !filter.keep(input, false) {
                    continue;
                }
                jobs.push(Job::File {
                    input: input.clone(),
                    output,
                });
            }
        }
    }

    // 多文件并行压缩（每个任务内部仍可用 `-j` 并行单文件内的块）。
    run_parallel(jobs, rzp::default_threads(), |job| match job {
        Job::File { input, output } => compress_one(
            &input,
            &output,
            &dict,
            opts.level,
            opts.block_size,
            opts.threads,
            password,
            &crypto,
            opts.force,
            opts.keep,
            opts.progress,
            opts.strong_checksum,
        ),
        Job::Dir { input, output } => compress_dir(
            &input,
            &output,
            &dict,
            opts.level,
            opts.block_size,
            opts.threads,
            password,
            &crypto,
            opts.force,
            opts.keep,
            opts.progress,
            opts.strong_checksum,
            &filter,
        ),
    })
}

/// 把整个目录打包为单个归档并压缩（索引式，尾部带中央目录）。
#[allow(clippy::too_many_arguments)]
fn compress_dir(
    dir: &Path,
    output: &Path,
    dict: &[u8],
    level: Level,
    block_size: usize,
    threads: usize,
    password: Option<&str>,
    crypto: &rzp::CryptoOptions,
    force: bool,
    keep: bool,
    progress: bool,
    strong_checksum: bool,
    filter: &PathFilter,
) -> Result<()> {
    // 目录归档暂不显示进度条（总量需二次遍历），且条目各自独立压缩、块大小固定，
    // 故忽略这两个标志。
    let _ = progress;
    let _ = block_size;
    let include = |rel: &Path, is_dir: bool| filter.keep(rel, is_dir);

    if let Some(pw) = password {
        // 密码模式：两趟流式（先打包到临时内层文件，再流式加密写出），内存有界。
        let tmp = TempFile::create()?;
        {
            let mut tmp_out = BufWriter::with_capacity(64 * 1024, File::create(tmp.path())?);
            if strong_checksum {
                rzp::archive::write_indexed_dir_with_strong_checksum(
                    dir,
                    &mut tmp_out,
                    &include,
                    level,
                    dict,
                    threads,
                )?;
            } else {
                rzp::archive::write_indexed_dir(dir, &mut tmp_out, &include, level, dict, threads)?;
            }
            tmp_out.flush()?;
        }

        let out_len =
            encrypt_inner_to_output(tmp.path(), output, level.as_u8(), pw, crypto, force)?;

        maybe_remove_input_dir(dir, output, keep);
        eprintln!(
            "{}: {} -> {} {}",
            style::paint(
                msgs().status_compressed,
                style::Color::Green,
                style::stderr_tty()
            ),
            label(dir, true),
            label(output, false),
            tr!(msgs().dir_archive_bytes, out_len)
        );
        return Ok(());
    }

    let out_writer = create_output_writer(output, force)?;
    let mut writer = CountingWriter::new(out_writer);
    if strong_checksum {
        rzp::archive::write_indexed_dir_with_strong_checksum(
            dir,
            &mut writer,
            &include,
            level,
            dict,
            threads,
        )?;
    } else {
        rzp::archive::write_indexed_dir(dir, &mut writer, &include, level, dict, threads)?;
    }
    writer.flush()?;
    let out_len = writer.count();

    maybe_remove_input_dir(dir, output, keep);

    eprintln!(
        "{}: {} -> {} {}",
        style::paint(
            msgs().status_compressed,
            style::Color::Green,
            style::stderr_tty()
        ),
        label(dir, true),
        label(output, false),
        tr!(msgs().dir_archive_bytes, out_len)
    );
    Ok(())
}

fn cmd_decompress(args: &[String]) -> Result<()> {
    let (opts, positional) = parse_opts(args)?;
    let inputs = validate_inputs(&positional)?;
    // 解压时只处理 .rzp 文件。
    let files = expand_inputs(&inputs, &is_rzp)?;
    let filter = PathFilter::new(&opts.include, &opts.exclude);
    let files: Vec<PathBuf> = files
        .into_iter()
        .filter(|p| filter.keep(p, false))
        .collect();
    ensure_single_output(&opts, &inputs)?;
    let dict = load_dict(&opts.dict)?;
    let prompt = opts.ask_pass || files.iter().any(|p| is_encrypted_file(p));
    let password = resolve_password(&opts, prompt)?;
    let password = password.as_deref();

    for input in &files {
        let output = match &opts.output {
            Some(o) => o.clone(),
            None if input.as_path() == Path::new("-") => PathBuf::from("-"),
            None => {
                let s = input.to_string_lossy();
                if let Some(stripped) = s.strip_suffix(".rzp") {
                    PathBuf::from(stripped)
                } else {
                    add_suffix(input, ".out")
                }
            }
        };
        decompress_one(
            input,
            &output,
            &dict,
            opts.threads,
            password,
            opts.force,
            opts.keep,
            opts.progress,
        )?;
    }
    Ok(())
}

fn cmd_info(args: &[String]) -> Result<()> {
    let (opts, positional) = parse_opts(args)?;
    let inputs = validate_inputs(&positional)?;
    let files = expand_inputs(&inputs, &is_rzp)?;
    let filter = PathFilter::new(&opts.include, &opts.exclude);
    let files: Vec<PathBuf> = files
        .into_iter()
        .filter(|p| filter.keep(p, false))
        .collect();
    let prompt = opts.ask_pass || files.iter().any(|p| is_encrypted_file(p));
    let password = resolve_password(&opts, prompt)?;
    let password = password.as_deref();
    for input in &files {
        info_one(input, password)?;
    }
    Ok(())
}

fn cmd_list(args: &[String]) -> Result<()> {
    let (opts, positional) = parse_opts(args)?;
    let inputs = validate_inputs(&positional)?;
    let files = expand_inputs(&inputs, &is_rzp)?;
    let filter = PathFilter::new(&opts.include, &opts.exclude);
    let files: Vec<PathBuf> = files
        .into_iter()
        .filter(|p| filter.keep(p, false))
        .collect();
    let dict = load_dict(&opts.dict)?;
    let prompt = opts.ask_pass || files.iter().any(|p| is_encrypted_file(p));
    let password = resolve_password(&opts, prompt)?;
    let password = password.as_deref();
    for input in &files {
        list_one(input, &dict, opts.threads, password)?;
    }
    Ok(())
}

fn cmd_test(args: &[String]) -> Result<()> {
    let (opts, positional) = parse_opts(args)?;
    let inputs = validate_inputs(&positional)?;
    let files = expand_inputs(&inputs, &is_rzp)?;
    let filter = PathFilter::new(&opts.include, &opts.exclude);
    let files: Vec<PathBuf> = files
        .into_iter()
        .filter(|p| filter.keep(p, false))
        .collect();
    let dict = load_dict(&opts.dict)?;
    let prompt = opts.ask_pass || files.iter().any(|p| is_encrypted_file(p));
    let password = resolve_password(&opts, prompt)?;
    let password = password.as_deref();
    for input in &files {
        test_one(input, &dict, opts.threads, password)?;
    }
    Ok(())
}

/// `rzp x <归档> <条目路径>`：从索引归档随机抽取单个条目。
fn cmd_extract(args: &[String]) -> Result<()> {
    let (opts, positional) = parse_opts(args)?;
    if positional.len() != 2 {
        return Err(rzp::Error::Io(msgs().extract_usage.into()));
    }
    let archive = PathBuf::from(&positional[0]);
    let entry = PathBuf::from(&positional[1]);
    let dict = load_dict(&opts.dict)?;
    let prompt = opts.ask_pass || is_encrypted_file(&archive);
    let password = resolve_password(&opts, prompt)?;
    let password = password.as_deref();
    let out_dir = opts.output.clone().unwrap_or_else(|| PathBuf::from("."));
    extract_one(&archive, &entry, &out_dir, &dict, opts.threads, password)
}

/// 从索引归档随机抽取单个条目到 `out_dir` 下（保留条目相对路径）。
fn extract_one(
    archive: &Path,
    entry: &Path,
    out_dir: &Path,
    dict: &[u8],
    threads: usize,
    password: Option<&str>,
) -> Result<()> {
    let (mut reader, kind) = open_payload(archive, password)?;
    if kind != Kind::IndexedDir {
        return Err(rzp::Error::Io(msgs().extract_requires_indexed.into()));
    }
    rzp::archive::extract_indexed_path(&mut reader, out_dir, entry, dict, threads)?;
    eprintln!(
        "{}: {} -> {}",
        style::paint(msgs().extracted, style::Color::Green, style::stderr_tty()),
        entry.display(),
        out_dir.join(entry).display()
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// `rzp completion`：输出 shell 补全脚本（bash/zsh/fish），零依赖静态生成。
// ---------------------------------------------------------------------------

fn cmd_completion(args: &[String]) -> Result<()> {
    let shells: [(&str, &str); 3] = [
        ("bash", msgs().bash_completion),
        ("zsh", msgs().zsh_completion),
        ("fish", msgs().fish_completion),
    ];
    if args.is_empty() {
        return Err(rzp::Error::Io(msgs().completion_usage.into()));
    }
    for (name, script) in shells {
        if args[0] == name {
            print!("{script}");
            return Ok(());
        }
    }
    Err(rzp::Error::Io(tr!(msgs().unknown_shell, args[0])))
}

// ---------------------------------------------------------------------------
// `rzp bench`：对比 rzp 与 gzip/zstd 的压缩率与速度（输入可为文件或目录）。
// ---------------------------------------------------------------------------

/// 单个工具在一份数据上的基准结果。
#[derive(Default, Clone)]
struct BenchTool {
    /// 工具是否可用（未安装则整行标记为 n/a）。
    available: bool,
    comp_size: u64,
    comp_time: f64,
    decomp_time: f64,
    /// 解压后内容是否与原文一致。
    decomp_ok: bool,
}

/// 一份输入在三种工具下的汇总。
struct BenchRow {
    name: String,
    orig: u64,
    rzp: BenchTool,
    gzip: BenchTool,
    zstd: BenchTool,
}

fn cmd_bench(args: &[String]) -> Result<()> {
    let (opts, positional) = parse_opts(args)?;
    if positional.is_empty() {
        return Err(rzp::Error::Io(msgs().bench_no_input.into()));
    }
    let files = collect_bench_inputs(&positional)?;
    if files.is_empty() {
        return Err(rzp::Error::Io(msgs().bench_no_files.into()));
    }

    let level = opts.level;
    let mut rows: Vec<BenchRow> = Vec::new();
    for file in &files {
        let data = std::fs::read(file)
            .map_err(|e| rzp::Error::Io(tr!(msgs().cannot_read_file, file.display(), e)))?;
        let orig = data.len() as u64;
        let rzp = bench_rzp(&data, level);
        let gzip = bench_external("gzip", &["-c", "-6"], &["-d", "-c"], &data);
        let zstd = bench_external("zstd", &["-q", "-c", "-3"], &["-d", "-q", "-c"], &data);
        rows.push(BenchRow {
            name: file.display().to_string(),
            orig,
            rzp,
            gzip,
            zstd,
        });
    }

    print_bench(&rows);
    Ok(())
}

/// 展开输入参数：文件直接收录，目录递归收录其中所有普通文件。
fn collect_bench_inputs(paths: &[String]) -> Result<Vec<PathBuf>> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
        let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)?
            .map(|e| e.map(|e| e.path()))
            .collect::<std::io::Result<_>>()?;
        entries.sort();
        for e in entries {
            let m = std::fs::metadata(&e)?;
            if m.is_file() {
                out.push(e);
            } else if m.is_dir() {
                walk(&e, out)?;
            }
        }
        Ok(())
    }

    let mut out = Vec::new();
    for s in paths {
        let p = Path::new(s);
        let meta = std::fs::metadata(p)
            .map_err(|e| rzp::Error::Io(tr!(msgs().cannot_access, p.display(), e)))?;
        if meta.is_file() {
            out.push(p.to_path_buf());
        } else if meta.is_dir() {
            walk(p, &mut out)?;
        } else {
            return Err(rzp::Error::Io(tr!(msgs().not_file_or_dir, p.display())));
        }
    }
    Ok(out)
}

/// 用库内单线程 `compress`/`decompress` 计时（与单线程 gzip/zstd 公平对比）。
fn bench_rzp(data: &[u8], level: Level) -> BenchTool {
    let t0 = Instant::now();
    let comp = rzp::compress(data, level);
    let comp_time = t0.elapsed().as_secs_f64();

    let t1 = Instant::now();
    let dec = rzp::decompress(&comp);
    let decomp_time = t1.elapsed().as_secs_f64();

    BenchTool {
        available: true,
        comp_size: comp.len() as u64,
        comp_time,
        decomp_time,
        decomp_ok: matches!(&dec, Ok(v) if v.as_slice() == data),
    }
}

/// 用外部工具（gzip/zstd）通过管道计时；工具未安装则整行标记为不可用。
fn bench_external(
    program: &str,
    comp_args: &[&str],
    decomp_args: &[&str],
    data: &[u8],
) -> BenchTool {
    let t0 = Instant::now();
    let comp = match run_pipe(program, comp_args, data) {
        Ok(v) => v,
        Err(_) => return BenchTool::default(),
    };
    let comp_time = t0.elapsed().as_secs_f64();

    let t1 = Instant::now();
    let dec = run_pipe(program, decomp_args, &comp);
    let decomp_time = t1.elapsed().as_secs_f64();

    BenchTool {
        available: true,
        comp_size: comp.len() as u64,
        comp_time,
        decomp_time,
        decomp_ok: matches!(&dec, Ok(v) if v.as_slice() == data),
    }
}

/// 通过 stdin/stdout 管道运行外部程序，返回其 stdout（写入输入在独立线程中
/// 进行，避免大输入下管道缓冲导致的死锁）。
fn run_pipe(program: &str, args: &[&str], input: &[u8]) -> Result<Vec<u8>> {
    use std::process::{Command, Stdio};

    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| rzp::Error::Io(tr!(msgs().cannot_start_program, program, e)))?;

    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| rzp::Error::Io(msgs().cannot_get_stdin.into()))?;
    let data = input.to_vec();
    let writer = std::thread::spawn(move || {
        let _ = stdin.write_all(&data);
    });

    let output = child.wait_with_output()?;
    writer.join().ok();
    if !output.status.success() {
        return Err(rzp::Error::Io(tr!(msgs().program_nonzero_exit, program)));
    }
    Ok(output.stdout)
}

/// 打印基准报告（逐文件明细 + 汇总）。
fn print_bench(rows: &[BenchRow]) {
    let tty = style::stdout_tty();
    println!(
        "{}",
        style::paint(msgs().bench_title, style::Color::Bold, tty)
    );
    println!();

    let header = format!(
        "{:<32} {:>12} {:>12} {:>10} {:>12} {:>12} {:>6}",
        msgs().bench_header_file,
        msgs().bench_header_orig,
        msgs().bench_header_comp_size,
        msgs().bench_header_ratio,
        msgs().bench_header_comp_time,
        msgs().bench_header_decomp_time,
        msgs().bench_header_verify
    );
    println!("{header}");

    for row in rows {
        let label = if row.name.len() > 32 {
            &row.name[row.name.len() - 32..]
        } else {
            &row.name
        };
        println!("=== {} ===", label);
        print_tool("rzp", &row.rzp, row.orig, tty);
        print_tool("gzip", &row.gzip, row.orig, tty);
        print_tool("zstd", &row.zstd, row.orig, tty);
        println!();
    }

    // 汇总（仅统计三个工具都可用且解压成功的行）。
    let mut totals = (0u64, 0u64, 0u64, 0u64); // (orig, rzp, gzip, zstd)
    for row in rows {
        if row.rzp.available && row.gzip.available && row.zstd.available {
            totals.0 += row.orig;
            totals.1 += row.rzp.comp_size;
            totals.2 += row.gzip.comp_size;
            totals.3 += row.zstd.comp_size;
        }
    }
    if totals.0 > 0 {
        println!(
            "{}",
            style::paint(msgs().bench_summary, style::Color::Bold, tty)
        );
        println!(
            "{}",
            tr!(
                msgs().bench_summary_fmt,
                human_size(totals.0),
                human_size(totals.1),
                pct(totals.1, totals.0),
                human_size(totals.2),
                pct(totals.2, totals.0),
                human_size(totals.3),
                pct(totals.3, totals.0)
            )
        );
    }
}

fn print_tool(name: &str, t: &BenchTool, orig: u64, tty: bool) {
    if !t.available {
        println!("{:<8} {:>12}", name, msgs().bench_na);
        return;
    }
    let ok = if t.decomp_ok {
        style::paint("OK", style::Color::Green, tty)
    } else {
        style::paint("FAIL", style::Color::Red, tty)
    };
    println!(
        "{:<8} {:>12} {:>12} {:>10} {:>12} {:>12} {:>6}",
        name,
        human_size(orig),
        human_size(t.comp_size),
        pct(t.comp_size, orig),
        dur(t.comp_time),
        dur(t.decomp_time),
        ok,
    );
}

fn human_size(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    if n < 1024 {
        return format!("{n} B");
    }
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    format!("{v:.2} {}", UNITS[u])
}

fn pct(comp: u64, orig: u64) -> String {
    if orig == 0 {
        return "100.0%".into();
    }
    format!("{:.1}%", comp as f64 * 100.0 / orig as f64)
}

fn dur(secs: f64) -> String {
    if secs < 0.000_001 {
        format!("{:.0}ns", secs * 1e9)
    } else if secs < 0.001 {
        format!("{:.1}µs", secs * 1e6)
    } else if secs < 1.0 {
        format!("{:.1}ms", secs * 1e3)
    } else {
        format!("{:.2}s", secs)
    }
}

/// 读取预设字典文件（整个文件内容，交由库内部截断到有效窗口）。
fn read_dict(path: &Path) -> Result<Vec<u8>> {
    std::fs::read(path).map_err(|e| rzp::Error::Io(tr!(msgs().cannot_read_dict, path.display(), e)))
}
fn open_input(path: &Path) -> Result<Box<dyn Read>> {
    if path == Path::new("-") {
        Ok(Box::new(BufReader::new(std::io::stdin())))
    } else {
        Ok(Box::new(BufReader::with_capacity(
            64 * 1024,
            File::open(path)?,
        )))
    }
}

/// 创建输出写入器：`-` 表示 stdout，否则创建文件（除非 `force`，否则拒绝覆盖）。
fn create_output_writer(path: &Path, force: bool) -> Result<Box<dyn Write>> {
    if path == Path::new("-") {
        Ok(Box::new(BufWriter::new(std::io::stdout())))
    } else {
        if path.exists() && !force {
            return Err(rzp::Error::Io(tr!(msgs().output_exists, path.display())));
        }
        Ok(Box::new(BufWriter::with_capacity(
            64 * 1024,
            File::create(path)?,
        )))
    }
}

/// 系统临时目录下的唯一临时文件，`Drop` 时自动删除。
struct TempFile {
    path: PathBuf,
}

impl TempFile {
    fn create() -> Result<Self> {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("rzp-{}-{}.tmp", std::process::id(), nanos));
        Ok(TempFile { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// 归档负载类型。
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// 单文件 RZP 流。
    FileStream,
    /// 旧式顺序（solid）目录归档。
    SolidDir,
    /// 新式索引目录归档（RZPA，尾部带中央目录）。
    IndexedDir,
}

/// 可随机访问的输入：普通文件直接打开；stdin 先缓冲到临时文件。
struct SeekableFile {
    file: File,
    _tmp: Option<TempFile>,
}

impl SeekableFile {
    fn open(path: &Path) -> Result<Self> {
        if path == Path::new("-") {
            let tmp = TempFile::create()?;
            {
                let mut f = BufWriter::with_capacity(64 * 1024, File::create(tmp.path())?);
                std::io::copy(&mut std::io::stdin().lock(), &mut f)?;
                f.flush()?;
            }
            let file = File::open(tmp.path())?;
            Ok(SeekableFile {
                file,
                _tmp: Some(tmp),
            })
        } else {
            let file = File::open(path)?;
            Ok(SeekableFile { file, _tmp: None })
        }
    }
}

impl Read for SeekableFile {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.file.read(buf)
    }
}

impl Seek for SeekableFile {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        self.file.seek(pos)
    }
}

/// 探测负载类型（读取头部后回卷到起始位置）。
fn peek_kind<R: Read + Seek>(r: &mut R) -> Result<Kind> {
    let mut hdr = [0u8; 8];
    r.read_exact(&mut hdr)?;
    r.seek(SeekFrom::Start(0))?;
    if hdr[0..4] == *b"RZPA" {
        return Ok(Kind::IndexedDir);
    }
    if hdr[0..3] == *b"RZP" {
        if hdr[5] & 0x04 != 0 {
            return Err(rzp::Error::PasswordRequired);
        }
        if hdr[5] & 0x08 != 0 {
            return Ok(Kind::SolidDir);
        }
        return Ok(Kind::FileStream);
    }
    Err(rzp::Error::Corrupt(msgs().corrupt_data.into()))
}

/// 打开输入并（必要时）解密，返回可随机访问读取器与负载类型。
///
/// 先直接打开并探测：若为加密信封（`PasswordRequired`），则用密码解密到临时
/// 文件后再次探测内层负载；这样可正确区分「加密的单文件 / solid 目录 / 索引
/// 目录」，且不影响未加密文件与多文件混合场景。
fn open_payload(input: &Path, password: Option<&str>) -> Result<(SeekableFile, Kind)> {
    let mut sf = SeekableFile::open(input)?;
    match peek_kind(&mut sf) {
        Ok(kind) => Ok((sf, kind)),
        Err(rzp::Error::PasswordRequired) => {
            let pw = password.ok_or(rzp::Error::PasswordRequired)?;
            let tmp = TempFile::create()?;
            {
                sf.seek(SeekFrom::Start(0))?;
                let mut dec = rzp::EncryptedDecoder::new(&mut sf, pw.as_bytes())?;
                let mut f = BufWriter::with_capacity(64 * 1024, File::create(tmp.path())?);
                std::io::copy(&mut dec, &mut f)?;
                f.flush()?;
            }
            let mut plain = SeekableFile {
                file: File::open(tmp.path())?,
                _tmp: Some(tmp),
            };
            let kind = peek_kind(&mut plain)?;
            Ok((plain, kind))
        }
        Err(e) => Err(e),
    }
}

/// 把内层明文临时文件流式加密到输出，返回加密后总字节数（内存有界）。
fn encrypt_inner_to_output(
    inner_path: &Path,
    output: &Path,
    level: u8,
    password: &str,
    crypto: &rzp::CryptoOptions,
    force: bool,
) -> Result<u64> {
    let total = std::fs::metadata(inner_path)
        .map_err(|e| rzp::Error::Io(tr!(msgs().cannot_read_temp, inner_path.display(), e)))?
        .len();

    let reader = BufReader::with_capacity(64 * 1024, File::open(inner_path)?);
    let out = CountingWriter::new(create_output_writer(output, force)?);
    let mut enc = rzp::EncryptedEncoder::new(
        out,
        level,
        password.as_bytes(),
        crypto.memory_kib,
        crypto.iterations,
        crypto.lanes,
        None,
        total,
    )?;

    let mut buf = [0u8; 64 * 1024];
    let mut reader = reader;
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        enc.write_all(&buf[..n])?;
    }

    let mut out = enc.finish()?;
    out.flush()?;
    Ok(out.count())
}

/// 成功后按 gzip 风格删除输入文件；`-k`、stdin/stdout、或输入输出同路径时跳过。
fn maybe_remove_input(input: &Path, output: &Path, keep: bool) {
    if keep {
        return;
    }
    if input == Path::new("-") || output == Path::new("-") {
        return;
    }
    if input == output {
        return;
    }
    if let Err(e) = std::fs::remove_file(input) {
        eprintln!(
            "{}",
            tr!(msgs().warn_cannot_remove_input, input.display(), e)
        );
    }
}

/// 目录压缩成功后删除整个输入目录（`-k` 保留；输出归档位于目录内时跳过删除）。
fn maybe_remove_input_dir(input: &Path, output: &Path, keep: bool) {
    if keep || input == output {
        return;
    }
    if output.starts_with(input) {
        eprintln!("{}", tr!(msgs().warn_output_inside_input, input.display()));
        return;
    }
    if let Err(e) = std::fs::remove_dir_all(input) {
        eprintln!("{}", tr!(msgs().warn_cannot_remove_dir, input.display(), e));
    }
}

/// 校验目录归档的输出目标：不能是 stdout，且已存在时需 `-f` 覆盖。
fn ensure_dir_output(output: &Path, force: bool) -> Result<()> {
    if output == Path::new("-") {
        return Err(rzp::Error::Io(msgs().dir_archive_no_stdout.into()));
    }
    if output.exists() && !force {
        return Err(rzp::Error::Io(tr!(
            msgs().output_exists_force,
            output.display()
        )));
    }
    Ok(())
}

/// 统计写入字节数的包装器，用于报告压缩后体积（对 stdout 同样适用）。
struct CountingWriter<W> {
    inner: W,
    count: u64,
}

impl<W> CountingWriter<W> {
    fn new(inner: W) -> Self {
        CountingWriter { inner, count: 0 }
    }

    fn count(&self) -> u64 {
        self.count
    }
}

impl<W: Write> Write for CountingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.count += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// 路径的可读标签：`-` 显示为 stdin/stdout。
fn label(path: &Path, is_input: bool) -> String {
    if path == Path::new("-") {
        if is_input {
            "(stdin)".to_string()
        } else {
            "(stdout)".to_string()
        }
    } else {
        path.display().to_string()
    }
}
