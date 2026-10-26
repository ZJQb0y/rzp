//! RZP 基准：压缩率与吞吐量对比。
//!
//! 用法（release 优化下运行）：
//!
//! ```text
//! cargo bench --bench bench
//! ```
//!
//! 生成确定性语料（文本 / 源码 / JSON / 高冗余 / 随机，各 1 MiB），分别测量
//! RZP 的 L1/L6/L9 压缩率与吞吐量；若系统 `PATH` 上存在 `gzip` 或 `zstd`，
//! 则一并对比（stdin→stdout 单流），输出一张文本对比表，作为后续改动的前后基准。
//!
//! 只依赖标准库与系统命令，不引入任何第三方 crate，符合「零第三方依赖」约定。

use std::io::Write;
use std::process::{Command, Stdio};
use std::time::Instant;

use rzp::{compress, Level};

/// 每份语料的字节数（1 MiB，跨多个块，避免块级并行主导计时）。
const CORPUS_SIZE: usize = 1 << 20;

/// 确定性 LCG，返回一个伪随机字节并推进状态。
fn lcg(state: &mut u32) -> u8 {
    *state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
    (*state >> 24) as u8
}

/// 自然语言风格的文本语料（含大量重复单词与句子结构）。
fn text_corpus(n: usize) -> Vec<u8> {
    const WORDS: &[&str] = &[
        "the",
        "quick",
        "brown",
        "fox",
        "jumps",
        "over",
        "lazy",
        "dog",
        "compression",
        "algorithm",
        "entropy",
        "coding",
        "huffman",
        "lz77",
        "streaming",
        "format",
        "integrity",
        "checksum",
        "encryption",
        "password",
    ];
    let mut out = Vec::with_capacity(n);
    let mut state = 0x9e37_79b9u32;
    while out.len() < n {
        let word_count = 4 + (lcg(&mut state) as usize % 9);
        for _ in 0..word_count {
            let w = WORDS[lcg(&mut state) as usize % WORDS.len()];
            out.extend_from_slice(w.as_bytes());
            out.push(b' ');
        }
        out.pop();
        out.extend_from_slice(b".\n");
    }
    out.truncate(n);
    out
}

/// 源码风格的语料（关键字 + 标识符 + 缩进结构）。
fn code_corpus(n: usize) -> Vec<u8> {
    const KWS: &[&str] = &[
        "fn", "let", "mut", "for", "in", "if", "else", "return", "match", "struct", "impl", "pub",
        "use", "mod", "while", "loop", "const",
    ];
    let mut out = Vec::with_capacity(n);
    let mut state = 0xdead_beefu32;
    let mut indent = 0usize;
    while out.len() < n {
        for _ in 0..indent {
            out.extend_from_slice(b"    ");
        }
        let kw = KWS[lcg(&mut state) as usize % KWS.len()];
        out.extend_from_slice(kw.as_bytes());
        out.push(b' ');
        out.extend_from_slice(b"ident_");
        let num = lcg(&mut state);
        out.extend_from_slice(format!("{num} = {};\n", lcg(&mut state)).as_bytes());
        indent = (indent + 1) % 4;
    }
    out.truncate(n);
    out
}

/// JSON 风格的语料（键值对 + 嵌套括号）。
fn json_corpus(n: usize) -> Vec<u8> {
    const KEYS: &[&str] = &[
        "name",
        "value",
        "id",
        "type",
        "status",
        "payload",
        "timestamp",
        "offset",
        "length",
        "checksum",
    ];
    let mut out = Vec::with_capacity(n);
    let mut state = 0x0123_4567u32;
    while out.len() < n {
        out.extend_from_slice(b"{\"");
        let k = KEYS[lcg(&mut state) as usize % KEYS.len()];
        out.extend_from_slice(k.as_bytes());
        out.extend_from_slice(b"\": ");
        let num = lcg(&mut state);
        out.extend_from_slice(format!("{num},\n").as_bytes());
        let k2 = KEYS[lcg(&mut state) as usize % KEYS.len()];
        out.extend_from_slice(format!("\"{k2}\": \"value_{num}\"}},\n").as_bytes());
    }
    out.truncate(n);
    out
}

/// 高冗余语料：固定 64 字节模式重复。
fn redundant_corpus(n: usize) -> Vec<u8> {
    let pattern: Vec<u8> = (0..64u32).map(|i| (i % 251) as u8).collect();
    let mut out = Vec::with_capacity(n);
    while out.len() < n {
        out.extend_from_slice(&pattern);
    }
    out.truncate(n);
    out
}

/// 伪随机语料（接近不可压缩）。
fn random_corpus(n: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(n);
    let mut state = 0xcafe_babeu32;
    for _ in 0..n {
        out.push(lcg(&mut state));
    }
    out
}

/// 一行对比结果。
struct Row {
    tool: String,
    packed: usize,
    ratio_pct: f64,
    mbps: f64,
}

impl Row {
    fn new(tool: String, raw: usize, packed: usize, secs: f64) -> Self {
        Row {
            tool,
            packed,
            ratio_pct: packed as f64 * 100.0 / raw.max(1) as f64,
            mbps: raw as f64 / 1e6 / secs.max(1e-9),
        }
    }
}

/// 测量 RZP 某个级别的压缩结果与耗时。
fn measure_rzp(data: &[u8], level: Level) -> Row {
    let start = Instant::now();
    let packed = compress(data, level);
    Row::new(
        format!("rzp L{}", level.as_u8()),
        data.len(),
        packed.len(),
        start.elapsed().as_secs_f64(),
    )
}

/// 测量 RZP 某级别、按历史 V4 格式输出的压缩结果与耗时。
fn measure_rzp_v4(data: &[u8], level: Level) -> Row {
    use std::io::Write;
    let start = Instant::now();
    let mut enc = rzp::Encoder::new(Vec::new(), level).with_legacy_v4();
    enc.write_all(data).expect("writing into a Vec cannot fail");
    let packed = enc.finish().expect("finishing into a Vec cannot fail");
    Row::new(
        format!("rzp L{} (v4)", level.as_u8()),
        data.len(),
        packed.len(),
        start.elapsed().as_secs_f64(),
    )
}

/// 按指定线程数测量 RZP 压缩吞吐（用于多线程缩放对比）。
fn measure_rzp_threads(data: &[u8], level: Level, threads: usize) -> Row {
    use std::io::Write;
    let start = Instant::now();
    let mut enc = rzp::Encoder::new(Vec::new(), level).with_threads(threads);
    enc.write_all(data).expect("writing into a Vec cannot fail");
    let packed = enc.finish().expect("finishing into a Vec cannot fail");
    Row::new(
        format!("rzp L{} (j={})", level.as_u8(), threads),
        data.len(),
        packed.len(),
        start.elapsed().as_secs_f64(),
    )
}

/// 通过系统命令测量外部工具（stdin→stdout 单流）。失败或不存在返回 `None`。
fn measure_external(tool: &str, label: &str, args: &[&str], data: &[u8]) -> Option<Row> {
    let mut child = Command::new(tool)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let mut stdin = child.stdin.take()?;
    let start = Instant::now();

    // 并发写 stdin 与读 stdout，避免管道缓冲区填满导致的死锁。
    let out = std::thread::scope(|scope| {
        scope.spawn(move || {
            let _ = stdin.write_all(data);
        });
        child.wait_with_output()
    })
    .ok()?;

    if !out.status.success() {
        return None;
    }
    Some(Row::new(
        label.to_string(),
        data.len(),
        out.stdout.len(),
        start.elapsed().as_secs_f64(),
    ))
}

/// 判断某系统命令是否可用。
fn tool_available(tool: &str) -> bool {
    Command::new(tool)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn print_corpus(name: &str, data: &[u8], have_gzip: bool, have_zstd: bool) {
    println!("== {name} ==");
    println!(
        "{:<14} {:>10} {:>8} {:>9}",
        "tool", "packed", "ratio%", "MB/s"
    );

    let mut rows = vec![
        measure_rzp(data, Level::L1),
        measure_rzp(data, Level::L6),
        measure_rzp(data, Level::L9),
        measure_rzp_v4(data, Level::L9),
    ];
    if have_gzip {
        if let Some(r) = measure_external("gzip", "gzip -6", &["-c", "-6"], data) {
            rows.push(r);
        }
        if let Some(r) = measure_external("gzip", "gzip -9", &["-c", "-9"], data) {
            rows.push(r);
        }
    }
    if have_zstd {
        if let Some(r) = measure_external("zstd", "zstd -3", &["-q", "-c", "-3"], data) {
            rows.push(r);
        }
        if let Some(r) = measure_external("zstd", "zstd -19", &["-q", "-c", "-19"], data) {
            rows.push(r);
        }
    }

    for r in &rows {
        println!(
            "{:<14} {:>10} {:>7.1}% {:>9.1}",
            r.tool, r.packed, r.ratio_pct, r.mbps
        );
    }
    println!();
}

fn main() {
    let corpus: Vec<(&str, Vec<u8>)> = vec![
        ("text", text_corpus(CORPUS_SIZE)),
        ("code", code_corpus(CORPUS_SIZE)),
        ("json", json_corpus(CORPUS_SIZE)),
        ("redundant", redundant_corpus(CORPUS_SIZE)),
        ("random", random_corpus(CORPUS_SIZE)),
    ];

    let have_gzip = tool_available("gzip");
    let have_zstd = tool_available("zstd");

    println!("RZP benchmark — {} MiB per corpus", CORPUS_SIZE >> 20);
    if !have_gzip && !have_zstd {
        println!("(未检测到 gzip/zstd，仅输出 RZP 自身对比；安装后重新运行可得到对比表)");
    }
    println!();

    for (name, data) in &corpus {
        print_corpus(name, data, have_gzip, have_zstd);
    }

    print_scaling(&corpus);
}

/// 多线程缩放对比：用一块足够大、跨多个块（约 8 MiB）的混合语料，测量
/// `threads = 1` 与 `threads = default_threads()` 的吞吐，展示单流并行对单一大文件
/// 的加速；同时 L6（4 字节哈希链）与 L9（二分树）的压缩率对比已在上一节按级别列出。
fn print_scaling(_corpus: &[(&str, Vec<u8>)]) {
    let threads = rzp::default_threads();
    if threads <= 1 {
        return;
    }
    // 8 MiB 混合语料：随机数据 + 高重复段交替，横跨多个 1 MiB 块。
    let n = 8 << 20;
    let mut data = Vec::with_capacity(n);
    let mut state = 0x9e37_79b9u32;
    while data.len() < n {
        for _ in 0..(1 << 16) {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            data.push((state >> 24) as u8);
        }
        let b = (state >> 24) as u8;
        data.extend(std::iter::repeat_n(b, 1 << 16));
    }
    data.truncate(n);

    println!("== 多线程缩放（threads=1 vs {threads}，8 MiB 混合语料）==");
    println!(
        "{:<14} {:>10} {:>8} {:>9} {:>9}",
        "tool", "packed", "ratio%", "MB/s", "speedup"
    );
    let single = measure_rzp_threads(&data, Level::L6, 1);
    let multi = measure_rzp_threads(&data, Level::L6, threads);
    println!(
        "{:<14} {:>10} {:>7.1}% {:>9.1} {:>8.2}x",
        "L6 (1t)", single.packed, single.ratio_pct, single.mbps, 1.0
    );
    println!(
        "{:<14} {:>10} {:>7.1}% {:>9.1} {:>8.2}x",
        format!("L6 ({threads}t)"),
        multi.packed,
        multi.ratio_pct,
        multi.mbps,
        multi.mbps / single.mbps
    );
}
