//! 压缩率回归测试。
//!
//! 用固定、确定性的自建语料，断言：
//!   1. 各压缩级别可无损往返；
//!   2. 默认级别（L6）与最高级别（L9）的压缩比不劣于基线阈值；
//!   3. L9 不显著劣于 L6（防止高等级惰性匹配退化再次引入）。
//!
//! 语料覆盖文本 / 源码 / JSON / 高冗余 / 随机等典型形态。

use rzp::{compress, decompress, Level};

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
        out.pop(); // 去掉句尾空格
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

/// 压缩后大小 / 原始大小 的比值（越小越好）。
fn ratio(data: &[u8], level: Level) -> f64 {
    let packed = compress(data, level);
    packed.len() as f64 / data.len().max(1) as f64
}

#[test]
fn compression_ratio_regression() {
    struct Case {
        name: &'static str,
        data: Vec<u8>,
        /// L1..=L9 中最优压缩比的上限。
        best_max: f64,
        /// 默认级别 L6 压缩比的上限。
        l6_max: f64,
    }

    let cases = vec![
        Case {
            name: "text",
            data: text_corpus(128 * 1024),
            best_max: 0.18,
            l6_max: 0.19,
        },
        Case {
            name: "code",
            data: code_corpus(128 * 1024),
            best_max: 0.23,
            l6_max: 0.24,
        },
        Case {
            name: "json",
            data: json_corpus(128 * 1024),
            best_max: 0.17,
            l6_max: 0.18,
        },
        Case {
            name: "redundant",
            data: redundant_corpus(128 * 1024),
            best_max: 0.05,
            l6_max: 0.05,
        },
    ];

    for c in &cases {
        // 正确性：默认与最高等级均能往返还原。
        for lvl in [Level::L6, Level::L9] {
            let packed = compress(&c.data, lvl);
            assert_eq!(
                &decompress(&packed).unwrap()[..],
                &c.data[..],
                "{} roundtrip L{}",
                c.name,
                lvl.as_u8()
            );
        }

        let mut best = f64::MAX;
        for lvl in 1..=9u8 {
            best = best.min(ratio(&c.data, Level::from_u8(lvl)));
        }
        let l6 = ratio(&c.data, Level::L6);
        let l9 = ratio(&c.data, Level::L9);

        assert!(
            best < c.best_max,
            "{}: 最佳压缩比 {best} 超过基线 {}",
            c.name,
            c.best_max
        );
        assert!(
            l6 < c.l6_max,
            "{}: L6 压缩比 {l6} 超过基线 {}",
            c.name,
            c.l6_max
        );
        // 高等级不应显著劣于默认等级（防止惰性匹配退化回归）。
        assert!(
            l9 <= l6 * 1.05 + 1e-9,
            "{}: L9 压缩比 {l9} 明显劣于 L6 {l6}",
            c.name
        );
    }

    // 随机数据接近不可压缩：仅校验默认级别不会过度膨胀。
    let random = random_corpus(64 * 1024);
    assert_eq!(
        &decompress(&compress(&random, Level::L6)).unwrap()[..],
        &random[..]
    );
    assert!(ratio(&random, Level::L6) < 1.10, "random: L6 压缩比过高");
}
