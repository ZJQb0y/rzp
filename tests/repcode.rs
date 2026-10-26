//! 重复偏移（repcode）回归测试。
//!
//! V5 距离字母表把符号 0/1/2 定义为 rep0/rep1/rep2（最近 3 个距离），
//! 在大量等距重复的语料上应无损往返，且压缩率不劣于 V4。

use rzp::{FormatVersion, Level};

fn compress_with(data: &[u8], fv: FormatVersion, level: Level) -> Vec<u8> {
    use std::io::Write;
    let mut enc = rzp::Encoder::new(Vec::new(), level).with_format_version(fv);
    enc.write_all(data).expect("writing into a Vec cannot fail");
    enc.finish().expect("finishing into a Vec cannot fail")
}

#[test]
fn repcode_roundtrip_equidistant() {
    // 大量等距重复：产生相同距离的匹配序列，触发 rep0 复用。
    let pattern = b"the quick brown fox jumps over the lazy dog. ";
    let mut data = Vec::new();
    for _ in 0..2000 {
        data.extend_from_slice(pattern);
    }

    let v5 = compress_with(&data, FormatVersion::V5, Level::L6);
    assert_eq!(rzp::decompress(&v5).unwrap(), data);

    // 也应能压缩得很小（大量重复）。
    assert!(
        v5.len() < data.len() / 10,
        "等距重复应被显著压缩：{} -> {}",
        data.len(),
        v5.len()
    );
}

#[test]
fn repcode_not_worse_than_v4() {
    // 等距重复语料：V5 的 repcode 应不劣于 V4 的显式距离码。
    let pattern = b"abcabc-xyzxyz-123123 ";
    let mut data = Vec::new();
    for _ in 0..4000 {
        data.extend_from_slice(pattern);
    }

    let v4 = compress_with(&data, FormatVersion::V4, Level::L6);
    let v5 = compress_with(&data, FormatVersion::V5, Level::L6);

    assert_eq!(rzp::decompress(&v4).unwrap(), data);
    assert_eq!(rzp::decompress(&v5).unwrap(), data);

    // 允许 1% 的抖动，V5 应不劣于 V4。
    assert!(
        v5.len() <= v4.len() + v4.len() / 100,
        "V5 repcode 应不劣于 V4：v4={} v5={}",
        v4.len(),
        v5.len()
    );
}
