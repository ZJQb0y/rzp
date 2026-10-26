//! 格式版本兼容性回归测试。
//!
//! 锁定两条不变量：
//!   1. 历史 V4 流（黄金字节向量）可被当前解码器只读解码；
//!   2. 编码器通过 `with_format_version` / `with_legacy_v4` 开关产出 V4/V5，
//!      且二者均可无损往返。

use rzp::{inspect, FormatVersion, Level};

/// 由历史 VERSION 4 编码器产出的黄金字节向量。
///
/// 输入数据为 `b"the quick brown fox jumps over the lazy dog. ".repeat(16)`
/// （720 字节），压缩级别 L6。该字节序列必须永远可被解码器还原，锁定 V4 只读兼容。
const V4_GOLDEN: &[u8] = &[
    0x52, 0x5a, 0x50, 0x04, 0x06, 0x01, 0x00, 0x00, 0xd0, 0x02, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00,
    0x01, 0x02, 0xa4, 0x98, 0x95, 0x50, 0xa1, 0xa5, 0x99, 0x93, 0x9b, 0x50, 0x92, 0xa2, 0x9f, 0xa7,
    0x9e, 0x50, 0x96, 0x9f, 0xa8, 0x50, 0x9a, 0xa5, 0x9d, 0xa0, 0xa3, 0x50, 0x9f, 0xa6, 0x95, 0xa2,
    0x50, 0x04, 0x4e, 0x9c, 0x91, 0xaa, 0xa9, 0x50, 0x94, 0x9f, 0x97, 0x5e, 0x50, 0xc5, 0x2b, 0x31,
    0x4a, 0xcc, 0x1e, 0x15, 0x80, 0x00, 0x93, 0xaf, 0xf8, 0x70, 0xd0, 0x02, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00,
];

#[test]
fn v4_golden_vector_decodes() {
    let expected = b"the quick brown fox jumps over the lazy dog. ".repeat(16);
    assert_eq!(expected.len(), 720);

    // 头版本字节必须为 4。
    assert_eq!(V4_GOLDEN[3], 4);

    // 只读解码。
    let out = rzp::decompress(V4_GOLDEN).expect("V4 golden vector must decode");
    assert_eq!(out, expected);

    // inspect 也应接受并报告正确的元信息。
    let mut slice: &[u8] = V4_GOLDEN;
    let info = inspect(&mut slice).unwrap();
    assert_eq!(info.raw_size, 720);
    assert_eq!(info.level, Level::L6);
}

#[test]
fn format_version_v4_v5_roundtrip() {
    use std::io::Write;

    let data: Vec<u8> = {
        let mut seed = 0x9e37_79b9u32;
        let mut v = Vec::new();
        for _ in 0..80_000 {
            seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            v.push((seed >> 24) as u8);
        }
        v.extend_from_slice(&b"repeat repeat repeat".repeat(100));
        v
    };

    for fv in [FormatVersion::V4, FormatVersion::V5] {
        let mut enc = rzp::Encoder::new(Vec::new(), Level::L6).with_format_version(fv);
        enc.write_all(&data).unwrap();
        let packed = enc.finish().unwrap();

        // 头版本字节必须等于所选版本。
        assert_eq!(packed[3], fv.as_u8());

        let out = rzp::decompress(&packed).unwrap();
        assert_eq!(out, data, "format version {fv:?} roundtrip");
    }
}

#[test]
fn with_legacy_v4_matches_v4() {
    use std::io::Write;

    let data = b"legacy v4 switch".repeat(100);
    let mut enc = rzp::Encoder::new(Vec::new(), Level::L6).with_legacy_v4();
    enc.write_all(&data).unwrap();
    let packed = enc.finish().unwrap();

    assert_eq!(packed[3], FormatVersion::V4.as_u8());
    assert_eq!(rzp::decompress(&packed).unwrap(), data);
}
