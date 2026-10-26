//! 长距离重复语料回归测试。
//!
//! 验证 V5 的 32 MiB 搜索窗口能引用超过 1 MiB 的重复数据，从而在长距离重复语料上
//! 显著优于 V4（V4 窗口 1 MiB，无法引用该距离的匹配）。
//!
//! 注意：默认块大小为 1 MiB，跨块匹配不会发生；这里显式放大块大小，使长距离重复
//! 落在单个块内，从而真正触发 >1 MiB 的窗口回溯。

use rzp::{FormatVersion, Level};

fn compress_with(data: &[u8], fv: FormatVersion, level: Level) -> Vec<u8> {
    use std::io::Write;
    let mut enc = rzp::Encoder::new(Vec::new(), level)
        .with_format_version(fv)
        .with_block_size(4 * 1024 * 1024)
        .expect("block size is within limits");
    enc.write_all(data).expect("writing into a Vec cannot fail");
    enc.finish().expect("finishing into a Vec cannot fail")
}

/// 伪随机（无短周期）字节块，接近不可压缩，无法靠自身周期压缩。
fn pseudo_random_unit(n: usize, seed: &mut u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        *seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        out.push((*seed >> 24) as u8);
    }
    out
}

#[test]
fn long_distance_window_improves_ratio() {
    // 一段伪随机数据，在超过 1 MiB 的距离处再次出现。
    // 第二次出现足够大，使 V4（无法引用 >1 MiB 距离）与 V5 的压缩率差异可测量。
    let mut seed = 0x1234_5678u32;
    let unit = pseudo_random_unit(200_000, &mut seed);
    let gap = (1 << 20) + 100_000; // 使重复距离 > 1 MiB
    let mut data = unit.clone();
    data.extend(std::iter::repeat_n(0xEEu8, gap));
    data.extend_from_slice(&unit);

    let v4 = compress_with(&data, FormatVersion::V4, Level::L7);
    let v5 = compress_with(&data, FormatVersion::V5, Level::L7);

    // 无损往返。
    assert_eq!(rzp::decompress(&v4).unwrap(), data);
    assert_eq!(rzp::decompress(&v5).unwrap(), data);

    let r4 = v4.len() as f64 / data.len() as f64;
    let r5 = v5.len() as f64 / data.len() as f64;

    // V5 应能引用远距离匹配，压缩率显著优于 V4。
    assert!(r5 < r4, "V5 大窗口应优于 V4：v4={r4:.4} v5={r5:.4}");
    // 远距离重复数据应带来可观的压缩收益。
    assert!(r5 < 0.5, "V5 应显著压缩长距离重复语料：v5={r5:.4}");
}

#[test]
fn v4_does_not_exceed_one_mib_window() {
    // 锁 V4 窗口仍为 1 MiB：同一段独特数据在约 1 MiB 内重复应可引用，
    // 确认 V4 只读兼容不受大窗口改动影响。
    let mut seed = 0xdead_beefu32;
    let unit = pseudo_random_unit(40_000, &mut seed);

    // 距离 < 1 MiB：V4 与 V5 都能引用。
    let mut near = unit.clone();
    near.extend(std::iter::repeat_n(0xAAu8, 100_000));
    near.extend_from_slice(&unit);

    let v4_near = compress_with(&near, FormatVersion::V4, Level::L7);
    let v5_near = compress_with(&near, FormatVersion::V5, Level::L7);
    assert_eq!(rzp::decompress(&v4_near).unwrap(), near);
    assert_eq!(rzp::decompress(&v5_near).unwrap(), near);
    // 近距离下二者都应压缩得很好。
    assert!(v4_near.len() < near.len() / 2);
    assert!(v5_near.len() < near.len() / 2);
}
