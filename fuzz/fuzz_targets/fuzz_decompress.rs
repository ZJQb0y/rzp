#![no_main]

use libfuzzer_sys::fuzz_target;

// 对解码器做健壮性模糊测试：任意字节作为输入，`decompress`/`inspect` 不得 panic
// （可返回错误）。该路径会覆盖 V5 FSE 块、V4 Huffman 块、repcode、32 MiB 窗口等
// 解码核心。同时喂给加密解码路径，覆盖外层信封解析与分块认证的健壮性。
fuzz_target!(|data: &[u8]| {
    let _ = rzp::decompress(data);
    let _ = rzp::inspect(&mut &data[..]);
    // 同时喂给加密解码路径，覆盖外层信封解析与分块认证的健壮性。
    let _ = rzp::decompress_encrypted(data, b"fuzz");

    // 用一段确定性数据经 V5（默认）压缩后再截断/翻转，提高 FSE 解码路径覆盖率。
    let mut seed = 0x9e37_79b9u32;
    let mut sample = Vec::with_capacity(64 * 1024);
    for _ in 0..64 * 1024 {
        seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        sample.push((seed >> 24) as u8);
    }
    sample.extend_from_slice(&[0xABu8; 16 * 1024]);
    let packed = rzp::compress(&sample, rzp::Level::L6);
    // 截断。
    let mut cut = packed.clone();
    cut.truncate(data.len().min(cut.len()));
    let _ = rzp::decompress(&cut);
    // 翻转若干字节。
    let mut flipped = packed.clone();
    for (i, b) in flipped.iter_mut().enumerate().take(data.len().min(flipped.len())) {
        *b ^= data[i % data.len().max(1)];
    }
    let _ = rzp::decompress(&flipped);
});
