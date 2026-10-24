#![no_main]

use libfuzzer_sys::fuzz_target;

// 对解码器做健壮性模糊测试：任意字节作为输入，`decompress`/`inspect` 不得 panic
// （可返回错误）。该路径会覆盖内部 `read_lengths` 与 `decode_symbol` 等解码核心。
fuzz_target!(|data: &[u8]| {
    let _ = rzp::decompress(data);
    let _ = rzp::inspect(&mut &data[..]);
    // 同时喂给加密解码路径，覆盖外层信封解析与分块认证的健壮性。
    let _ = rzp::decompress_encrypted(data, b"fuzz");
});
