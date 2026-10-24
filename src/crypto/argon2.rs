//! Argon2id 密钥派生（RFC 9106）。
//!
//! 从零实现：BLAKE2b 提供 H0 / H'（可变长度哈希），压缩函数 G 使用无消息
//! 输入的 BLAKE2b 轮置换（blamka）。支持 Argon2d / Argon2i / Argon2id 三种
//! 类型，本 crate 仅使用 Argon2id。

use super::blake2b::blake2b;

/// Argon2 版本号（0x13）。
const ARGON2_VERSION: u32 = 0x13;
/// 同步点（切片）数量。
const SYNC_POINTS: usize = 4;
/// 每个 1024 字节块内的 64 位字数。
const QWORDS_IN_BLOCK: usize = 128;
/// 块大小（字节）。
const BLOCK_SIZE: usize = 1024;
/// 单个地址块可提供的伪随机数个数（= 块内字数）。
const ADDRESSES_IN_BLOCK: usize = QWORDS_IN_BLOCK;

/// Argon2 专用的 BLAKE2b 轮置换（blamka = BLAKE2b + multiplication）。
///
/// 与标准 BLAKE2b 轮函数唯一区别是 `a = a + b` 改为
/// `a = a + b + 2 * (a & 0xFFFF_FFFF) * (b & 0xFFFF_FFFF)`（RFC 9106 §3.6 的 GB）。
#[inline]
fn f_bla_mka(x: u64, y: u64) -> u64 {
    let xy = (x & 0xFFFF_FFFF) * (y & 0xFFFF_FFFF);
    x.wrapping_add(y).wrapping_add(xy.wrapping_mul(2))
}

/// 无消息输入的 Argon2 轮置换（16 个 64 位字）。
#[inline]
fn blamka(v: &mut [u64; 16]) {
    #[inline]
    fn g(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize) {
        v[a] = f_bla_mka(v[a], v[b]);
        v[d] = (v[d] ^ v[a]).rotate_right(32);
        v[c] = f_bla_mka(v[c], v[d]);
        v[b] = (v[b] ^ v[c]).rotate_right(24);
        v[a] = f_bla_mka(v[a], v[b]);
        v[d] = (v[d] ^ v[a]).rotate_right(16);
        v[c] = f_bla_mka(v[c], v[d]);
        v[b] = (v[b] ^ v[c]).rotate_right(63);
    }

    g(v, 0, 4, 8, 12);
    g(v, 1, 5, 9, 13);
    g(v, 2, 6, 10, 14);
    g(v, 3, 7, 11, 15);
    g(v, 0, 5, 10, 15);
    g(v, 1, 6, 11, 12);
    g(v, 2, 7, 8, 13);
    g(v, 3, 4, 9, 14);
}

/// Argon2 压缩函数：`G(X, Y) = P(X XOR Y) XOR (X XOR Y)`。
fn compression_g(x: &[u64; QWORDS_IN_BLOCK], y: &[u64; QWORDS_IN_BLOCK]) -> [u64; QWORDS_IN_BLOCK] {
    let mut r = [0u64; QWORDS_IN_BLOCK];
    for i in 0..QWORDS_IN_BLOCK {
        r[i] = x[i] ^ y[i];
    }
    let tmp = r; // 保存 R = X XOR Y，供末尾再异或。

    // 行置换（8 行 × 16 字）。
    for i in 0..8 {
        let mut row = [0u64; 16];
        for (k, w) in row.iter_mut().enumerate() {
            *w = r[16 * i + k];
        }
        blamka(&mut row);
        for (k, w) in row.iter().enumerate() {
            r[16 * i + k] = *w;
        }
    }

    // 列置换（每列由 8 行中相邻两字组成，共 16 字）。
    for i in 0..8 {
        let mut col = [0u64; 16];
        for k in 0..8 {
            col[2 * k] = r[16 * k + 2 * i];
            col[2 * k + 1] = r[16 * k + 2 * i + 1];
        }
        blamka(&mut col);
        for k in 0..8 {
            r[16 * k + 2 * i] = col[2 * k];
            r[16 * k + 2 * i + 1] = col[2 * k + 1];
        }
    }

    let mut out = [0u64; QWORDS_IN_BLOCK];
    for i in 0..QWORDS_IN_BLOCK {
        out[i] = r[i] ^ tmp[i];
    }
    out
}

/// 可变长度哈希 H'（RFC 9106 §3.3）。
fn variable_length_hash(input: &[u8], out_len: usize) -> Vec<u8> {
    if out_len <= 64 {
        let mut buf = Vec::with_capacity(4 + input.len());
        buf.extend_from_slice(&(out_len as u32).to_le_bytes());
        buf.extend_from_slice(input);
        return blake2b(&buf, out_len);
    }
    let r = out_len.div_ceil(32) - 2;
    let mut out = Vec::with_capacity(out_len);

    let mut buf = Vec::with_capacity(4 + input.len());
    buf.extend_from_slice(&(out_len as u32).to_le_bytes());
    buf.extend_from_slice(input);

    // V1 = H^64(LE32(T) || input)；输出 A1 = V1 前 32 字节。
    let mut v = blake2b(&buf, 64);
    out.extend_from_slice(&v[..32]);

    // V2..Vr，各输出前 32 字节。
    for _ in 1..r {
        v = blake2b(&v, 64);
        out.extend_from_slice(&v[..32]);
    }

    // V_{r+1} = H^{T-32r}(V_r)。
    let last = out_len - 32 * r;
    v = blake2b(&v, last);
    out.extend_from_slice(&v);
    out
}

/// 计算 H0：把参数块哈希为 64 字节初始值。
#[allow(clippy::too_many_arguments)]
fn initial_hash(
    lanes: u32,
    out_len: u32,
    memory_kib: u32,
    passes: u32,
    version: u32,
    typ: u32,
    pwd: &[u8],
    salt: &[u8],
    secret: &[u8],
    ad: &[u8],
) -> [u8; 64] {
    let mut buf = Vec::new();
    let put_u32 = |buf: &mut Vec<u8>, v: u32| buf.extend_from_slice(&v.to_le_bytes());
    let put_bytes = |buf: &mut Vec<u8>, b: &[u8]| {
        put_u32(buf, b.len() as u32);
        buf.extend_from_slice(b);
    };
    put_u32(&mut buf, lanes);
    put_u32(&mut buf, out_len);
    put_u32(&mut buf, memory_kib);
    put_u32(&mut buf, passes);
    put_u32(&mut buf, version);
    put_u32(&mut buf, typ);
    put_bytes(&mut buf, pwd);
    put_bytes(&mut buf, salt);
    put_bytes(&mut buf, secret);
    put_bytes(&mut buf, ad);

    let h = blake2b(&buf, 64);
    h.try_into().expect("64-byte hash")
}

/// 把 u64 切片序列化为小端字节串。
fn words_to_bytes(words: &[u64]) -> Vec<u8> {
    let mut out = Vec::with_capacity(words.len() * 8);
    for w in words {
        out.extend_from_slice(&w.to_le_bytes());
    }
    out
}

/// 字节串解析为 1024 字节块（128 个 u64）。
fn bytes_to_block(bytes: &[u8]) -> [u64; QWORDS_IN_BLOCK] {
    debug_assert_eq!(bytes.len(), BLOCK_SIZE);
    let mut b = [0u64; QWORDS_IN_BLOCK];
    for (i, w) in b.iter_mut().enumerate() {
        let mut tmp = [0u8; 8];
        tmp.copy_from_slice(&bytes[i * 8..i * 8 + 8]);
        *w = u64::from_le_bytes(tmp);
    }
    b
}

/// 生成下一个地址块（Argon2i / 前半 Argon2id 的数据无关寻址）。
fn next_addresses(
    address: &mut [u64; QWORDS_IN_BLOCK],
    input: &mut [u64; QWORDS_IN_BLOCK],
    zero: &[u64; QWORDS_IN_BLOCK],
) {
    input[6] = input[6].wrapping_add(1);
    *address = compression_g(zero, input);
    *address = compression_g(zero, address);
}

/// 数据相关/无关共用的索引映射：把伪随机数映射到参考块的绝对索引。
fn index_alpha(
    pass: usize,
    slice: usize,
    index: usize,
    pseudo_rand: u32,
    same_lane: bool,
    segment_length: usize,
    lane_length: usize,
) -> usize {
    let reference_area_size: usize;
    if pass == 0 {
        if slice == 0 {
            reference_area_size = index - 1;
        } else if same_lane {
            reference_area_size = slice * segment_length + index - 1;
        } else {
            reference_area_size = slice * segment_length - if index == 0 { 1 } else { 0 };
        }
    } else if same_lane {
        reference_area_size = lane_length - segment_length + index - 1;
    } else {
        reference_area_size = lane_length - segment_length - if index == 0 { 1 } else { 0 };
    }

    let mut relative = pseudo_rand as u64;
    relative = relative.wrapping_mul(relative) >> 32;
    relative = (reference_area_size as u64)
        .wrapping_sub(1)
        .wrapping_sub((reference_area_size as u64).wrapping_mul(relative) >> 32);

    let start = if pass != 0 && slice != SYNC_POINTS - 1 {
        (slice + 1) * segment_length
    } else {
        0
    };
    (start + relative as usize) % lane_length
}

/// Argon2 核心。
///
/// 参数：`pwd` 密码、`salt` 盐、`lanes` 并行度 p、`out_len` 输出长度、
/// `memory_kib` 内存（KiB）、`passes` 迭代 t、`typ` 类型（2 = Argon2id）、
/// 可选 `secret` / `ad`（本 crate 传空）。
#[allow(clippy::too_many_arguments, clippy::explicit_counter_loop)]
pub fn argon2(
    pwd: &[u8],
    salt: &[u8],
    lanes: u32,
    out_len: u32,
    memory_kib: u32,
    passes: u32,
    typ: u32,
    secret: &[u8],
    ad: &[u8],
) -> Vec<u8> {
    let lanes_u32 = lanes.max(1);
    let lanes = lanes_u32 as usize;
    let passes = passes.max(1);

    // H0 使用原始的 memory_kib（不夹紧）。
    let h0 = initial_hash(
        lanes_u32,
        out_len,
        memory_kib,
        passes,
        ARGON2_VERSION,
        typ,
        pwd,
        salt,
        secret,
        ad,
    );

    // 内存分配：m 按 4*p 对齐，且不少于 8*p 块。
    let mut memory_blocks = (memory_kib as usize).max(2 * SYNC_POINTS * lanes);
    let segment_length = memory_blocks / (lanes * SYNC_POINTS);
    memory_blocks = segment_length * lanes * SYNC_POINTS;
    let lane_length = segment_length * SYNC_POINTS;

    let mut memory: Vec<[u64; QWORDS_IN_BLOCK]> = vec![[0u64; QWORDS_IN_BLOCK]; memory_blocks];

    // 初始化每车道前两块。
    for lane in 0..lanes {
        for k in 0..2u32 {
            let mut seed = h0.to_vec();
            seed.extend_from_slice(&k.to_le_bytes());
            seed.extend_from_slice(&(lane as u32).to_le_bytes());
            let block_bytes = variable_length_hash(&seed, BLOCK_SIZE);
            memory[lane * lane_length + k as usize] = bytes_to_block(&block_bytes);
        }
    }

    // 填充内存。
    for pass in 0..passes as usize {
        for slice in 0..SYNC_POINTS {
            let data_independent = typ == 1 || (typ == 2 && pass == 0 && slice < SYNC_POINTS / 2);

            for lane in 0..lanes {
                let zero_block = [0u64; QWORDS_IN_BLOCK];
                let mut input_block = [0u64; QWORDS_IN_BLOCK];
                let mut address_block = [0u64; QWORDS_IN_BLOCK];

                if data_independent {
                    input_block[0] = pass as u64;
                    input_block[1] = lane as u64;
                    input_block[2] = slice as u64;
                    input_block[3] = memory_blocks as u64;
                    input_block[4] = passes as u64;
                    input_block[5] = typ as u64;
                }

                let starting_index = if pass == 0 && slice == 0 { 2 } else { 0 };
                if pass == 0 && slice == 0 && data_independent {
                    next_addresses(&mut address_block, &mut input_block, &zero_block);
                }

                let mut curr_offset = lane * lane_length + slice * segment_length + starting_index;
                let mut prev_offset = if curr_offset.is_multiple_of(lane_length) {
                    curr_offset + lane_length - 1
                } else {
                    curr_offset - 1
                };

                for i in starting_index..segment_length {
                    if curr_offset % lane_length == 1 {
                        prev_offset = curr_offset - 1;
                    }

                    let pseudo_rand: u64 = if data_independent {
                        if i % ADDRESSES_IN_BLOCK == 0 {
                            next_addresses(&mut address_block, &mut input_block, &zero_block);
                        }
                        address_block[i % ADDRESSES_IN_BLOCK]
                    } else {
                        memory[prev_offset][0]
                    };

                    let mut ref_lane = ((pseudo_rand >> 32) % lanes as u64) as usize;
                    if pass == 0 && slice == 0 {
                        ref_lane = lane;
                    }

                    let ref_index = index_alpha(
                        pass,
                        slice,
                        i,
                        (pseudo_rand & 0xFFFF_FFFF) as u32,
                        ref_lane == lane,
                        segment_length,
                        lane_length,
                    );

                    let reference = memory[ref_lane * lane_length + ref_index];
                    let prev = memory[prev_offset];
                    let g = compression_g(&prev, &reference);

                    if pass == 0 {
                        memory[curr_offset] = g;
                    } else {
                        let old = memory[curr_offset];
                        let mut merged = g;
                        for k in 0..QWORDS_IN_BLOCK {
                            merged[k] ^= old[k];
                        }
                        memory[curr_offset] = merged;
                    }

                    curr_offset += 1;
                    prev_offset += 1;
                }
            }
        }
    }

    // 汇总：各车道末块异或。
    let mut final_block = memory[lane_length - 1];
    for lane in 1..lanes {
        let b = memory[lane * lane_length + lane_length - 1];
        for i in 0..QWORDS_IN_BLOCK {
            final_block[i] ^= b[i];
        }
    }

    let final_bytes = words_to_bytes(&final_block);
    variable_length_hash(&final_bytes, out_len as usize)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::sha256::hex;

    fn rfc9106_inputs() -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
        // RFC 9106 §5 共用输入：密码 32 字节 0x01、盐 16 字节 0x02、
        // 秘密 8 字节 0x03、关联数据 12 字节 0x04。
        (
            vec![0x01u8; 32],
            vec![0x02u8; 16],
            vec![0x03u8; 8],
            vec![0x04u8; 12],
        )
    }

    #[test]
    fn rfc9106_argon2id_p4() {
        // RFC 9106 §5.3：Argon2id, p=4, T=32, m=32 KiB, t=3。
        let (pwd, salt, secret, ad) = rfc9106_inputs();
        let tag = argon2(&pwd, &salt, 4, 32, 32, 3, 2, &secret, &ad);
        assert_eq!(
            hex(&tag),
            "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"
        );
    }

    #[test]
    fn rfc9106_argon2i_p4() {
        // RFC 9106 §5.2：Argon2i, p=4, T=32, m=32 KiB, t=3。
        let (pwd, salt, secret, ad) = rfc9106_inputs();
        let tag = argon2(&pwd, &salt, 4, 32, 32, 3, 1, &secret, &ad);
        assert_eq!(
            hex(&tag),
            "c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8"
        );
    }

    #[test]
    fn rfc9106_argon2d_p4() {
        // RFC 9106 §5.1：Argon2d, p=4, T=32, m=32 KiB, t=3。
        let (pwd, salt, secret, ad) = rfc9106_inputs();
        let tag = argon2(&pwd, &salt, 4, 32, 32, 3, 0, &secret, &ad);
        assert_eq!(
            hex(&tag),
            "512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb"
        );
    }

    #[test]
    fn rfc9106_argon2id_h0() {
        // RFC 9106 §5.3 的 Pre-hashing digest（H0）。
        let (pwd, salt, secret, ad) = rfc9106_inputs();
        let h0 = initial_hash(4, 32, 32, 3, ARGON2_VERSION, 2, &pwd, &salt, &secret, &ad);
        assert_eq!(
            hex(&h0),
            "2889de487eb42ae500c0007ed9252f1069eadec40d5765b485de6dc2437a67b8\
             546a2f0acc1a0882db8fcf74714b472e94df421a5da1112ffa11434370a1e997"
        );
    }

    #[test]
    fn rfc9106_argon2id_block_init() {
        // RFC 9106 §5.3 “After pass 0” 的 Block 0000 前两个 64 位字，
        // 即 B[0][0] 的初始化结果。
        let (pwd, salt, secret, ad) = rfc9106_inputs();
        let h0 = initial_hash(4, 32, 32, 3, ARGON2_VERSION, 2, &pwd, &salt, &secret, &ad);
        let mut seed = h0.to_vec();
        seed.extend_from_slice(&0u32.to_le_bytes());
        seed.extend_from_slice(&0u32.to_le_bytes());
        let block = bytes_to_block(&variable_length_hash(&seed, BLOCK_SIZE));
        assert_eq!(block[0], 0x6b2e09f10671bd43);
        assert_eq!(block[1], 0xf69f5c27918a21be);
    }
}
