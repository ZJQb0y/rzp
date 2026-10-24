//! 目录归档容器：把整个目录树打包为单一字节流（之后再交由 RZP 压缩）。
//!
//! 保留：相对路径、文件内容、空目录、符号链接、权限位（mode）、修改时间（mtime）、
//! uid/gid、扩展属性（xattr，含 POSIX ACL）、硬链接与稀疏文件布局。
//! 不跟随符号链接；特殊文件（fifo/socket/设备）会被跳过。

use std::collections::HashMap;
use std::fs::{self, File, FileTimes};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::time::UNIX_EPOCH;

use crate::{Error, Level};

/// 平台差异封装：路径字节、元数据字段、属主/权限/符号链接。
///
/// 归档容器以「原始 OS 字节」记录路径名；Unix 上是原生字节，Windows 上是
/// `OsStr::as_encoded_bytes()` 产出的 WTF-8 字节，二者在各自平台上回放即可。
mod platform {
    use std::fs;
    use std::io;
    use std::path::{Path, PathBuf};

    /// 把路径表示为原始字节（Unix：原生字节；Windows：WTF-8）。
    #[cfg(unix)]
    pub fn path_bytes(path: &Path) -> &[u8] {
        use std::os::unix::ffi::OsStrExt;
        path.as_os_str().as_bytes()
    }

    #[cfg(windows)]
    pub fn path_bytes(path: &Path) -> &[u8] {
        path.as_os_str().as_encoded_bytes()
    }

    /// 把原始字节解释为路径（借用）。
    #[cfg(unix)]
    pub fn path_from_bytes(bytes: &[u8]) -> &Path {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        Path::new(OsStr::from_bytes(bytes))
    }

    #[cfg(windows)]
    pub fn path_from_bytes(bytes: &[u8]) -> &Path {
        use std::ffi::OsStr;
        // 字节源自同一平台的 `as_encoded_bytes`，满足 unsafe 契约。
        Path::new(unsafe { OsStr::from_encoded_bytes_unchecked(bytes) })
    }

    /// 把原始字节解释为拥有所有权的路径。
    pub fn path_owned_from_bytes(bytes: &[u8]) -> PathBuf {
        path_from_bytes(bytes).to_path_buf()
    }

    #[cfg(unix)]
    pub fn meta_mode(meta: &fs::Metadata) -> u32 {
        use std::os::unix::fs::MetadataExt;
        (meta.mode() & 0o7777) as u32
    }

    #[cfg(windows)]
    pub fn meta_mode(_meta: &fs::Metadata) -> u32 {
        0
    }

    #[cfg(unix)]
    pub fn meta_uid(meta: &fs::Metadata) -> u32 {
        use std::os::unix::fs::MetadataExt;
        meta.uid()
    }

    #[cfg(windows)]
    pub fn meta_uid(_meta: &fs::Metadata) -> u32 {
        0
    }

    #[cfg(unix)]
    pub fn meta_gid(meta: &fs::Metadata) -> u32 {
        use std::os::unix::fs::MetadataExt;
        meta.gid()
    }

    #[cfg(windows)]
    pub fn meta_gid(_meta: &fs::Metadata) -> u32 {
        0
    }

    #[cfg(unix)]
    pub fn meta_mtime_sec(meta: &fs::Metadata) -> i64 {
        use std::os::unix::fs::MetadataExt;
        meta.mtime()
    }

    #[cfg(windows)]
    pub fn meta_mtime_sec(meta: &fs::Metadata) -> i64 {
        modified_parts(meta).0
    }

    #[cfg(unix)]
    pub fn meta_mtime_nsec(meta: &fs::Metadata) -> u32 {
        use std::os::unix::fs::MetadataExt;
        meta.mtime_nsec() as u32
    }

    #[cfg(windows)]
    pub fn meta_mtime_nsec(meta: &fs::Metadata) -> u32 {
        modified_parts(meta).1
    }

    #[cfg(windows)]
    fn modified_parts(meta: &fs::Metadata) -> (i64, u32) {
        use std::time::UNIX_EPOCH;
        match meta.modified() {
            Ok(t) => match t.duration_since(UNIX_EPOCH) {
                Ok(d) => (d.as_secs() as i64, d.subsec_nanos()),
                Err(_) => (0, 0),
            },
            Err(_) => (0, 0),
        }
    }

    /// inode 键，用于硬链接去重。Windows 无此概念，恒返回 `(0, 0)`。
    #[cfg(unix)]
    pub fn meta_inode_key(meta: &fs::Metadata) -> (u64, u64) {
        use std::os::unix::fs::MetadataExt;
        (meta.dev(), meta.ino())
    }

    #[cfg(windows)]
    pub fn meta_inode_key(_meta: &fs::Metadata) -> (u64, u64) {
        (0, 0)
    }

    #[cfg(unix)]
    pub fn meta_nlink(meta: &fs::Metadata) -> u64 {
        use std::os::unix::fs::MetadataExt;
        meta.nlink()
    }

    #[cfg(windows)]
    pub fn meta_nlink(_meta: &fs::Metadata) -> u64 {
        1
    }

    /// 稀疏判定：实际分配块字节数小于逻辑大小。Windows 不判定，恒返回 false。
    #[cfg(unix)]
    pub fn is_sparse(meta: &fs::Metadata) -> bool {
        use std::os::unix::fs::MetadataExt;
        meta.blocks().saturating_mul(512) < meta.len()
    }

    #[cfg(windows)]
    pub fn is_sparse(_meta: &fs::Metadata) -> bool {
        false
    }

    #[cfg(unix)]
    pub fn set_owner(path: &Path, uid: Option<u32>, gid: Option<u32>) {
        use std::os::unix::fs::chown;
        let _ = chown(path, uid, gid);
    }

    #[cfg(windows)]
    pub fn set_owner(_path: &Path, _uid: Option<u32>, _gid: Option<u32>) {}

    #[cfg(unix)]
    pub fn lchown(path: &Path, uid: Option<u32>, gid: Option<u32>) {
        use std::os::unix::fs::lchown;
        let _ = lchown(path, uid, gid);
    }

    #[cfg(windows)]
    pub fn lchown(_path: &Path, _uid: Option<u32>, _gid: Option<u32>) {}

    #[cfg(unix)]
    pub fn set_mode(path: &Path, mode: u32) {
        use std::fs::Permissions;
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, Permissions::from_mode(mode));
    }

    #[cfg(windows)]
    pub fn set_mode(_path: &Path, _mode: u32) {}

    /// 创建符号链接。Windows 上符号链接需要权限，先按文件、再按目录尝试。
    #[cfg(unix)]
    pub fn create_symlink(link: &[u8], target: &Path) -> io::Result<()> {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::symlink;
        symlink(OsStr::from_bytes(link), target)
    }

    #[cfg(windows)]
    pub fn create_symlink(link: &[u8], target: &Path) -> io::Result<()> {
        use std::ffi::OsStr;
        use std::os::windows::fs::{symlink_dir, symlink_file};
        let link = Path::new(unsafe { OsStr::from_encoded_bytes_unchecked(link) });
        symlink_file(link, target).or_else(|_| symlink_dir(link, target))
    }
}

const TYPE_FILE: u8 = 0;
const TYPE_DIR: u8 = 1;
const TYPE_SYMLINK: u8 = 2;
const TYPE_HARDLINK: u8 = 3;
const TYPE_END: u8 = 0xFF;

/// 条目标志位 bit0：稀疏文件（数据为「扩展区列表」而非完整内容）。
const FLAG_SPARSE: u8 = 0x01;

/// 条目头大小（字节）：type(1) + name_len(2) + mode(4) + mtime_sec(8) + mtime_nsec(4) + size(8)。
const HEADER_SIZE: usize = 27;

/// 把 `root` 目录树打包写入 `out`。条目路径相对于 `root` 记录。
pub fn write_dir<W: Write>(root: &Path, out: &mut W) -> io::Result<()> {
    write_dir_filtered(root, out, &|_, _| true)
}

/// 与 [`write_dir`] 相同，但 `filter` 决定是否收录某条目。回调参数为
/// （相对 `root` 的路径, 是否为目录）。返回 `false` 的目录连同其子树一并跳过；
/// 返回 `false` 的文件被跳过。目录不因 `--include` 而被剪枝，以保证能遍历到
/// 可能匹配的后代。
pub fn write_dir_filtered<W: Write>(
    root: &Path,
    out: &mut W,
    filter: &dyn Fn(&Path, bool) -> bool,
) -> io::Result<()> {
    write_tree(root, root, out, filter)?;
    write_end(out)
}

fn write_tree<W: Write>(
    root: &Path,
    dir: &Path,
    out: &mut W,
    filter: &dyn Fn(&Path, bool) -> bool,
) -> io::Result<()> {
    let mut paths: Vec<PathBuf> = fs::read_dir(dir)?
        .map(|e| e.map(|e| e.path()))
        .collect::<io::Result<_>>()?;
    paths.sort();

    for path in paths {
        let meta = fs::symlink_metadata(&path)?;
        let rel = path.strip_prefix(root).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "failed to strip root prefix")
        })?;
        let ft = meta.file_type();
        if !filter(rel, ft.is_dir()) {
            continue;
        }
        let name = platform::path_bytes(rel);
        let mode = platform::meta_mode(&meta);

        if ft.is_dir() {
            write_entry(
                out,
                TYPE_DIR,
                name,
                mode,
                platform::meta_mtime_sec(&meta),
                platform::meta_mtime_nsec(&meta),
                0,
            )?;
            write_tree(root, &path, out, filter)?;
        } else if ft.is_file() {
            let size = meta.len();
            write_entry(
                out,
                TYPE_FILE,
                name,
                mode,
                platform::meta_mtime_sec(&meta),
                platform::meta_mtime_nsec(&meta),
                size,
            )?;
            let mut f = File::open(&path)?;
            io::copy(&mut f, out)?;
        } else if ft.is_symlink() {
            let target = fs::read_link(&path)?;
            let target = platform::path_bytes(&target);
            write_entry(out, TYPE_SYMLINK, name, 0, 0, 0, target.len() as u64)?;
            out.write_all(target)?;
        }
        // 其余特殊文件（fifo/socket/设备）跳过。
    }
    Ok(())
}

fn write_entry<W: Write>(
    out: &mut W,
    ty: u8,
    name: &[u8],
    mode: u32,
    mtime_sec: i64,
    mtime_nsec: u32,
    size: u64,
) -> io::Result<()> {
    let name_len = u16::try_from(name.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "file name too long"))?;
    let mut h = [0u8; HEADER_SIZE];
    h[0] = ty;
    h[1..3].copy_from_slice(&name_len.to_le_bytes());
    h[3..7].copy_from_slice(&mode.to_le_bytes());
    h[7..15].copy_from_slice(&mtime_sec.to_le_bytes());
    h[15..19].copy_from_slice(&mtime_nsec.to_le_bytes());
    h[19..27].copy_from_slice(&size.to_le_bytes());
    out.write_all(&h)?;
    out.write_all(name)?;
    Ok(())
}

fn write_end<W: Write>(out: &mut W) -> io::Result<()> {
    write_entry(out, TYPE_END, &[], 0, 0, 0, 0)
}

/// 归档条目的元信息（供列表 / 随机访问使用）。
pub struct Entry {
    pub ty: u8,
    pub name: Vec<u8>,
    pub mode: u32,
    pub mtime_sec: i64,
    pub mtime_nsec: u32,
    pub size: u64,
}

impl Entry {
    /// 条目的相对路径（按原始字节解释为 OS 路径）。
    pub fn path(&self) -> &Path {
        platform::path_from_bytes(&self.name)
    }

    /// 类型的人类可读名。
    pub fn type_name(&self) -> &'static str {
        match self.ty {
            TYPE_FILE => "file",
            TYPE_DIR => "dir",
            TYPE_SYMLINK => "symlink",
            _ => "other",
        }
    }
}

fn read_entry<R: Read>(input: &mut R) -> io::Result<Entry> {
    let mut h = [0u8; HEADER_SIZE];
    input.read_exact(&mut h)?;
    let ty = h[0];
    let name_len = u16::from_le_bytes([h[1], h[2]]) as usize;
    let mode = u32::from_le_bytes([h[3], h[4], h[5], h[6]]);
    let mtime_sec = i64::from_le_bytes(h[7..15].try_into().unwrap());
    let mtime_nsec = u32::from_le_bytes(h[15..19].try_into().unwrap());
    let size = u64::from_le_bytes(h[19..27].try_into().unwrap());
    let mut name = vec![0u8; name_len];
    input.read_exact(&mut name)?;
    Ok(Entry {
        ty,
        name,
        mode,
        mtime_sec,
        mtime_nsec,
        size,
    })
}

/// 顺序读取每个条目元信息并回调 `f`，数据部分被跳过（不写盘、不产出内容）。
///
/// 供 `rzp l` 使用；`input` 需已定位到首条条目处（同 [`extract`]）。
pub fn list<R: Read>(input: &mut R, mut f: impl FnMut(&Entry) -> io::Result<()>) -> io::Result<()> {
    loop {
        let e = read_entry(input)?;
        if e.ty == TYPE_END {
            break;
        }
        skip_n(input, e.size)?;
        f(&e)?;
    }
    Ok(())
}

/// 跳过 `n` 字节（`read_exact`，复用栈缓冲）。
fn skip_n<R: Read>(input: &mut R, mut n: u64) -> io::Result<()> {
    let mut buf = [0u8; 64 * 1024];
    while n > 0 {
        let want = buf.len().min(n as usize);
        input.read_exact(&mut buf[..want])?;
        n -= want as u64;
    }
    Ok(())
}

/// 从 `input` 解出目录归档，写入 `dest` 目录（`dest` 会被自动创建）。
///
/// `input` 需已定位到首条条目处（即不含任何前缀），由调用方先通过流头
/// `FLAG_DIR` 判定为目录归档后再调用。
pub fn extract<R: Read>(input: &mut R, dest: &Path) -> io::Result<()> {
    fs::create_dir_all(dest)?;
    loop {
        let entry = read_entry(input)?;
        if entry.ty == TYPE_END {
            break;
        }
        extract_entry(input, &entry, dest)?;
    }
    Ok(())
}

fn extract_entry<R: Read>(input: &mut R, e: &Entry, dest: &Path) -> io::Result<()> {
    let rel = sanitize_name(&e.name)?;
    let target = dest.join(&rel);
    match e.ty {
        TYPE_DIR => {
            fs::create_dir_all(&target)?;
            set_meta(&target, e.mode, None, None, e.mtime_sec, e.mtime_nsec);
        }
        TYPE_FILE => {
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)?;
            }
            let mut f = File::create(&target)?;
            copy_n(input, &mut f, e.size)?;
            f.flush()?;
            drop(f);
            set_meta(&target, e.mode, None, None, e.mtime_sec, e.mtime_nsec);
        }
        TYPE_SYMLINK => {
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)?;
            }
            let mut link = vec![0u8; e.size as usize];
            input.read_exact(&mut link)?;
            match fs::symlink_metadata(&target) {
                Ok(m) if m.is_dir() => fs::remove_dir_all(&target)?,
                Ok(_) => fs::remove_file(&target)?,
                Err(_) => {}
            }
            platform::create_symlink(&link, &target)?;
        }
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown entry type {other}"),
            ));
        }
    }
    Ok(())
}

/// 精确复制 `n` 字节（`read_exact` + `write_all`），避免越界读到下一条目。
fn copy_n<R: Read, W: Write>(input: &mut R, out: &mut W, mut n: u64) -> io::Result<()> {
    let mut buf = [0u8; 64 * 1024];
    while n > 0 {
        let want = buf.len().min(n as usize);
        input.read_exact(&mut buf[..want])?;
        out.write_all(&buf[..want])?;
        n -= want as u64;
    }
    Ok(())
}

/// 把归档里的路径名解析为安全的相对路径，拒绝绝对路径与 `..` 穿越。
fn sanitize_name(name: &[u8]) -> io::Result<PathBuf> {
    let path = platform::path_owned_from_bytes(name);
    for comp in path.components() {
        match comp {
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unsafe path in archive",
                ));
            }
            _ => {}
        }
    }
    Ok(path)
}

/// 恢复属主、权限与修改时间（best-effort：失败不中断解压）。
///
/// `uid`/`gid` 传 `None` 表示不改动属主（旧式 solid 归档不记录属主）。
fn set_meta(
    path: &Path,
    mode: u32,
    uid: Option<u32>,
    gid: Option<u32>,
    mtime_sec: i64,
    mtime_nsec: u32,
) {
    // chown 可能清除 setuid/setgid，故先 chown 再 chmod。
    platform::set_owner(path, uid, gid);
    if mode != 0 {
        platform::set_mode(path, mode);
    }
    let secs = mtime_sec.max(0) as u64;
    if let Some(t) = UNIX_EPOCH.checked_add(std::time::Duration::new(secs, mtime_nsec)) {
        let times = FileTimes::new().set_modified(t);
        if let Ok(f) = File::open(path) {
            let _ = f.set_times(times);
        }
    }
}

// ---------------------------------------------------------------------------
// 索引式目录归档（非 solid）：尾部中央目录，支持按条目随机访问。
//
// 与上文的顺序流式容器（solid）不同，这里每个文件条目独立压缩，容器尾部追加
// 中央目录（index）与结束记录（EOCD），从而无需解压整个归档即可列目录或抽取
// 单个条目（类似 ZIP）。
// ---------------------------------------------------------------------------

/// 索引归档容器魔数："RZPA"。
pub const INDEX_MAGIC: [u8; 4] = *b"RZPA";
/// 索引归档容器版本。
pub const INDEX_VERSION: u8 = 1;
/// 容器头大小：魔数(4) + 版本(1) + 标志(1) + 保留(2)。
pub const INDEX_HEADER_SIZE: usize = 8;
/// 条目头大小：type(1) + flags(1) + method(1) + name_len(2) + mode(4) + uid(4) +
/// gid(4) + mtime_sec(8) + mtime_nsec(4) + size(8) + comp_size(8) + xattr_len(4)。
pub const INDEX_ENTRY_HEADER_SIZE: usize = 49;
/// 中央目录记录大小：条目头(49) + offset(8)。
pub const INDEX_CD_RECORD_SIZE: usize = 57;
/// 结束记录（EOCD）大小：count(8) + cd_offset(8) + cd_size(8) + 魔数(4)。
pub const INDEX_EOCD_SIZE: usize = 28;
/// EOCD 尾部魔数："RZPD"。
pub const INDEX_EOCD_MAGIC: [u8; 4] = *b"RZPD";

/// 压缩方法：数据原样存储。
const METHOD_STORED: u8 = 0;
/// 压缩方法：数据为一段独立 RZP 流。
const METHOD_RZP: u8 = 1;

/// 索引归档中的一个条目（含中央目录里的随机访问偏移）。
pub struct IndexEntry {
    pub ty: u8,
    pub flags: u8,
    pub method: u8,
    pub name: Vec<u8>,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub mtime_sec: i64,
    pub mtime_nsec: u32,
    pub size: u64,
    pub comp_size: u64,
    pub xattr_len: u32,
    /// 条目头在容器内的字节偏移（供随机访问）。
    pub offset: u64,
}

impl IndexEntry {
    /// 条目的相对路径（按原始字节解释为 OS 路径）。
    pub fn path(&self) -> &Path {
        platform::path_from_bytes(&self.name)
    }

    /// 类型的人类可读名。
    pub fn type_name(&self) -> &'static str {
        match self.ty {
            TYPE_FILE => "file",
            TYPE_DIR => "dir",
            TYPE_SYMLINK => "symlink",
            TYPE_HARDLINK => "hardlink",
            _ => "other",
        }
    }
}

/// 把 `root` 目录树打包为索引式归档（非 solid），写入 `out`。
///
/// 每个文件条目独立 RZP 压缩（压缩后不更小时则原样存储），容器尾部追加中央
/// 目录与 EOCD。`filter` 语义同 [`write_dir_filtered`]。条目 RZP 流使用 CRC-32
/// 校验；如需更强校验见 [`write_indexed_dir_with_strong_checksum`]。
pub fn write_indexed_dir<W: Write>(
    root: &Path,
    out: &mut W,
    filter: &dyn Fn(&Path, bool) -> bool,
    level: Level,
    dict: &[u8],
    threads: usize,
) -> crate::Result<()> {
    write_indexed_dir_inner(root, out, filter, level, dict, threads, false)
}

/// 同 [`write_indexed_dir`]，但每条 RZP 流使用 BLAKE2b-256 强校验。
pub fn write_indexed_dir_with_strong_checksum<W: Write>(
    root: &Path,
    out: &mut W,
    filter: &dyn Fn(&Path, bool) -> bool,
    level: Level,
    dict: &[u8],
    threads: usize,
) -> crate::Result<()> {
    write_indexed_dir_inner(root, out, filter, level, dict, threads, true)
}

fn write_indexed_dir_inner<W: Write>(
    root: &Path,
    out: &mut W,
    filter: &dyn Fn(&Path, bool) -> bool,
    level: Level,
    dict: &[u8],
    threads: usize,
    strong: bool,
) -> crate::Result<()> {
    let mut hdr = [0u8; INDEX_HEADER_SIZE];
    hdr[0..4].copy_from_slice(&INDEX_MAGIC);
    hdr[4] = INDEX_VERSION;
    out.write_all(&hdr)?;

    let mut offset = INDEX_HEADER_SIZE as u64;
    let mut index: Vec<IndexEntry> = Vec::new();
    let mut seen: HashMap<(u64, u64), Vec<u8>> = HashMap::new();
    write_indexed_tree(
        root,
        root,
        out,
        filter,
        level,
        dict,
        threads,
        strong,
        &mut offset,
        &mut index,
        &mut seen,
    )?;

    // 中央目录。
    let cd_offset = offset;
    for e in &index {
        write_cd_record(out, e)?;
        out.write_all(&e.name)?;
        offset += (INDEX_CD_RECORD_SIZE + e.name.len()) as u64;
    }
    let cd_size = offset - cd_offset;

    // EOCD。
    let mut eocd = [0u8; INDEX_EOCD_SIZE];
    eocd[0..8].copy_from_slice(&(index.len() as u64).to_le_bytes());
    eocd[8..16].copy_from_slice(&cd_offset.to_le_bytes());
    eocd[16..24].copy_from_slice(&cd_size.to_le_bytes());
    eocd[24..28].copy_from_slice(&INDEX_EOCD_MAGIC);
    out.write_all(&eocd)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn write_indexed_tree<W: Write>(
    root: &Path,
    dir: &Path,
    out: &mut W,
    filter: &dyn Fn(&Path, bool) -> bool,
    level: Level,
    dict: &[u8],
    threads: usize,
    strong: bool,
    offset: &mut u64,
    index: &mut Vec<IndexEntry>,
    seen: &mut HashMap<(u64, u64), Vec<u8>>,
) -> crate::Result<()> {
    let mut paths: Vec<PathBuf> = fs::read_dir(dir)?
        .map(|e| e.map(|e| e.path()))
        .collect::<io::Result<_>>()?;
    paths.sort();

    for path in paths {
        let meta = fs::symlink_metadata(&path)?;
        let rel = path.strip_prefix(root).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "failed to strip root prefix")
        })?;
        let ft = meta.file_type();
        if !filter(rel, ft.is_dir()) {
            continue;
        }
        let name = platform::path_bytes(rel).to_vec();
        let mode = platform::meta_mode(&meta);
        let uid = platform::meta_uid(&meta);
        let gid = platform::meta_gid(&meta);
        let mtime_sec = platform::meta_mtime_sec(&meta);
        let mtime_nsec = platform::meta_mtime_nsec(&meta);

        if ft.is_dir() {
            let xblob = serialize_xattrs(&read_xattrs(&path));
            write_entry_header(
                out,
                TYPE_DIR,
                0,
                METHOD_STORED,
                &name,
                mode,
                uid,
                gid,
                mtime_sec,
                mtime_nsec,
                0,
                0,
                xblob.len() as u32,
            )?;
            out.write_all(&xblob)?;
            let entry_offset = *offset;
            *offset += (INDEX_ENTRY_HEADER_SIZE + name.len() + xblob.len()) as u64;
            index.push(IndexEntry {
                ty: TYPE_DIR,
                flags: 0,
                method: METHOD_STORED,
                name,
                mode,
                uid,
                gid,
                mtime_sec,
                mtime_nsec,
                size: 0,
                comp_size: 0,
                xattr_len: xblob.len() as u32,
                offset: entry_offset,
            });
            write_indexed_tree(
                root, &path, out, filter, level, dict, threads, strong, offset, index, seen,
            )?;
        } else if ft.is_file() {
            // 硬链接：nlink > 1 且 inode 已收录过 → 记为指向首个出现路径的 hardlink。
            let inode_key = platform::meta_inode_key(&meta);
            if platform::meta_nlink(&meta) > 1 {
                if let Some(target) = seen.get(&inode_key) {
                    let blob = target.clone();
                    write_entry_header(
                        out,
                        TYPE_HARDLINK,
                        0,
                        METHOD_STORED,
                        &name,
                        mode,
                        uid,
                        gid,
                        mtime_sec,
                        mtime_nsec,
                        0,
                        blob.len() as u64,
                        0,
                    )?;
                    out.write_all(&blob)?;
                    let entry_offset = *offset;
                    *offset += (INDEX_ENTRY_HEADER_SIZE + name.len() + blob.len()) as u64;
                    index.push(IndexEntry {
                        ty: TYPE_HARDLINK,
                        flags: 0,
                        method: METHOD_STORED,
                        name,
                        mode,
                        uid,
                        gid,
                        mtime_sec,
                        mtime_nsec,
                        size: 0,
                        comp_size: blob.len() as u64,
                        xattr_len: 0,
                        offset: entry_offset,
                    });
                    continue;
                }
                seen.insert(inode_key, name.clone());
            }

            let xblob = serialize_xattrs(&read_xattrs(&path));
            let size = meta.len();
            let (flags, method, blob) = if platform::is_sparse(&meta) {
                let payload = serialize_sparse(&read_sparse_extents(&path, size)?);
                let comp = compress_bytes(&payload, level, dict, threads, strong);
                if comp.len() < payload.len() {
                    (FLAG_SPARSE, METHOD_RZP, comp)
                } else {
                    (FLAG_SPARSE, METHOD_STORED, payload)
                }
            } else {
                let raw = fs::read(&path)?;
                let comp = compress_bytes(&raw, level, dict, threads, strong);
                if comp.len() < raw.len() {
                    (0, METHOD_RZP, comp)
                } else {
                    (0, METHOD_STORED, raw)
                }
            };
            let comp_size = blob.len() as u64;
            write_entry_header(
                out,
                TYPE_FILE,
                flags,
                method,
                &name,
                mode,
                uid,
                gid,
                mtime_sec,
                mtime_nsec,
                size,
                comp_size,
                xblob.len() as u32,
            )?;
            out.write_all(&xblob)?;
            out.write_all(&blob)?;
            let entry_offset = *offset;
            *offset += (INDEX_ENTRY_HEADER_SIZE + name.len() + xblob.len() + blob.len()) as u64;
            index.push(IndexEntry {
                ty: TYPE_FILE,
                flags,
                method,
                name,
                mode,
                uid,
                gid,
                mtime_sec,
                mtime_nsec,
                size,
                comp_size,
                xattr_len: xblob.len() as u32,
                offset: entry_offset,
            });
        } else if ft.is_symlink() {
            let target = fs::read_link(&path)?;
            let blob = platform::path_bytes(&target).to_vec();
            let size = blob.len() as u64;
            write_entry_header(
                out,
                TYPE_SYMLINK,
                0,
                METHOD_STORED,
                &name,
                mode,
                uid,
                gid,
                mtime_sec,
                mtime_nsec,
                size,
                size,
                0,
            )?;
            out.write_all(&blob)?;
            let entry_offset = *offset;
            *offset += (INDEX_ENTRY_HEADER_SIZE + name.len() + blob.len()) as u64;
            index.push(IndexEntry {
                ty: TYPE_SYMLINK,
                flags: 0,
                method: METHOD_STORED,
                name,
                mode,
                uid,
                gid,
                mtime_sec,
                mtime_nsec,
                size,
                comp_size: size,
                xattr_len: 0,
                offset: entry_offset,
            });
        }
        // 其余特殊文件（fifo/socket/设备）跳过。
    }
    Ok(())
}

/// 写入 49 字节条目头 + 名字。
#[allow(clippy::too_many_arguments)]
fn write_entry_header<W: Write>(
    out: &mut W,
    ty: u8,
    flags: u8,
    method: u8,
    name: &[u8],
    mode: u32,
    uid: u32,
    gid: u32,
    mtime_sec: i64,
    mtime_nsec: u32,
    size: u64,
    comp_size: u64,
    xattr_len: u32,
) -> crate::Result<()> {
    let name_len = u16::try_from(name.len()).map_err(|_| Error::Io("file name too long".into()))?;
    let mut h = [0u8; INDEX_ENTRY_HEADER_SIZE];
    h[0] = ty;
    h[1] = flags;
    h[2] = method;
    h[3..5].copy_from_slice(&name_len.to_le_bytes());
    h[5..9].copy_from_slice(&mode.to_le_bytes());
    h[9..13].copy_from_slice(&uid.to_le_bytes());
    h[13..17].copy_from_slice(&gid.to_le_bytes());
    h[17..25].copy_from_slice(&mtime_sec.to_le_bytes());
    h[25..29].copy_from_slice(&mtime_nsec.to_le_bytes());
    h[29..37].copy_from_slice(&size.to_le_bytes());
    h[37..45].copy_from_slice(&comp_size.to_le_bytes());
    h[45..49].copy_from_slice(&xattr_len.to_le_bytes());
    out.write_all(&h)?;
    out.write_all(name)?;
    Ok(())
}

/// 写入一条中央目录记录（57 字节）+ 名字。
fn write_cd_record<W: Write>(out: &mut W, e: &IndexEntry) -> crate::Result<()> {
    let name_len =
        u16::try_from(e.name.len()).map_err(|_| Error::Io("file name too long".into()))?;
    let mut h = [0u8; INDEX_CD_RECORD_SIZE];
    h[0] = e.ty;
    h[1] = e.flags;
    h[2] = e.method;
    h[3..5].copy_from_slice(&name_len.to_le_bytes());
    h[5..9].copy_from_slice(&e.mode.to_le_bytes());
    h[9..13].copy_from_slice(&e.uid.to_le_bytes());
    h[13..17].copy_from_slice(&e.gid.to_le_bytes());
    h[17..25].copy_from_slice(&e.mtime_sec.to_le_bytes());
    h[25..29].copy_from_slice(&e.mtime_nsec.to_le_bytes());
    h[29..37].copy_from_slice(&e.size.to_le_bytes());
    h[37..45].copy_from_slice(&e.comp_size.to_le_bytes());
    h[45..49].copy_from_slice(&e.xattr_len.to_le_bytes());
    h[49..57].copy_from_slice(&e.offset.to_le_bytes());
    out.write_all(&h)?;
    Ok(())
}

/// 压缩一段字节为独立 RZP 流（写内存，不可能失败）。
fn compress_bytes(data: &[u8], level: Level, dict: &[u8], threads: usize, strong: bool) -> Vec<u8> {
    use std::io::Write;
    let mut enc = crate::Encoder::with_dictionary(Vec::new(), level, dict).with_threads(threads);
    if strong {
        enc = enc.with_strong_checksum();
    }
    enc.write_all(data).expect("writing to Vec cannot fail");
    enc.finish().expect("finishing to Vec cannot fail")
}

/// 读取路径上的全部 xattr（best-effort：读不到则返回空）。
fn read_xattrs(path: &Path) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut out = Vec::new();
    let Ok(names) = crate::xattr::list_xattrs(path) else {
        return out;
    };
    for name in names {
        if let Ok(value) = crate::xattr::get_xattr(path, &name) {
            out.push((name, value));
        }
    }
    out
}

/// 把 xattr 列表序列化为「name_len(2) + name + value_len(4) + value」的字节流。
fn serialize_xattrs(xattrs: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (name, value) in xattrs {
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(name);
        out.extend_from_slice(&(value.len() as u32).to_le_bytes());
        out.extend_from_slice(value);
    }
    out
}

/// 反序列化 xattr 字节流（带边界校验）。
fn deserialize_xattrs(mut blob: &[u8]) -> io::Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let mut out = Vec::new();
    while !blob.is_empty() {
        if blob.len() < 2 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated xattr name length",
            ));
        }
        let nl = u16::from_le_bytes([blob[0], blob[1]]) as usize;
        blob = &blob[2..];
        if blob.len() < nl + 4 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated xattr record",
            ));
        }
        let name = blob[..nl].to_vec();
        let vl = u32::from_le_bytes(blob[nl..nl + 4].try_into().unwrap()) as usize;
        blob = &blob[nl + 4..];
        if blob.len() < vl {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated xattr value",
            ));
        }
        let value = blob[..vl].to_vec();
        blob = &blob[vl..];
        out.push((name, value));
    }
    Ok(out)
}

/// 稀疏块扫描粒度（字节）。
const SPARSE_BLOCK: usize = 4096;

/// 读取稀疏文件，产出 `(offset, data)` 扩展区列表（按 4 KiB 全零块识别空洞）。
fn read_sparse_extents(path: &Path, logical_len: u64) -> io::Result<Vec<(u64, Vec<u8>)>> {
    let mut f = File::open(path)?;
    let mut extents: Vec<(u64, Vec<u8>)> = Vec::new();
    let mut buf = vec![0u8; SPARSE_BLOCK];
    let mut pos: u64 = 0;
    while pos < logical_len {
        let want = (logical_len - pos).min(SPARSE_BLOCK as u64) as usize;
        f.read_exact(&mut buf[..want])?;
        let all_zero = buf[..want].iter().all(|&b| b == 0);
        if !all_zero {
            match extents.last_mut() {
                Some((off, data)) if *off + data.len() as u64 == pos => {
                    data.extend_from_slice(&buf[..want]);
                }
                _ => extents.push((pos, buf[..want].to_vec())),
            }
        }
        pos += want as u64;
    }
    Ok(extents)
}

/// 序列化扩展区列表：count(4) + [offset(8) + length(8) + data]*。
fn serialize_sparse(extents: &[(u64, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(extents.len() as u32).to_le_bytes());
    for (off, data) in extents {
        out.extend_from_slice(&off.to_le_bytes());
        out.extend_from_slice(&(data.len() as u64).to_le_bytes());
        out.extend_from_slice(data);
    }
    out
}

/// 把稀疏扩展区列表还原为稀疏文件（`set_len` 预留空洞，再逐扩展区 seek+write）。
fn write_sparse_file(f: &mut File, logical_len: u64, payload: &[u8]) -> io::Result<()> {
    let truncated = || io::Error::new(io::ErrorKind::InvalidData, "truncated sparse payload");
    f.set_len(logical_len)?;
    let mut cur = payload;
    if cur.len() < 4 {
        return Err(truncated());
    }
    let count = u32::from_le_bytes(cur[0..4].try_into().unwrap()) as usize;
    cur = &cur[4..];
    for _ in 0..count {
        if cur.len() < 16 {
            return Err(truncated());
        }
        let offset = u64::from_le_bytes(cur[0..8].try_into().unwrap());
        let length = u64::from_le_bytes(cur[8..16].try_into().unwrap());
        cur = &cur[16..];
        let len = length as usize;
        if cur.len() < len {
            return Err(truncated());
        }
        let data = &cur[..len];
        cur = &cur[len..];
        if offset
            .checked_add(length)
            .is_none_or(|end| end > logical_len)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "sparse extent out of range",
            ));
        }
        f.seek(SeekFrom::Start(offset))?;
        f.write_all(data)?;
    }
    Ok(())
}

/// 读取并反序列化条目的 xattr 块。
fn read_entry_xattrs<R: Read + Seek>(
    r: &mut R,
    e: &IndexEntry,
) -> crate::Result<Vec<(Vec<u8>, Vec<u8>)>> {
    if e.xattr_len == 0 {
        return Ok(Vec::new());
    }
    let xattr_offset = e.offset + (INDEX_ENTRY_HEADER_SIZE + e.name.len()) as u64;
    r.seek(SeekFrom::Start(xattr_offset))?;
    let mut blob = vec![0u8; e.xattr_len as usize];
    r.read_exact(&mut blob)?;
    Ok(deserialize_xattrs(&blob)?)
}

/// 把条目的 xattr 恢复到 `target`（best-effort，失败不中断）。
fn restore_xattrs<R: Read + Seek>(r: &mut R, e: &IndexEntry, target: &Path) -> crate::Result<()> {
    for (name, value) in read_entry_xattrs(r, e)? {
        let _ = crate::xattr::set_xattr(target, &name, &value);
    }
    Ok(())
}

/// 删除解压目标上已存在的同名条目（文件/目录/符号链接均可）。
fn remove_existing(target: &Path) -> io::Result<()> {
    match fs::symlink_metadata(target) {
        Ok(m) if m.is_dir() => fs::remove_dir_all(target)?,
        Ok(_) => fs::remove_file(target)?,
        Err(_) => {}
    }
    Ok(())
}

/// 读取容器头与 EOCD，返回中央目录里的全部条目（元信息，不读条目数据）。
pub fn read_index<R: Read + Seek>(r: &mut R) -> crate::Result<Vec<IndexEntry>> {
    let mut hdr = [0u8; INDEX_HEADER_SIZE];
    r.read_exact(&mut hdr)?;
    if hdr[0..4] != INDEX_MAGIC {
        return Err(Error::Corrupt("not an indexed RZP archive".into()));
    }
    if hdr[4] != INDEX_VERSION {
        return Err(Error::Corrupt(format!(
            "unsupported archive version {}",
            hdr[4]
        )));
    }

    let total = r.seek(SeekFrom::End(0))?;
    let min = (INDEX_HEADER_SIZE + INDEX_EOCD_SIZE) as u64;
    if total < min {
        return Err(Error::Corrupt("archive too small".into()));
    }
    r.seek(SeekFrom::Start(total - INDEX_EOCD_SIZE as u64))?;
    let mut eocd = [0u8; INDEX_EOCD_SIZE];
    r.read_exact(&mut eocd)?;
    if eocd[24..28] != INDEX_EOCD_MAGIC {
        return Err(Error::Corrupt("bad archive end marker".into()));
    }
    let count = u64::from_le_bytes(eocd[0..8].try_into().unwrap());
    let cd_offset = u64::from_le_bytes(eocd[8..16].try_into().unwrap());
    let cd_size = u64::from_le_bytes(eocd[16..24].try_into().unwrap());
    if cd_offset.checked_add(cd_size).is_none_or(|end| end > total) {
        return Err(Error::Corrupt("central directory out of range".into()));
    }

    r.seek(SeekFrom::Start(cd_offset))?;
    let mut entries = Vec::with_capacity(count as usize);
    let mut read = 0u64;
    for _ in 0..count {
        let mut h = [0u8; INDEX_CD_RECORD_SIZE];
        r.read_exact(&mut h)?;
        read += INDEX_CD_RECORD_SIZE as u64;
        let ty = h[0];
        let flags = h[1];
        let method = h[2];
        let name_len = u16::from_le_bytes([h[3], h[4]]) as usize;
        let mode = u32::from_le_bytes([h[5], h[6], h[7], h[8]]);
        let uid = u32::from_le_bytes([h[9], h[10], h[11], h[12]]);
        let gid = u32::from_le_bytes([h[13], h[14], h[15], h[16]]);
        let mtime_sec = i64::from_le_bytes(h[17..25].try_into().unwrap());
        let mtime_nsec = u32::from_le_bytes(h[25..29].try_into().unwrap());
        let size = u64::from_le_bytes(h[29..37].try_into().unwrap());
        let comp_size = u64::from_le_bytes(h[37..45].try_into().unwrap());
        let xattr_len = u32::from_le_bytes(h[45..49].try_into().unwrap());
        let offset = u64::from_le_bytes(h[49..57].try_into().unwrap());
        let mut name = vec![0u8; name_len];
        r.read_exact(&mut name)?;
        read += name_len as u64;
        if read > cd_size {
            return Err(Error::Corrupt("central directory size mismatch".into()));
        }
        entries.push(IndexEntry {
            ty,
            flags,
            method,
            name,
            mode,
            uid,
            gid,
            mtime_sec,
            mtime_nsec,
            size,
            comp_size,
            xattr_len,
            offset,
        });
    }
    if read != cd_size {
        return Err(Error::Corrupt("central directory size mismatch".into()));
    }
    Ok(entries)
}

/// 随机访问读取某条目的数据（存储条目返回原样，压缩条目解压后返回）。
fn read_entry_payload<R: Read + Seek>(
    r: &mut R,
    e: &IndexEntry,
    dict: &[u8],
    threads: usize,
) -> crate::Result<Vec<u8>> {
    let data_offset =
        e.offset + (INDEX_ENTRY_HEADER_SIZE + e.name.len() + e.xattr_len as usize) as u64;
    r.seek(SeekFrom::Start(data_offset))?;
    let mut blob = vec![0u8; e.comp_size as usize];
    r.read_exact(&mut blob)?;
    match e.method {
        METHOD_STORED => Ok(blob),
        METHOD_RZP => crate::decompress_with_dictionary_and_threads(&blob, dict, threads),
        other => Err(Error::Corrupt(format!(
            "unknown compression method {other}"
        ))),
    }
}

/// 列出索引归档内容（只读中央目录，不解压数据）。
pub fn list_indexed<R: Read + Seek>(
    r: &mut R,
    mut f: impl FnMut(&IndexEntry) -> crate::Result<()>,
) -> crate::Result<()> {
    let entries = read_index(r)?;
    for e in &entries {
        f(e)?;
    }
    Ok(())
}

/// 校验索引归档完整性：逐条目读取并（必要时）解压以触发 CRC 校验。
pub fn verify_indexed<R: Read + Seek>(r: &mut R, dict: &[u8], threads: usize) -> crate::Result<()> {
    let entries = read_index(r)?;
    for e in &entries {
        if e.ty == TYPE_FILE {
            let _ = read_entry_payload(r, e, dict, threads)?;
        }
    }
    Ok(())
}

/// 解出整个索引归档到 `dest`（`dest` 自动创建）。
pub fn extract_indexed<R: Read + Seek>(
    r: &mut R,
    dest: &Path,
    dict: &[u8],
    threads: usize,
) -> crate::Result<()> {
    fs::create_dir_all(dest)?;
    let entries = read_index(r)?;
    for e in &entries {
        extract_indexed_entry(r, e, dest, dict, threads)?;
    }
    Ok(())
}

/// 随机解出单个条目到 `dest`。
pub fn extract_indexed_entry<R: Read + Seek>(
    r: &mut R,
    e: &IndexEntry,
    dest: &Path,
    dict: &[u8],
    threads: usize,
) -> crate::Result<()> {
    let rel = sanitize_name(&e.name)?;
    let target = dest.join(&rel);
    match e.ty {
        TYPE_DIR => {
            fs::create_dir_all(&target)?;
            restore_xattrs(r, e, &target)?;
            set_meta(
                &target,
                e.mode,
                Some(e.uid),
                Some(e.gid),
                e.mtime_sec,
                e.mtime_nsec,
            );
        }
        TYPE_FILE => {
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)?;
            }
            let mut f = File::create(&target)?;
            let data = read_entry_payload(r, e, dict, threads)?;
            if e.flags & FLAG_SPARSE != 0 {
                write_sparse_file(&mut f, e.size, &data)?;
            } else {
                f.write_all(&data)?;
            }
            f.flush()?;
            drop(f);
            restore_xattrs(r, e, &target)?;
            set_meta(
                &target,
                e.mode,
                Some(e.uid),
                Some(e.gid),
                e.mtime_sec,
                e.mtime_nsec,
            );
        }
        TYPE_SYMLINK => {
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)?;
            }
            let link = read_entry_payload(r, e, dict, threads)?;
            remove_existing(&target)?;
            platform::create_symlink(&link, &target)?;
            platform::lchown(&target, Some(e.uid), Some(e.gid));
        }
        TYPE_HARDLINK => {
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)?;
            }
            let link = read_entry_payload(r, e, dict, threads)?;
            let link_target = dest.join(sanitize_name(&link)?);
            remove_existing(&target)?;
            match fs::hard_link(&link_target, &target) {
                Ok(()) => {}
                Err(_) => {
                    // 单独抽取硬链接时目标可能尚未还原，退化为复制内容。
                    let data = fs::read(&link_target)?;
                    fs::write(&target, data)?;
                }
            }
        }
        other => {
            return Err(Error::Io(format!("unknown entry type {other}")));
        }
    }
    Ok(())
}

/// 按相对路径随机解出单个条目（不存在时报错）。
pub fn extract_indexed_path<R: Read + Seek>(
    r: &mut R,
    dest: &Path,
    name: &Path,
    dict: &[u8],
    threads: usize,
) -> crate::Result<()> {
    let needle = platform::path_bytes(name);
    let entries = read_index(r)?;
    let e = entries
        .iter()
        .find(|e| e.name == needle)
        .ok_or_else(|| Error::Io(format!("归档中找不到条目: {}", name.display())))?;
    extract_indexed_entry(r, e, dest, dict, threads)
}

#[cfg(all(test, unix))]
mod indexed_tests {
    use super::*;
    use std::io::Cursor;
    use std::os::unix::fs::MetadataExt;

    fn tmpdir(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let p = std::env::temp_dir().join(format!("rzp-test-{tag}-{}-{nanos}", std::process::id()));
        fs::create_dir_all(&p).unwrap();
        p
    }

    fn write_file(path: &Path, data: &[u8]) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, data).unwrap();
    }

    #[test]
    fn indexed_roundtrip_and_random_access() {
        let src = tmpdir("src");
        write_file(
            &src.join("a.txt"),
            b"hello hello hello hello".repeat(20).as_slice(),
        );
        write_file(
            &src.join("sub").join("b.bin"),
            &(0..50_000u32).map(|i| (i % 251) as u8).collect::<Vec<_>>(),
        );
        write_file(&src.join("empty"), b"");
        // 符号链接。
        std::os::unix::fs::symlink("a.txt", src.join("link")).unwrap();

        let mut packed = Vec::new();
        write_indexed_dir(&src, &mut packed, &|_, _| true, Level::L6, &[], 2).unwrap();

        // 头魔数。
        assert_eq!(&packed[0..4], b"RZPA");

        // 读中央目录，列出 5 个条目（含目录 `sub`）。
        let mut cur = Cursor::new(packed.clone());
        let entries = read_index(&mut cur).unwrap();
        let names: Vec<&[u8]> = entries.iter().map(|e| e.name.as_slice()).collect();
        assert!(names.contains(&b"a.txt".as_slice()));
        assert!(names.contains(&b"sub".as_slice()));
        assert!(names.contains(&b"sub/b.bin".as_slice()));
        assert!(names.contains(&b"empty".as_slice()));
        assert!(names.contains(&b"link".as_slice()));
        assert_eq!(entries.len(), 5);

        // 整体解出。
        let dst = tmpdir("dst");
        extract_indexed(&mut Cursor::new(packed.clone()), &dst, &[], 2).unwrap();
        assert_eq!(
            fs::read(dst.join("a.txt")).unwrap(),
            b"hello hello hello hello".repeat(20)
        );
        assert_eq!(
            fs::read(dst.join("sub").join("b.bin")).unwrap(),
            (0..50_000u32).map(|i| (i % 251) as u8).collect::<Vec<_>>()
        );
        assert_eq!(fs::read(dst.join("empty")).unwrap(), b"");

        // 随机解出单个条目。
        let one = tmpdir("one");
        extract_indexed_path(
            &mut Cursor::new(packed),
            &one,
            Path::new("sub/b.bin"),
            &[],
            2,
        )
        .unwrap();
        assert_eq!(
            fs::read(one.join("sub").join("b.bin")).unwrap(),
            (0..50_000u32).map(|i| (i % 251) as u8).collect::<Vec<_>>()
        );
    }

    #[test]
    fn indexed_preserves_metadata() {
        use std::io::{Seek, SeekFrom, Write};

        let src = tmpdir("meta-src");
        write_file(
            &src.join("data.txt"),
            b"metadata payload ".repeat(100).as_slice(),
        );

        // 硬链接。
        fs::hard_link(src.join("data.txt"), src.join("data2.txt")).unwrap();

        // 稀疏文件：开头与尾部各写一段，中间留洞。
        let sparse_path = src.join("sparse.bin");
        {
            let mut f = File::create(&sparse_path).unwrap();
            f.write_all(b"HEAD").unwrap();
            f.seek(SeekFrom::Start(1 << 20)).unwrap();
            f.write_all(b"TAIL").unwrap();
            f.set_len((1 << 20) + 8).unwrap();
        }

        // xattr（best-effort：文件系统可能不支持，仅在不支持时跳过该断言）。
        let xattr_set =
            crate::xattr::set_xattr(&src.join("data.txt"), b"user.rzp", b"hello-xattr").is_ok();

        let mut packed = Vec::new();
        write_indexed_dir(&src, &mut packed, &|_, _| true, Level::L6, &[], 2).unwrap();

        let dst = tmpdir("meta-dst");
        extract_indexed(&mut Cursor::new(packed), &dst, &[], 2).unwrap();

        // 内容。
        assert_eq!(
            fs::read(dst.join("data.txt")).unwrap(),
            b"metadata payload ".repeat(100)
        );

        // 硬链接：两路径指向同一 inode。
        let ino_a = fs::metadata(dst.join("data.txt")).unwrap().ino();
        let ino_b = fs::metadata(dst.join("data2.txt")).unwrap().ino();
        assert_eq!(ino_a, ino_b);

        // 稀疏：内容一致且仍为稀疏。
        let sparse = fs::read(dst.join("sparse.bin")).unwrap();
        assert_eq!(sparse.len(), (1 << 20) + 8);
        assert_eq!(&sparse[0..4], b"HEAD");
        assert_eq!(&sparse[1 << 20..(1 << 20) + 4], b"TAIL");
        let meta = fs::metadata(dst.join("sparse.bin")).unwrap();
        assert!(
            meta.blocks().saturating_mul(512) < meta.len(),
            "sparse layout not preserved"
        );

        // xattr。
        if xattr_set {
            assert_eq!(
                crate::xattr::get_xattr(&dst.join("data.txt"), b"user.rzp").unwrap(),
                b"hello-xattr"
            );
        }

        // uid/gid（同一用户环境下应保持原值）。
        let s = fs::metadata(src.join("data.txt")).unwrap();
        let d = fs::metadata(dst.join("data.txt")).unwrap();
        assert_eq!(d.uid(), s.uid());
        assert_eq!(d.gid(), s.gid());
    }
}
