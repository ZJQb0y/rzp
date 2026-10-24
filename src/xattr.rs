//! 扩展属性（xattr）辅助。
//!
//! 在 Unix（Linux/macOS）上通过 raw libc 符号实现，使用 `l*` 系列
//! （`llistxattr`/`lgetxattr`/`lsetxattr`）直接作用于路径而不跟随符号链接。
//! POSIX ACL 在 Linux 上以 `system.posix_acl_*` xattr 形式存储，因此复制全部
//! xattr 即同时保留 ACL。
//!
//! Windows 没有对应的 xattr 语义，故提供空实现 / 返回“不支持”。

use std::io;
use std::path::Path;

#[cfg(unix)]
mod imp {
    use super::*;
    use std::os::raw::{c_char, c_int, c_void};
    use std::os::unix::ffi::OsStrExt;

    extern "C" {
        fn llistxattr(path: *const c_char, list: *mut c_char, size: usize) -> isize;
        fn lgetxattr(
            path: *const c_char,
            name: *const c_char,
            value: *mut c_void,
            size: usize,
        ) -> isize;
        fn lsetxattr(
            path: *const c_char,
            name: *const c_char,
            value: *const c_void,
            size: usize,
            flags: c_int,
        ) -> c_int;
    }

    fn path_cstring(path: &Path) -> io::Result<std::ffi::CString> {
        std::ffi::CString::new(path.as_os_str().as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL byte"))
    }

    fn name_cstring(name: &[u8]) -> io::Result<std::ffi::CString> {
        std::ffi::CString::new(name)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "xattr name contains NUL byte"))
    }

    /// 列出路径上的全部 xattr 名字（不含 NUL 终止符）。
    pub fn list_xattrs(path: &Path) -> io::Result<Vec<Vec<u8>>> {
        let cpath = path_cstring(path)?;
        // 先以 size=0 查询所需缓冲区大小。
        let mut size = unsafe { llistxattr(cpath.as_ptr(), std::ptr::null_mut(), 0) };
        if size < 0 {
            return Err(io::Error::last_os_error());
        }
        loop {
            if size == 0 {
                return Ok(Vec::new());
            }
            let mut buf = vec![0u8; size as usize];
            let n = unsafe { llistxattr(cpath.as_ptr(), buf.as_mut_ptr() as *mut c_char, buf.len()) };
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            if (n as usize) <= buf.len() {
                buf.truncate(n as usize);
                return Ok(buf
                    .split(|&b| b == 0)
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_vec())
                    .collect());
            }
            // 属性列表在两轮调用间增大，按返回所需大小重试。
            size = n;
        }
    }

    /// 读取路径上单个 xattr 的值。
    pub fn get_xattr(path: &Path, name: &[u8]) -> io::Result<Vec<u8>> {
        let cpath = path_cstring(path)?;
        let cname = name_cstring(name)?;
        let mut size = unsafe { lgetxattr(cpath.as_ptr(), cname.as_ptr(), std::ptr::null_mut(), 0) };
        if size < 0 {
            return Err(io::Error::last_os_error());
        }
        loop {
            let mut buf = vec![0u8; size as usize];
            let n = unsafe {
                lgetxattr(
                    cpath.as_ptr(),
                    cname.as_ptr(),
                    buf.as_mut_ptr() as *mut c_void,
                    buf.len(),
                )
            };
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            if (n as usize) <= buf.len() {
                buf.truncate(n as usize);
                return Ok(buf);
            }
            size = n;
        }
    }

    /// 设置（创建或替换）路径上单个 xattr 的值。
    pub fn set_xattr(path: &Path, name: &[u8], value: &[u8]) -> io::Result<()> {
        let cpath = path_cstring(path)?;
        let cname = name_cstring(name)?;
        let r = unsafe {
            lsetxattr(
                cpath.as_ptr(),
                cname.as_ptr(),
                value.as_ptr() as *const c_void,
                value.len(),
                0,
            )
        };
        if r != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

#[cfg(windows)]
mod imp {
    use super::*;

    pub fn list_xattrs(_path: &Path) -> io::Result<Vec<Vec<u8>>> {
        Ok(Vec::new())
    }

    pub fn get_xattr(_path: &Path, _name: &[u8]) -> io::Result<Vec<u8>> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "xattr is not supported on Windows",
        ))
    }

    pub fn set_xattr(_path: &Path, _name: &[u8], _value: &[u8]) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "xattr is not supported on Windows",
        ))
    }
}

/// 列出路径上的全部 xattr 名字（不含 NUL 终止符）。
pub fn list_xattrs(path: &Path) -> io::Result<Vec<Vec<u8>>> {
    imp::list_xattrs(path)
}

/// 读取路径上单个 xattr 的值。
pub fn get_xattr(path: &Path, name: &[u8]) -> io::Result<Vec<u8>> {
    imp::get_xattr(path, name)
}

/// 设置（创建或替换）路径上单个 xattr 的值。
pub fn set_xattr(path: &Path, name: &[u8], value: &[u8]) -> io::Result<()> {
    imp::set_xattr(path, name, value)
}
