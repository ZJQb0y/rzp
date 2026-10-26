//! Windows 构建脚本：为 `rzp.exe` 嵌入版本信息资源（文件属性 → 详细信息）
//! 与图标资源（`assets/rzp.ico`，可选）。
//!
//! 仅在目标为 Windows 时生效；优先使用 MSVC 的 `rc.exe`（原生 Windows），
//! 否则回退到 mingw-w64 的 `windres`（Linux 交叉编译到 `*-pc-windows-gnu`）。
//! 两者都找不到时优雅跳过（仅少一个「详细信息」页，不影响功能）。
//!
//! 非 Windows 平台不做任何事。

use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }

    let version = std::env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "0.0.0".into());
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let icon = manifest.join("assets").join("rzp.ico");

    // 若存在图标资源（assets/rzp.ico），则一并嵌入 rzp.exe；缺失时优雅跳过。
    let icon_rc = if icon.is_file() {
        // .rc 字符串里反斜杠是转义符，需双写为 `\\`。
        Some(icon.display().to_string().replace('\\', "\\\\"))
    } else {
        None
    };

    let out = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));
    let rc_file = out.join("version.rc");
    std::fs::write(&rc_file, generate_rc(&version, icon_rc.as_deref()))
        .expect("写入 version.rc 失败");

    // 1) MSVC：rc.exe 编译为 .res，直接交给 link.exe。
    if let Some(rc) = find_rc_exe(arch_dir()) {
        let res_file = out.join("version.res");
        let status = Command::new(&rc)
            .arg("/nologo")
            .arg("/fo")
            .arg(&res_file)
            .arg(&rc_file)
            .status()
            .expect("启动 rc.exe 失败");
        if !status.success() {
            panic!("rc.exe 编译版本资源失败");
        }
        println!("cargo:rustc-link-arg-bin=rzp={}", res_file.display());
        emit_rerun();
        return;
    }

    // 2) GNU/mingw：windres 编译为 COFF 目标文件，交给 mingw 链接器。
    if let Some(windres) = find_windres() {
        let obj_file = out.join("version.o");
        let status = Command::new(&windres)
            .arg(&rc_file)
            .arg("-O")
            .arg("coff")
            .arg("-o")
            .arg(&obj_file)
            .status()
            .expect("启动 windres 失败");
        if !status.success() {
            panic!("windres 编译版本资源失败");
        }
        println!("cargo:rustc-link-arg-bin=rzp={}", obj_file.display());
        emit_rerun();
        return;
    }

    println!(
        "cargo:warning=未找到 rc.exe / windres，跳过嵌入版本资源（文件属性将缺少「详细信息」）"
    );
    emit_rerun();
}

/// 生成独立的 `.rc` 内容（用数值常量替代 `#include <windows.h>`，
/// 从而无需配置 INCLUDE 环境变量即可编译）。
fn generate_rc(version: &str, icon: Option<&str>) -> String {
    let mut parts: Vec<u32> = version.split('.').map(|p| p.parse().unwrap_or(0)).collect();
    while parts.len() < 4 {
        parts.push(0);
    }
    let (a, b, c, d) = (parts[0], parts[1], parts[2], parts[3]);

    let icon_line = match icon {
        Some(path) => format!("1 ICON \"{path}\"\n\n"),
        None => String::new(),
    };

    format!(
        "#pragma code_page(65001)\n\
{icon_line}\
1 VERSIONINFO\n\
FILEVERSION {a},{b},{c},{d}\n\
PRODUCTVERSION {a},{b},{c},{d}\n\
FILEFLAGSMASK 0x3fL\n\
FILEFLAGS 0x0L\n\
FILEOS 0x40004L\n\
FILETYPE 0x1L\n\
FILESUBTYPE 0x0L\n\
BEGIN\n\
    BLOCK \"StringFileInfo\"\n\
    BEGIN\n\
        BLOCK \"080404b0\"\n\
        BEGIN\n\
            VALUE \"CompanyName\", \"张俊琦\"\n\
            VALUE \"FileDescription\", \"RZP 压缩工具\"\n\
            VALUE \"FileVersion\", \"{version}\"\n\
            VALUE \"InternalName\", \"rzp\"\n\
            VALUE \"LegalCopyright\", \"Copyright (c) 张俊琦\"\n\
            VALUE \"OriginalFilename\", \"rzp.exe\"\n\
            VALUE \"ProductName\", \"RZP\"\n\
            VALUE \"ProductVersion\", \"{version}\"\n\
        END\n\
    END\n\
    BLOCK \"VarFileInfo\"\n\
    BEGIN\n\
        VALUE \"Translation\", 0x0804, 1200\n\
    END\n\
END\n"
    )
}

fn arch_dir() -> &'static str {
    match std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() {
        Ok("x86_64") => "x64",
        Ok("aarch64") => "arm64",
        Ok("x86") => "x86",
        _ => "x64",
    }
}

fn mingw_windres_name() -> &'static str {
    match std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() {
        Ok("x86_64") => "x86_64-w64-mingw32-windres",
        Ok("aarch64") => "aarch64-w64-mingw32-windres",
        Ok("x86") => "i686-w64-mingw32-windres",
        _ => "x86_64-w64-mingw32-windres",
    }
}

fn find_rc_exe(arch_dir: &str) -> Option<PathBuf> {
    // 1. PATH
    if let Some(path) = std::env::var_os("PATH") {
        for d in std::env::split_paths(&path) {
            let p = d.join("rc.exe");
            if p.is_file() {
                return Some(p);
            }
        }
    }

    // 2. Windows Kits：<ProgramFiles(x86)>\Windows Kits\10\bin\<版本>\<arch>\rc.exe
    for pf in ["ProgramFiles(x86)", "ProgramFiles"] {
        let Some(root) = std::env::var_os(pf) else {
            continue;
        };
        let kits_bin = Path::new(&root).join("Windows Kits").join("10").join("bin");
        if !kits_bin.is_dir() {
            continue;
        }
        let mut versions: Vec<PathBuf> = std::fs::read_dir(&kits_bin)
            .ok()?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.is_dir())
            .collect();
        versions.sort();
        for v in versions.into_iter().rev() {
            let p = v.join(arch_dir).join("rc.exe");
            if p.is_file() {
                return Some(p);
            }
        }
    }

    None
}

fn find_windres() -> Option<PathBuf> {
    let names = [mingw_windres_name(), "windres"];
    if let Some(path) = std::env::var_os("PATH") {
        for d in std::env::split_paths(&path) {
            for name in names {
                let p = d.join(name);
                if p.is_file() {
                    return Some(p);
                }
            }
        }
    }
    None
}

fn emit_rerun() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=assets/rzp.ico");
    println!("cargo:rerun-if-env-changed=CARGO_PKG_VERSION");
}
