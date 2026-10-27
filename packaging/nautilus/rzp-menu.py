#!/usr/bin/env python3
"""RZP —— GNOME 文件管理器（Nautilus）右键菜单扩展。

在 Nautilus 右键菜单中集成 RZP 的压缩 / 解压，后台执行不阻塞文件管理器。

安装（用户级）：
    1. 安装依赖（nautilus-python 与 python3-gi）：
         Debian/Ubuntu:  sudo apt install python3-nautilus python3-gi
         Fedora:         sudo dnf install nautilus-python python3-gobject
    2. 安装扩展：
         mkdir -p ~/.local/share/nautilus-python/extensions
         cp rzp-menu.py ~/.local/share/nautilus-python/extensions/
    3. 确保 `rzp` 在 PATH 中；否则用环境变量 RZP_BIN 指定其绝对路径。
    4. 重启 Nautilus：`nautilus -q`（或注销重登）。

行为说明：
    - 选中文件 / 文件夹   → 「用 RZP 压缩」：生成同名 .rzp，始终保留源文件（-k）。
    - 选中 .rzp           → 「用 RZP 解压」：解压到同目录，始终保留 .rzp（-k）。
    - 文件夹空白处        → 「用 RZP 压缩此文件夹」：打包当前目录。
"""

import os
import shutil
import subprocess
import threading
import urllib.parse

import gi

# Nautilus 扩展 API 版本随 GTK4 迁移推进（新版 4.1，旧发行版可能 4.0 / 3.0），
# 逐级尝试取系统可用者。
for _ver in ("4.1", "4.0", "3.0"):
    try:
        gi.require_version("Nautilus", _ver)
        break
    except ValueError:
        continue

from gi.repository import Nautilus, GObject  # noqa: E402

# 可用环境变量 RZP_BIN 覆盖 rzp 可执行文件路径；否则从 PATH 查找。
RZP_BIN = os.environ.get("RZP_BIN") or shutil.which("rzp")


def _notify(title, body):
    """尽量用 notify-send 弹系统通知；缺失时静默降级。"""
    try:
        subprocess.Popen(
            ["notify-send", "--app-name=RZP", title, body],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        pass


class RzpMenuProvider(GObject.GObject, Nautilus.MenuProvider):
    """在右键菜单中挂载 RZP 压缩 / 解压入口。"""

    def __init__(self):
        super().__init__()

    # ---- 路径解析 ---------------------------------------------------------
    @staticmethod
    def _local_path(file_info):
        """返回 FileInfo 对应的本地路径；非本地（远程挂载等）返回 None。"""
        try:
            loc = file_info.get_location()
            if loc is not None:
                path = loc.get_path()
                if path:
                    return path
        except Exception:
            pass
        try:
            uri = file_info.get_uri()
            if uri and uri.startswith("file://"):
                return urllib.parse.unquote(uri[len("file://"):])
        except Exception:
            pass
        return None

    # ---- 后台执行 ---------------------------------------------------------
    def _run(self, args):
        if not RZP_BIN:
            _notify("RZP", "未找到 rzp 可执行文件：请把 rzp 安装到 PATH，或设置 RZP_BIN。")
            return

        full = [RZP_BIN] + args

        def worker():
            try:
                proc = subprocess.Popen(
                    full,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                    start_new_session=True,
                )
                _, stderr = proc.communicate()
                if proc.returncode == 0:
                    _notify("RZP", "操作完成。")
                else:
                    tail = stderr.decode("utf-8", "replace").strip().splitlines()
                    detail = tail[-1] if tail else "退出码 {}".format(proc.returncode)
                    _notify("RZP 操作失败", detail)
            except Exception as exc:  # noqa: BLE001
                _notify("RZP 操作失败", str(exc))

        threading.Thread(target=worker, daemon=True).start()

    # ---- 菜单回调 ---------------------------------------------------------
    def _compress_cb(self, _menu, paths):
        # -k 保留源文件；-f 覆盖同名 .rzp（覆盖旧归档是常见预期）。
        self._run(["c", "-k", "-f"] + paths)

    def _decompress_cb(self, _menu, paths):
        # -k 保留 .rzp；不加 -f，目标已存在时报错，避免覆盖用户数据。
        self._run(["d", "-k"] + paths)

    # ---- 菜单提供 ---------------------------------------------------------
    def _item(self, name, label, callback, paths):
        item = Nautilus.MenuItem(name=name, label=label)
        item.connect("activate", callback, paths)
        return item

    def get_file_items(self, *args):
        files = args[-1] if args else []
        paths = [self._local_path(f) for f in files]
        paths = [p for p in paths if p]
        if not paths:
            return []

        to_compress = [p for p in paths if not p.endswith(".rzp")]
        to_decompress = [p for p in paths if p.endswith(".rzp")]

        items = []
        if to_compress:
            label = "用 RZP 压缩" if len(to_compress) == 1 else \
                "用 RZP 压缩 {} 个项目".format(len(to_compress))
            items.append(self._item(
                "RzpMenuProvider::Compress", label, self._compress_cb, to_compress,
            ))
        if to_decompress:
            label = "用 RZP 解压" if len(to_decompress) == 1 else \
                "用 RZP 解压 {} 个项目".format(len(to_decompress))
            items.append(self._item(
                "RzpMenuProvider::Decompress", label, self._decompress_cb, to_decompress,
            ))
        return items

    def get_background_items(self, *args):
        folder = args[-1] if args else None
        if folder is None:
            return []
        path = self._local_path(folder)
        if not path:
            return []
        item = Nautilus.MenuItem(
            name="RzpMenuProvider::CompressFolder",
            label="用 RZP 压缩此文件夹",
        )
        item.connect("activate", self._compress_cb, [path])
        return [item]
