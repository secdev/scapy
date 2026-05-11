from __future__ import annotations

import ctypes
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from packet_studio.runtime.paths import RuntimeDirectories


@dataclass(frozen=True)
class AppEnvironment:
    scapy_version: Optional[str]
    pyside6_version: Optional[str]
    npcap_status: str
    is_elevated: bool
    config_dir: Path
    log_dir: Path
    cache_dir: Path

    def to_multiline_text(self) -> str:
        lines = [
            "Scapy Studio 运行环境概览",
            "",
            f"Scapy 版本: {self.scapy_version or '未检测到'}",
            f"PySide6 版本: {self.pyside6_version or '运行时导入'}",
            f"Npcap 状态: {self.npcap_status}",
            f"管理员权限: {'是' if self.is_elevated else '否'}",
            f"配置目录: {self.config_dir}",
            f"日志目录: {self.log_dir}",
            f"缓存目录: {self.cache_dir}",
        ]
        return "\n".join(lines)


def collect_environment(runtime_dirs: RuntimeDirectories) -> AppEnvironment:
    return AppEnvironment(
        scapy_version=_detect_scapy_version(),
        pyside6_version=_detect_pyside6_version(),
        npcap_status=_detect_npcap_status(),
        is_elevated=_is_elevated(),
        config_dir=runtime_dirs.config_dir,
        log_dir=runtime_dirs.log_dir,
        cache_dir=runtime_dirs.cache_dir,
    )


def _detect_scapy_version() -> Optional[str]:
    try:
        import scapy  # type: ignore

        return getattr(scapy, "VERSION", None)
    except Exception:
        return None


def _detect_pyside6_version() -> Optional[str]:
    try:
        import PySide6  # type: ignore

        return getattr(PySide6, "__version__", None)
    except Exception:
        return None


def _detect_npcap_status() -> str:
    if os.name != "nt":
        return "当前不是 Windows 环境"

    program_files = os.environ.get("ProgramFiles", r"C:\Program Files")
    candidates = [
        Path(program_files) / "Npcap",
        Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "Npcap",
    ]
    for candidate in candidates:
        if candidate.exists():
            return f"已检测到: {candidate}"
    return "未检测到 Npcap 安装目录"


def _is_elevated() -> bool:
    if os.name != "nt":
        return os.getuid() == 0 if hasattr(os, "getuid") else False

    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False