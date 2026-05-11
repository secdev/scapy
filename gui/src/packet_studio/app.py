from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Sequence
from packet_studio.runtime.dependency_check import collect_environment
from packet_studio.runtime.paths import ensure_runtime_directories


def configure_logging(log_dir: Path) -> Path:
    """初始化最小日志输出。"""
    log_file = log_dir / "packet_studio.log"
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        handlers=[
            logging.FileHandler(log_file, encoding="utf-8"),
            logging.StreamHandler(sys.stdout),
        ],
    )
    return log_file


def main(argv: Sequence[str] | None = None) -> int:
    """启动 GUI 应用。"""
    try:
        from PySide6 import QtWidgets
    except ModuleNotFoundError:
        print(
            "未安装 PySide6，无法启动 Scapy Studio。\n"
            "请先在 gui 子项目环境中执行: pip install -e .",
            file=sys.stderr,
        )
        return 1

    from packet_studio.main_window import MainWindow

    runtime_dirs = ensure_runtime_directories()
    log_file = configure_logging(runtime_dirs.log_dir)
    logging.getLogger(__name__).info("日志文件: %s", log_file)

    app_argv = list(argv) if argv is not None else sys.argv
    application = QtWidgets.QApplication(app_argv)
    application.setApplicationName("Scapy Studio")
    application.setOrganizationName("Scapy Studio")

    environment = collect_environment(runtime_dirs)
    window = MainWindow(environment=environment, log_file=log_file)
    window.show()
    return application.exec()