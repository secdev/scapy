from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Sequence

from packet_studio.app import configure_logging
from packet_studio.main_window import MainWindow
from packet_studio.runtime.dependency_check import AppEnvironment, collect_environment
from packet_studio.runtime.paths import ensure_runtime_directories


def _build_checklist_text(environment: AppEnvironment, log_file: Path) -> str:
    lines = [
        "Scapy Studio Windows 验收启动器",
        "",
        f"Scapy 版本: {environment.scapy_version or '未检测到'}",
        f"PySide6 版本: {environment.pyside6_version or '未检测到'}",
        f"Npcap 状态: {environment.npcap_status}",
        f"管理员权限: {'是' if environment.is_elevated else '否'}",
        f"日志文件: {log_file}",
        "",
        "建议人工验收清单:",
        "1. 在欢迎页确认环境摘要、日志目录和依赖状态。",
        "2. 打开接口页，刷新并确认目标网卡是否可见。",
        "3. 在包构建器中添加 IP/ICMP 或 Ether/ARP，确认摘要、结构和十六进制联动。",
        "4. 在发送任务页验证 send、sendp 或 sr1 基本路径。",
        "5. 在离线分析页打开 pcap 或 pcapng，验证列表、过滤、详情和复制回构包。",
        "",
        "说明:",
        "- sendp 和部分接口能力仍依赖 Npcap、管理员权限和网卡驱动。",
        "- 如果目标机只做人工验收，优先使用此启动器；自动化测试仍建议在开发机源码环境运行。",
    ]
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    try:
        from PySide6 import QtWidgets
    except ModuleNotFoundError:
        print(
            "未安装 PySide6，无法启动 Windows 验收启动器。\n"
            "请先在 gui 子项目环境中执行: pip install -e .",
            file=sys.stderr,
        )
        return 1

    runtime_dirs = ensure_runtime_directories()
    log_file = configure_logging(runtime_dirs.log_dir)
    logging.getLogger(__name__).info("日志文件: %s", log_file)

    app_argv = list(argv) if argv is not None else sys.argv
    application = QtWidgets.QApplication(app_argv)
    application.setApplicationName("Scapy Studio Validation")
    application.setOrganizationName("Scapy Studio")

    environment = collect_environment(runtime_dirs)
    messageBox = QtWidgets.QMessageBox()
    messageBox.setWindowTitle("Scapy Studio Windows 验收")
    messageBox.setIcon(QtWidgets.QMessageBox.Icon.Information)
    messageBox.setText("将启动 Scapy Studio GUI，并显示当前机器的验收前置信息。")
    messageBox.setDetailedText(_build_checklist_text(environment, log_file))
    launchButton = messageBox.addButton("启动 GUI 验收", QtWidgets.QMessageBox.ButtonRole.AcceptRole)
    messageBox.addButton("取消", QtWidgets.QMessageBox.ButtonRole.RejectRole)
    messageBox.exec()
    if messageBox.clickedButton() is not launchButton:
        return 0

    window = MainWindow(environment=environment, log_file=log_file)
    window.show()
    return application.exec()


if __name__ == "__main__":
    raise SystemExit(main())