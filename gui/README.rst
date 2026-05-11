Scapy Studio GUI
================

这是 Scapy 图形化应用的独立子项目骨架。

当前阶段目标：

* 保持与主仓库解耦
* 提供最小可运行的 PySide6 启动入口
* 建立主窗口、运行时目录和依赖检查基础设施

运行方式::

    python -m packet_studio

Windows 验证脚本::

    powershell -ExecutionPolicy Bypass -File scripts\windows_npcap_validation.ps1 -SkipManualChecklist

另一台 Windows 电脑如何测试
---------------------------

有两种方式：

1. 源码方式

    * 拷贝整个仓库，至少保留 ``scapy/`` 根目录和 ``gui/`` 子项目。
    * 目标机需要安装 Python 3.9+。
    * 安装 GUI 依赖：``python -m pip install -e .``。
    * 如需 ``sendp`` 或更完整的网卡发现，目标机还需要安装 Npcap；部分功能建议管理员权限运行。
    * 然后在 ``gui/`` 目录执行现有脚本：``powershell -ExecutionPolicy Bypass -File scripts\windows_npcap_validation.ps1``。

2. 打包方式

    * 正式发布时，仅发布 ``onedir`` 版本，双击后会直接打开 Scapy Studio 主界面。
    * 先在开发机安装 PyInstaller：``python -m pip install pyinstaller``。
    * 在 ``gui/`` 目录执行：``powershell -ExecutionPolicy Bypass -File scripts\build_windows_validation_exe.ps1``。
    * 默认生成 ``onedir`` 版本，稳定性更高；产物目录为 ``dist\ScapyStudio``，主程序为 ``ScapyStudio.exe``。
    * 目标机仍建议安装 Npcap；若要做 ``sendp`` 或接口相关验证，通常仍建议管理员权限运行。

Windows 发布打包::

    powershell -ExecutionPolicy Bypass -File scripts\build_windows_release_package.ps1

也可以直接双击 ``build_release_package.bat`` 重新打包并生成 zip 发布包。该发布包会包含 ``ScapyStudio`` 目录和安装说明 ``ScapyStudio-Windows-Guide.txt``。

说明：

* 仅拷贝 ``windows_npcap_validation.ps1`` 到另一台机器通常不够，因为它依赖 Python、Scapy、PySide6 以及仓库源码结构。
* 本次正式发布仅支持 ``onedir`` 目录形式，不提供单文件 exe。