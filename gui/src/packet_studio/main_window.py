from __future__ import annotations

from pathlib import Path
from typing import Optional

from PySide6 import QtCore, QtGui, QtWidgets

from packet_studio.domain.task_models import TaskPhase, TaskState
from packet_studio.domain.workspace_models import WorkspaceDocument, WorkspacePanelSnapshot, TaskRecord
from packet_studio.runtime.dependency_check import AppEnvironment
from packet_studio.services.interface_service import InterfaceRecord, InterfaceService
from packet_studio.services.workspace_document_service import WorkspaceDocumentService
from packet_studio.widgets.automation_tools_widget import AutomationToolsWidget
from packet_studio.widgets.offline_analysis_widget import OfflineAnalysisWidget
from packet_studio.widgets.packet_builder_widget import PacketBuilderWidget
from packet_studio.widgets.send_task_widget import SendTaskWidget


class InterfaceLoadWorker(QtCore.QObject):
    finished = QtCore.Signal(int, bool, list)
    failed = QtCore.Signal(int, str)

    def __init__(
        self,
        interfaceService: InterfaceService,
        generation: int,
        initialLoad: bool,
    ) -> None:
        super().__init__()
        self.interfaceService = interfaceService
        self.generation = generation
        self.initialLoad = initialLoad

    @QtCore.Slot()
    def run(self) -> None:
        try:
            records = self.interfaceService.loadInterfaces()
        except Exception as exc:
            self.failed.emit(self.generation, str(exc))
            return
        self.finished.emit(self.generation, self.initialLoad, records)


class MainWindow(QtWidgets.QMainWindow):
    """Scapy Studio 的最小主窗口。"""

    def __init__(self, environment: AppEnvironment, log_file: Path) -> None:
        super().__init__()
        self.environment = environment
        self.log_file = log_file
        self.interfaceService = InterfaceService()
        self.interfaceRecords: list[InterfaceRecord] = []
        self.interfaceLoadThread: Optional[QtCore.QThread] = None
        self.interfaceLoadWorker: Optional[InterfaceLoadWorker] = None
        self.interfaceLoadGeneration = 0
        self.interfaceLoadActive = False
        self.workspaceDocumentService = WorkspaceDocumentService()
        self.taskRecords: list[TaskRecord] = []
        self.workspaceDocument: Optional[WorkspaceDocument] = None

        self.setWindowTitle("Scapy Studio")
        self.resize(1440, 900)

        self._setup_ui()
        self._populate_environment()
        QtCore.QTimer.singleShot(0, self._start_initial_interface_load)

    def _setup_ui(self) -> None:
        self.leftNav = QtWidgets.QListWidget()
        self.leftNav.addItems(
            [
                "欢迎",
                "接口",
                "包构建器",
                "发送任务",
                "离线分析",
                "自动化工具",
            ]
        )
        self.leftNav.setCurrentRow(0)

        self.workspace_tabs = QtWidgets.QTabWidget()
        self.leftNav.currentRowChanged.connect(self.workspace_tabs.setCurrentIndex)
        self.workspace_tabs.currentChanged.connect(self.leftNav.setCurrentRow)
        self.workspace_tabs.currentChanged.connect(self._handle_workspace_tab_changed)
        self.packetBuilderTab = PacketBuilderWidget()
        self.sendTaskTab = SendTaskWidget()
        self.offlineAnalysisTab = OfflineAnalysisWidget()
        self.automationToolsTab = AutomationToolsWidget()
        self.packetBuilderTab.createStreamRequested.connect(self.sendTaskTab.addStreamFromPacket)
        self.packetBuilderTab.saveStreamRequested.connect(self._handle_save_stream_to_send_task)
        self.sendTaskTab.editPacketRequested.connect(self._handle_edit_send_stream_packet)
        self.offlineAnalysisTab.importPacketRequested.connect(self._handle_import_capture_packet)
        self.automationToolsTab.openToolRequested.connect(self._handle_open_tool_tab)
        self.workspace_tabs.addTab(self._build_welcome_tab(), "欢迎")
        self.workspace_tabs.addTab(self._build_interfaces_tab(), "接口")
        self.workspace_tabs.addTab(self.packetBuilderTab, "包构建器")
        self.workspace_tabs.addTab(self.sendTaskTab, "发送任务")
        self.workspace_tabs.addTab(self.offlineAnalysisTab, "离线分析")
        self.workspace_tabs.addTab(self.automationToolsTab, "自动化工具")

        splitter = QtWidgets.QSplitter(QtCore.Qt.Orientation.Horizontal)
        splitter.addWidget(self.leftNav)
        splitter.addWidget(self.workspace_tabs)
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)
        self.setCentralWidget(splitter)

        details_dock = QtWidgets.QDockWidget("详情", self)
        details_dock.setAllowedAreas(
            QtCore.Qt.DockWidgetArea.RightDockWidgetArea
        )
        details_dock.setWidget(self._build_details_panel())
        self.addDockWidget(QtCore.Qt.DockWidgetArea.RightDockWidgetArea, details_dock)

        log_dock = QtWidgets.QDockWidget("运行与日志", self)
        log_dock.setAllowedAreas(
            QtCore.Qt.DockWidgetArea.BottomDockWidgetArea
        )
        log_dock.setWidget(self._build_log_panel())
        self.addDockWidget(QtCore.Qt.DockWidgetArea.BottomDockWidgetArea, log_dock)
        self.sendTaskTab.statusMessage.connect(
            lambda message: self._handle_panel_status_message(
                "发送任务",
                self.sendTaskTab.buildWorkspaceSnapshot,
                message,
            )
        )
        self.offlineAnalysisTab.statusMessage.connect(
            lambda message: self._handle_panel_status_message(
                "离线分析",
                self.offlineAnalysisTab.buildWorkspaceSnapshot,
                message,
            )
        )
        self.automationToolsTab.statusMessage.connect(
            lambda message: self._handle_panel_status_message(
                "自动化工具",
                self.automationToolsTab.buildWorkspaceSnapshot,
                message,
            )
        )

        status_bar = self.statusBar()
        status_bar.showMessage("GUI 子项目骨架已启动")
        self._refresh_workspace_document()

    def closeEvent(self, event: QtGui.QCloseEvent) -> None:
        if self.interfaceLoadActive or self.sendTaskTab.hasRunningTask() or self.offlineAnalysisTab.isLoading():
            QtWidgets.QMessageBox.warning(
                self,
                "后台任务仍在运行",
                "请等待接口刷新、发送任务或离线分析完成后再关闭窗口。",
            )
            event.ignore()
            return
        if self.interfaceLoadThread is not None and self.interfaceLoadThread.isRunning():
            self.interfaceLoadThread.quit()
            self.interfaceLoadThread.wait(3000)
        super().closeEvent(event)

    def _build_interfaces_tab(self) -> QtWidgets.QWidget:
        widget = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(widget)

        topBar = QtWidgets.QHBoxLayout()
        self.interfaceSummaryLabel = QtWidgets.QLabel("正在加载接口列表...")
        self.interfaceSummaryLabel.setWordWrap(True)
        self.refreshInterfacesButton = QtWidgets.QPushButton("刷新接口")
        self.refreshInterfacesButton.clicked.connect(self._handle_refresh_interfaces)
        topBar.addWidget(self.interfaceSummaryLabel, 1)
        topBar.addWidget(self.refreshInterfacesButton)

        self.interfaceLoadingBar = QtWidgets.QProgressBar()
        self.interfaceLoadingBar.setRange(0, 0)
        self.interfaceLoadingBar.setVisible(False)
        self.interfaceLoadingBar.setTextVisible(False)

        self.interfaceTable = QtWidgets.QTableWidget(0, 7)
        self.interfaceTable.setHorizontalHeaderLabels(
            ["名称", "描述", "网络名", "MAC", "IPv4", "IPv6", "能力"]
        )
        self.interfaceTable.setEditTriggers(
            QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers
        )
        self.interfaceTable.setSelectionBehavior(
            QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows
        )
        self.interfaceTable.setSelectionMode(
            QtWidgets.QAbstractItemView.SelectionMode.SingleSelection
        )
        self.interfaceTable.verticalHeader().setVisible(False)
        self.interfaceTable.horizontalHeader().setStretchLastSection(True)
        self.interfaceTable.horizontalHeader().setSectionResizeMode(
            0, QtWidgets.QHeaderView.ResizeMode.ResizeToContents
        )
        self.interfaceTable.horizontalHeader().setSectionResizeMode(
            1, QtWidgets.QHeaderView.ResizeMode.Stretch
        )
        self.interfaceTable.itemSelectionChanged.connect(self._handle_interface_selection)

        layout.addLayout(topBar)
        layout.addWidget(self.interfaceLoadingBar)
        layout.addWidget(self.interfaceTable, 1)
        return widget

    def _build_welcome_tab(self) -> QtWidgets.QWidget:
        widget = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(widget)

        title = QtWidgets.QLabel("Scapy Studio")
        title.setObjectName("titleLabel")
        title.setStyleSheet("font-size: 28px; font-weight: 700;")

        subtitle = QtWidgets.QLabel(
            "当前阶段已打通接口浏览、包构建与发送、离线分析主链路。"
        )
        subtitle.setWordWrap(True)

        self.environment_summary = QtWidgets.QTextEdit()
        self.environment_summary.setReadOnly(True)
        self.workspace_summary = QtWidgets.QPlainTextEdit()
        self.workspace_summary.setReadOnly(True)

        layout.addWidget(title)
        layout.addWidget(subtitle)
        layout.addWidget(self.environment_summary, 1)
        layout.addWidget(self.workspace_summary, 1)
        return widget

    def _build_placeholder_tab(self, message: str) -> QtWidgets.QWidget:
        widget = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(widget)
        label = QtWidgets.QLabel(message)
        label.setWordWrap(True)
        label.setAlignment(QtCore.Qt.AlignmentFlag.AlignTop)
        layout.addWidget(label)
        layout.addStretch(1)
        return widget

    def _build_details_panel(self) -> QtWidgets.QWidget:
        widget = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(widget)

        label = QtWidgets.QLabel("后续这里会承载字段编辑器、协议树和任务参数。")
        label.setWordWrap(True)
        layout.addWidget(label)

        self.details_list = QtWidgets.QTreeWidget()
        self.details_list.setHeaderLabels(["项目", "状态"])
        layout.addWidget(self.details_list, 1)
        return widget

    def _build_log_panel(self) -> QtWidgets.QWidget:
        widget = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(widget)

        self.log_view = QtWidgets.QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setPlainText(
            "运行日志面板已建立。\n"
            f"日志文件: {self.log_file}"
        )
        layout.addWidget(self.log_view)
        return widget

    def _populate_environment(self) -> None:
        self.environment_summary.setPlainText(self.environment.to_multiline_text())
        self._set_details_items(
            [
                ("Scapy", self.environment.scapy_version or "未检测到"),
                ("PySide6", self.environment.pyside6_version or "运行时导入"),
                ("Npcap", self.environment.npcap_status),
                ("管理员权限", "是" if self.environment.is_elevated else "否"),
                ("配置目录", str(self.environment.config_dir)),
                ("日志目录", str(self.environment.log_dir)),
            ]
        )
        self._refresh_workspace_document()

    def _start_initial_interface_load(self) -> None:
        self._start_interface_load(initialLoad=True)

    def _start_interface_load(self, initialLoad: bool = False) -> None:
        if self.interfaceLoadActive:
            self.interfaceSummaryLabel.setText("接口加载仍在进行中，请稍候。")
            return

        self.interfaceLoadGeneration += 1
        generation = self.interfaceLoadGeneration
        self.interfaceLoadActive = True
        self._set_interface_loading_state(True)
        if initialLoad:
            self.interfaceSummaryLabel.setText("正在后台加载接口列表...")
        else:
            self.interfaceSummaryLabel.setText("正在后台刷新接口列表...")
        self.log_view.appendPlainText("开始后台加载接口列表。")
        self._append_task_record("接口", self.interfaceSummaryLabel.text(), TaskPhase.RUNNING)
        self._refresh_workspace_document()

        thread = QtCore.QThread(self)
        worker = InterfaceLoadWorker(self.interfaceService, generation, initialLoad)
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.finished.connect(self._on_interfaces_loaded)
        worker.failed.connect(self._on_interfaces_failed)
        worker.finished.connect(thread.quit)
        worker.failed.connect(thread.quit)
        thread.finished.connect(worker.deleteLater)
        thread.finished.connect(self._on_interface_thread_finished)

        self.interfaceLoadThread = thread
        self.interfaceLoadWorker = worker
        thread.start()

    def _populate_interface_table(self) -> None:
        self.interfaceTable.clearContents()
        self.interfaceTable.setRowCount(len(self.interfaceRecords))
        for rowIndex, interfaceRecord in enumerate(self.interfaceRecords):
            values = [
                interfaceRecord.name,
                interfaceRecord.description,
                interfaceRecord.networkName,
                interfaceRecord.mac,
                interfaceRecord.ipv4,
                interfaceRecord.ipv6,
                interfaceRecord.capabilitySummary,
            ]
            for columnIndex, value in enumerate(values):
                item = QtWidgets.QTableWidgetItem(value)
                item.setData(QtCore.Qt.ItemDataRole.UserRole, rowIndex)
                self.interfaceTable.setItem(rowIndex, columnIndex, item)

    def _handle_refresh_interfaces(self) -> None:
        self.statusBar().showMessage("正在刷新接口列表...")
        self._start_interface_load()

    def _handle_interface_selection(self) -> None:
        selectedItems = self.interfaceTable.selectedItems()
        if not selectedItems:
            return
        rowIndex = selectedItems[0].data(QtCore.Qt.ItemDataRole.UserRole)
        interfaceRecord = self.interfaceRecords[rowIndex]
        self._show_interface_details(interfaceRecord)

    def _show_interface_details(self, interfaceRecord: InterfaceRecord) -> None:
        self._set_details_items(
            [
                ("名称", interfaceRecord.name),
                ("描述", interfaceRecord.description),
                ("网络名", interfaceRecord.networkName),
                ("Provider", interfaceRecord.provider),
                ("索引", str(interfaceRecord.index)),
                ("MAC", interfaceRecord.mac or ""),
                ("IPv4", interfaceRecord.ipv4 or ""),
                ("IPv6", interfaceRecord.ipv6 or ""),
                ("Flags", interfaceRecord.flags),
                ("状态", "可用" if interfaceRecord.isValid else "不可用"),
                ("能力", interfaceRecord.capabilitySummary),
            ]
        )

    @QtCore.Slot(object)
    def _handle_import_capture_packet(self, packet: object) -> None:
        try:
            self.packetBuilderTab.setEditingStreamMode(False)
            self.packetBuilderTab.loadPacket(packet)
        except Exception as exc:
            self.statusBar().showMessage(f"导入数据包失败: {exc}", 5000)
            self.log_view.appendPlainText(f"导入数据包失败: {exc}")
            return

        self.workspace_tabs.setCurrentWidget(self.packetBuilderTab)
        self.statusBar().showMessage("已将数据包复制到包构建器。", 5000)
        self.log_view.appendPlainText("已将数据包复制到包构建器。")

    @QtCore.Slot(object)
    def _handle_edit_send_stream_packet(self, packet: object) -> None:
        selectedTemplateId = self.sendTaskTab.getCurrentSelectedTemplateId()
        if selectedTemplateId is None:
            self.statusBar().showMessage("当前没有选中的流模板。", 5000)
            return
        try:
            self.sendTaskTab.beginEditingStream(selectedTemplateId)
            self.packetBuilderTab.setEditingStreamMode(True)
            self.packetBuilderTab.loadPacket(packet)
        except Exception as exc:
            self.packetBuilderTab.setEditingStreamMode(False)
            self.statusBar().showMessage(f"载入流模板到包构建器失败: {exc}", 5000)
            self.log_view.appendPlainText(f"载入流模板到包构建器失败: {exc}")
            return

        self.workspace_tabs.setCurrentWidget(self.packetBuilderTab)
        self.statusBar().showMessage("已跳转到包构建器，可继续复杂编辑。", 5000)
        self.log_view.appendPlainText("已从发送任务跳转到包构建器继续编辑。")

    @QtCore.Slot(object)
    def _handle_save_stream_to_send_task(self, packet: object) -> None:
        saved = self.sendTaskTab.saveEditedStream(packet)
        if not saved:
            self.statusBar().showMessage("当前没有可回写的流模板，请先从发送任务进入编辑。", 5000)
            self.log_view.appendPlainText("保存回流模板失败：当前没有编辑中的流模板。")
            return

        self.packetBuilderTab.setEditingStreamMode(False)
        self.workspace_tabs.setCurrentWidget(self.sendTaskTab)
        self.statusBar().showMessage("已保存回当前流模板。", 5000)
        self.log_view.appendPlainText("已将包构建器修改保存回当前流模板。")

    @QtCore.Slot(str)
    def _handle_open_tool_tab(self, targetTabTitle: str) -> None:
        for index in range(self.workspace_tabs.count()):
            if self.workspace_tabs.tabText(index) == targetTabTitle:
                self.workspace_tabs.setCurrentIndex(index)
                self.statusBar().showMessage(f"已打开工具页: {targetTabTitle}", 5000)
                return

        self.statusBar().showMessage(f"未找到工具页: {targetTabTitle}", 5000)

    @QtCore.Slot(int, bool, list)
    def _on_interfaces_loaded(
        self,
        generation: int,
        initialLoad: bool,
        records: list[InterfaceRecord],
    ) -> None:
        if generation != self.interfaceLoadGeneration:
            return

        self.interfaceRecords = records
        self.sendTaskTab.setInterfaceRecords(records)
        self._populate_interface_table()
        count = len(self.interfaceRecords)
        if count == 0:
            self.interfaceSummaryLabel.setText(
                "当前没有发现可用接口。请确认 Npcap、权限和网络适配器状态。"
            )
            self.statusBar().showMessage("接口扫描完成，但没有可用接口。", 5000)
            if initialLoad:
                self.log_view.appendPlainText("未发现可用接口。")
            self._append_task_record("接口", self.interfaceSummaryLabel.text(), TaskPhase.SUCCEEDED)
            self._refresh_workspace_document()
            return

        self.interfaceSummaryLabel.setText(f"已发现 {count} 个可用接口。")
        self.statusBar().showMessage(f"接口列表已刷新，共 {count} 个接口。", 5000)
        self.log_view.appendPlainText(f"接口扫描完成，共 {count} 个可用接口。")
        self.interfaceTable.selectRow(0)
        self._append_task_record("接口", self.interfaceSummaryLabel.text(), TaskPhase.SUCCEEDED)
        self._refresh_workspace_document()

    @QtCore.Slot(int, str)
    def _on_interfaces_failed(self, generation: int, message: str) -> None:
        if generation != self.interfaceLoadGeneration:
            return

        self.interfaceRecords = []
        self.sendTaskTab.setInterfaceRecords([])
        self.interfaceTable.clearContents()
        self.interfaceTable.setRowCount(0)
        self.interfaceSummaryLabel.setText(f"接口加载失败: {message}")
        self.statusBar().showMessage("接口加载失败", 5000)
        self.log_view.appendPlainText(f"接口加载失败: {message}")
        self._set_details_items(
            [
                ("接口状态", "加载失败"),
                ("失败原因", message),
            ]
        )
        self._append_task_record("接口", f"接口加载失败: {message}", TaskPhase.FAILED)
        self._refresh_workspace_document()

    def _on_interface_thread_finished(self) -> None:
        self.interfaceLoadActive = False
        self._set_interface_loading_state(False)
        self.interfaceLoadThread = None
        self.interfaceLoadWorker = None
        self._refresh_workspace_document()

    def _set_interface_loading_state(self, isLoading: bool) -> None:
        self.refreshInterfacesButton.setEnabled(not isLoading)
        self.interfaceTable.setEnabled(not isLoading)
        self.interfaceLoadingBar.setVisible(isLoading)

    def _set_details_items(self, items: list[tuple[str, str]]) -> None:
        self.details_list.clear()
        for name, value in items:
            item = QtWidgets.QTreeWidgetItem([name, value])
            self.details_list.addTopLevelItem(item)

    def _handle_panel_status_message(
        self,
        sourceTitle: str,
        snapshotBuilder: callable,
        message: str,
    ) -> None:
        self.log_view.appendPlainText(message)
        snapshot = snapshotBuilder()
        self._append_task_record(sourceTitle, message, snapshot.taskState.phase, snapshot.detailText)
        self._refresh_workspace_document()

    def _handle_workspace_tab_changed(self, _index: int) -> None:
        self._refresh_workspace_document()

    def _append_task_record(
        self,
        sourceTitle: str,
        message: str,
        phase: TaskPhase,
        detailText: str = "",
    ) -> None:
        record = self.workspaceDocumentService.createTaskRecord(
            sequenceNumber=len(self.taskRecords) + 1,
            sourceTitle=sourceTitle,
            message=message,
            phase=phase,
            detailText=detailText,
        )
        self.taskRecords.append(record)
        if len(self.taskRecords) > 50:
            self.taskRecords = self.taskRecords[-50:]

    def _collect_workspace_snapshots(self) -> list[WorkspacePanelSnapshot]:
        interfaceStatusText = "接口页尚未初始化。"
        interfaceCount = len(self.interfaceRecords)
        if hasattr(self, "interfaceSummaryLabel"):
            interfaceStatusText = self.interfaceSummaryLabel.text()

        if self.interfaceLoadActive:
            interfaceState = TaskState.running(interfaceStatusText)
        elif "失败" in interfaceStatusText:
            interfaceState = TaskState.failed(interfaceStatusText)
        elif interfaceCount:
            interfaceState = TaskState.succeeded(interfaceStatusText)
        else:
            interfaceState = TaskState.idle(interfaceStatusText)

        snapshots = [
            WorkspacePanelSnapshot(
                panelId="interfaces",
                title="接口",
                taskState=interfaceState,
                itemCount=interfaceCount,
                detailText=interfaceStatusText,
            ),
            self.packetBuilderTab.buildWorkspaceSnapshot(),
            self.sendTaskTab.buildWorkspaceSnapshot(),
            self.offlineAnalysisTab.buildWorkspaceSnapshot(),
            self.automationToolsTab.buildWorkspaceSnapshot(),
        ]
        return snapshots

    def _refresh_workspace_document(self) -> None:
        activeIndex = self.workspace_tabs.currentIndex()
        activeTabTitle = self.workspace_tabs.tabText(activeIndex) if activeIndex >= 0 else "欢迎"
        openTabTitles = [self.workspace_tabs.tabText(index) for index in range(self.workspace_tabs.count())]
        self.workspaceDocument = self.workspaceDocumentService.buildWorkspaceDocument(
            activeTabTitle=activeTabTitle,
            openTabTitles=openTabTitles,
            panelSnapshots=self._collect_workspace_snapshots(),
            taskRecords=self.taskRecords,
            interfaceCount=len(self.interfaceRecords),
            interfaceSummaryText=self.interfaceSummaryLabel.text() if hasattr(self, "interfaceSummaryLabel") else "",
        )
        if hasattr(self, "workspace_summary"):
            self.workspace_summary.setPlainText(self.workspaceDocument.to_multiline_text())
