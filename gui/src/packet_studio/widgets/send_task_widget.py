from __future__ import annotations

import re
import threading
from dataclasses import dataclass
from typing import Any, Optional

from PySide6 import QtCore, QtGui, QtWidgets

from packet_studio.domain.packet_models import PacketPreview
from packet_studio.domain.task_models import SendTaskResult, TaskError, TaskState
from packet_studio.domain.workspace_models import WorkspacePanelSnapshot
from packet_studio.services.interface_service import InterfaceRecord
from packet_studio.services.send_task_service import SendTaskRequest, SendTaskService


@dataclass
class StreamTemplateEntry:
    templateId: int
    name: str
    packet: Any
    preview: PacketPreview
    enabled: bool = True
    sourceMac: str = ""
    destinationMac: str = ""
    hasEtherLayer: bool = False


class SendTaskWorker(QtCore.QObject):
    finished = QtCore.Signal(object)
    failed = QtCore.Signal(object)

    def __init__(
        self,
        sendTaskService: SendTaskService,
        request: SendTaskRequest,
        packets: list[Any],
        stopEvent: threading.Event,
    ) -> None:
        super().__init__()
        self.sendTaskService = sendTaskService
        self.request = request
        self.packets = packets
        self.stopEvent = stopEvent

    @QtCore.Slot()
    def run(self) -> None:
        try:
            result = self.sendTaskService.execute(
                self.request,
                self.packets,
                stopRequested=self.stopEvent.is_set,
            )
        except Exception as exc:
            self.failed.emit(TaskError(message=str(exc), logText=str(exc)))
            return
        self.finished.emit(result)


class SendTaskWidget(QtWidgets.QWidget):
    """发送与 sr1 请求响应任务面板。"""

    statusMessage = QtCore.Signal(str)
    editPacketRequested = QtCore.Signal(object)
    _MAC_PATTERN = re.compile(r"^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")

    def __init__(self, parent: QtWidgets.QWidget | None = None) -> None:
        super().__init__(parent)
        self.sendTaskService = SendTaskService()
        self.interfaceRecords: list[InterfaceRecord] = []
        self.streamTemplates: list[StreamTemplateEntry] = []
        self.nextTemplateId = 1
        self.currentEditingTemplateId: int | None = None
        self.workerThread: Optional[QtCore.QThread] = None
        self.worker: Optional[SendTaskWorker] = None
        self.stopEvent: Optional[threading.Event] = None
        self.currentTaskState = TaskState.idle("准备就绪。")

        self._setup_ui()
        self._refresh_stream_table()
        self._update_mode_state()

    def hasRunningTask(self) -> bool:
        return self.workerThread is not None

    def closeEvent(self, event: QtGui.QCloseEvent) -> None:
        if self.hasRunningTask():
            QtWidgets.QMessageBox.warning(
                self,
                "发送任务仍在运行",
                "请等待当前发送任务结束后再关闭窗口。",
            )
            event.ignore()
            return
        super().closeEvent(event)

    def setInterfaceRecords(self, interfaceRecords: list[InterfaceRecord]) -> None:
        self.interfaceRecords = list(interfaceRecords)
        selectedValue = self.interfaceCombo.currentData()
        self.interfaceCombo.blockSignals(True)
        self.interfaceCombo.clear()
        self.interfaceCombo.addItem("自动选择 / 路由决定", "")
        restoredIndex = 0
        for index, interfaceRecord in enumerate(self.interfaceRecords, start=1):
            label = f"{interfaceRecord.name} [{interfaceRecord.capabilitySummary}]"
            self.interfaceCombo.addItem(
                label,
                interfaceRecord.networkName or interfaceRecord.name,
            )
            if selectedValue and self.interfaceCombo.itemData(index) == selectedValue:
                restoredIndex = index
        self.interfaceCombo.setCurrentIndex(restoredIndex)
        self.interfaceCombo.blockSignals(False)

    def buildWorkspaceSnapshot(self) -> WorkspacePanelSnapshot:
        return WorkspacePanelSnapshot(
            panelId="send-task",
            title="发送任务",
            taskState=self.currentTaskState,
            itemCount=len(self.streamTemplates),
            detailText=self.resultSummaryLabel.text(),
        )

    @QtCore.Slot(object)
    def addStreamFromPacket(self, packet: Any) -> None:
        packetCopy = packet.copy() if packet is not None and hasattr(packet, "copy") else packet
        preview = self.sendTaskService.buildPacketPreview(packetCopy)
        if packetCopy is None or preview is None:
            self.statusLabel.setText("无法创建流模板：当前数据包为空。")
            return

        sourceMac, destinationMac, hasEtherLayer = self._extract_mac_fields(packetCopy)
        entry = StreamTemplateEntry(
            templateId=self.nextTemplateId,
            name=f"流 {self.nextTemplateId}",
            packet=packetCopy,
            preview=preview,
            sourceMac=sourceMac,
            destinationMac=destinationMac,
            hasEtherLayer=hasEtherLayer,
        )
        self.nextTemplateId += 1
        self.streamTemplates.append(entry)
        self._refresh_stream_table(selectedTemplateId=entry.templateId)
        self._apply_preview(entry.preview)
        self.statusLabel.setText(f"已新增流模板: {entry.name}")
        self.statusMessage.emit(f"已新增流模板: {entry.name}")

    def beginEditingStream(self, templateId: int) -> None:
        if self._find_stream(templateId) is None:
            self.currentEditingTemplateId = None
            return
        self.currentEditingTemplateId = templateId

    def getCurrentSelectedTemplateId(self) -> int | None:
        entry = self._current_selected_stream()
        if entry is None:
            return None
        return entry.templateId

    def saveEditedStream(self, packet: Any) -> bool:
        if self.currentEditingTemplateId is None:
            return False
        entry = self._find_stream(self.currentEditingTemplateId)
        if entry is None:
            self.currentEditingTemplateId = None
            return False
        packetCopy = packet.copy() if packet is not None and hasattr(packet, "copy") else packet
        preview = self.sendTaskService.buildPacketPreview(packetCopy)
        if packetCopy is None or preview is None:
            return False
        entry.packet = packetCopy
        entry.preview = preview
        entry.sourceMac, entry.destinationMac, entry.hasEtherLayer = self._extract_mac_fields(packetCopy)
        self._refresh_stream_table(selectedTemplateId=entry.templateId)
        self.statusLabel.setText(f"已保存回流模板: {entry.name}")
        self.statusMessage.emit(f"已保存回流模板: {entry.name}")
        self.currentEditingTemplateId = None
        return True

    def _setup_ui(self) -> None:
        rootLayout = QtWidgets.QVBoxLayout(self)

        controlsLayout = QtWidgets.QGridLayout()
        controlsLayout.addWidget(QtWidgets.QLabel("执行模式"), 0, 0)
        self.modeCombo = QtWidgets.QComboBox()
        self.modeCombo.addItem("send (L3 发送)", "send")
        self.modeCombo.addItem("sendp (L2 发送)", "sendp")
        self.modeCombo.addItem("sr1 (L3 请求/响应)", "sr1")
        self.modeCombo.setCurrentIndex(1)
        self.modeCombo.currentIndexChanged.connect(self._handle_mode_changed)
        controlsLayout.addWidget(self.modeCombo, 0, 1)

        controlsLayout.addWidget(QtWidgets.QLabel("发送策略"), 0, 2)
        self.strategyCombo = QtWidgets.QComboBox()
        self.strategyCombo.addItem("burst (按轮次发送)", "burst")
        self.strategyCombo.addItem("continuous (持续发送)", "continuous")
        self.strategyCombo.currentIndexChanged.connect(self._handle_strategy_changed)
        controlsLayout.addWidget(self.strategyCombo, 0, 3)

        controlsLayout.addWidget(QtWidgets.QLabel("接口"), 1, 0)
        self.interfaceCombo = QtWidgets.QComboBox()
        self.interfaceCombo.addItem("自动选择 / 路由决定", "")
        controlsLayout.addWidget(self.interfaceCombo, 1, 1)

        controlsLayout.addWidget(QtWidgets.QLabel("发送轮次"), 1, 2)
        self.countSpin = QtWidgets.QSpinBox()
        self.countSpin.setRange(1, 100000)
        self.countSpin.setValue(1)
        controlsLayout.addWidget(self.countSpin, 1, 3)

        controlsLayout.addWidget(QtWidgets.QLabel("发送间隔 (s)"), 2, 0)
        self.intervalSpin = QtWidgets.QDoubleSpinBox()
        self.intervalSpin.setRange(0.0, 3600.0)
        self.intervalSpin.setDecimals(3)
        self.intervalSpin.setSingleStep(0.1)
        controlsLayout.addWidget(self.intervalSpin, 2, 1)

        controlsLayout.addWidget(QtWidgets.QLabel("超时 (s)"), 2, 2)
        self.timeoutSpin = QtWidgets.QDoubleSpinBox()
        self.timeoutSpin.setRange(0.1, 3600.0)
        self.timeoutSpin.setDecimals(3)
        self.timeoutSpin.setValue(1.0)
        controlsLayout.addWidget(self.timeoutSpin, 2, 3)

        controlsLayout.addWidget(QtWidgets.QLabel("重试次数"), 3, 0)
        self.retrySpin = QtWidgets.QSpinBox()
        self.retrySpin.setRange(0, 100)
        controlsLayout.addWidget(self.retrySpin, 3, 1)

        actionLayout = QtWidgets.QHBoxLayout()
        self.executeButton = QtWidgets.QPushButton("开始执行")
        self.executeButton.clicked.connect(self._handle_execute)
        self.stopButton = QtWidgets.QPushButton("停止")
        self.stopButton.clicked.connect(self._handle_stop)
        self.statusLabel = QtWidgets.QLabel("准备就绪。")
        self.statusLabel.setWordWrap(True)
        actionLayout.addWidget(self.executeButton)
        actionLayout.addWidget(self.stopButton)
        actionLayout.addWidget(self.statusLabel, 1)

        contentSplitter = QtWidgets.QSplitter(QtCore.Qt.Orientation.Horizontal)

        streamPane = QtWidgets.QWidget()
        streamLayout = QtWidgets.QVBoxLayout(streamPane)
        streamLayout.addWidget(QtWidgets.QLabel("流模板"))
        self.streamTable = QtWidgets.QTableWidget(0, 5)
        self.streamTable.setHorizontalHeaderLabels(["发送", "名称", "摘要", "源 MAC", "目标 MAC"])
        self.streamTable.verticalHeader().setVisible(False)
        self.streamTable.setSelectionBehavior(
            QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows
        )
        self.streamTable.setSelectionMode(
            QtWidgets.QAbstractItemView.SelectionMode.SingleSelection
        )
        self.streamTable.horizontalHeader().setStretchLastSection(False)
        self.streamTable.horizontalHeader().setSectionResizeMode(
            0, QtWidgets.QHeaderView.ResizeMode.ResizeToContents
        )
        self.streamTable.horizontalHeader().setSectionResizeMode(
            1, QtWidgets.QHeaderView.ResizeMode.Interactive
        )
        self.streamTable.horizontalHeader().setSectionResizeMode(
            2, QtWidgets.QHeaderView.ResizeMode.Interactive
        )
        self.streamTable.horizontalHeader().setSectionResizeMode(
            3, QtWidgets.QHeaderView.ResizeMode.Stretch
        )
        self.streamTable.horizontalHeader().setSectionResizeMode(
            4, QtWidgets.QHeaderView.ResizeMode.Stretch
        )
        self.streamTable.setColumnWidth(1, 130)
        self.streamTable.setColumnWidth(2, 220)
        self.streamTable.itemSelectionChanged.connect(self._handle_stream_selection_changed)
        streamLayout.addWidget(self.streamTable, 1)

        streamActionsLayout = QtWidgets.QHBoxLayout()
        self.selectAllStreamsButton = QtWidgets.QPushButton("全部勾选")
        self.clearCheckedStreamsButton = QtWidgets.QPushButton("全部取消")
        self.removeStreamButton = QtWidgets.QPushButton("移除选中流")
        self.editInBuilderButton = QtWidgets.QPushButton("跳到包构建器编辑")
        self.selectAllStreamsButton.clicked.connect(lambda: self._set_all_streams_enabled(True))
        self.clearCheckedStreamsButton.clicked.connect(lambda: self._set_all_streams_enabled(False))
        self.removeStreamButton.clicked.connect(self._handle_remove_selected_stream)
        self.editInBuilderButton.clicked.connect(self._handle_edit_selected_stream)
        streamActionsLayout.addWidget(self.selectAllStreamsButton)
        streamActionsLayout.addWidget(self.clearCheckedStreamsButton)
        streamActionsLayout.addWidget(self.removeStreamButton)
        streamActionsLayout.addWidget(self.editInBuilderButton)
        streamLayout.addLayout(streamActionsLayout)

        previewSplitter = QtWidgets.QSplitter(QtCore.Qt.Orientation.Vertical)

        requestPane = QtWidgets.QWidget()
        requestLayout = QtWidgets.QVBoxLayout(requestPane)
        requestLayout.addWidget(QtWidgets.QLabel("选中流模板预览"))
        self.packetSummaryEdit = QtWidgets.QLineEdit()
        self.packetSummaryEdit.setReadOnly(True)
        requestLayout.addWidget(self.packetSummaryEdit)
        requestTabs = QtWidgets.QTabWidget()
        self.packetStructureEdit = QtWidgets.QPlainTextEdit()
        self.packetStructureEdit.setReadOnly(True)
        self.packetHexdumpEdit = QtWidgets.QPlainTextEdit()
        self.packetHexdumpEdit.setReadOnly(True)
        requestTabs.addTab(self.packetStructureEdit, "结构")
        requestTabs.addTab(self.packetHexdumpEdit, "十六进制")
        requestLayout.addWidget(requestTabs, 1)

        resultPane = QtWidgets.QWidget()
        resultLayout = QtWidgets.QVBoxLayout(resultPane)
        self.resultSummaryLabel = QtWidgets.QLabel("尚未执行发送任务。")
        self.resultSummaryLabel.setWordWrap(True)
        resultLayout.addWidget(self.resultSummaryLabel)
        resultTabs = QtWidgets.QTabWidget()
        self.resultLogEdit = QtWidgets.QPlainTextEdit()
        self.resultLogEdit.setReadOnly(True)
        self.answerStructureEdit = QtWidgets.QPlainTextEdit()
        self.answerStructureEdit.setReadOnly(True)
        self.answerHexdumpEdit = QtWidgets.QPlainTextEdit()
        self.answerHexdumpEdit.setReadOnly(True)
        resultTabs.addTab(self.resultLogEdit, "发送日志")
        resultTabs.addTab(self.answerStructureEdit, "应答结构")
        resultTabs.addTab(self.answerHexdumpEdit, "应答十六进制")
        resultLayout.addWidget(resultTabs, 1)

        previewSplitter.addWidget(requestPane)
        previewSplitter.addWidget(resultPane)
        previewSplitter.setStretchFactor(0, 1)
        previewSplitter.setStretchFactor(1, 1)

        contentSplitter.addWidget(streamPane)
        contentSplitter.addWidget(previewSplitter)
        contentSplitter.setStretchFactor(0, 1)
        contentSplitter.setStretchFactor(1, 1)

        rootLayout.addLayout(controlsLayout)
        rootLayout.addLayout(actionLayout)
        rootLayout.addWidget(contentSplitter, 1)

    def _build_request(self) -> SendTaskRequest:
        mode = str(self.modeCombo.currentData())
        interfaceName = ""
        if mode == "sendp":
            interfaceName = str(self.interfaceCombo.currentData() or "")
        return SendTaskRequest(
            mode=mode,
            sendStrategy=str(self.strategyCombo.currentData()),
            interfaceName=interfaceName,
            count=int(self.countSpin.value()),
            intervalSeconds=float(self.intervalSpin.value()),
            timeoutSeconds=float(self.timeoutSpin.value()),
            retryCount=int(self.retrySpin.value()),
        )

    def _handle_mode_changed(self) -> None:
        self._update_mode_state()

    def _handle_strategy_changed(self) -> None:
        self._update_mode_state()

    def _update_mode_state(self) -> None:
        mode = str(self.modeCombo.currentData())
        isRunning = self.workerThread is not None
        isSr1 = mode == "sr1"
        usesInterface = mode == "sendp"
        if isSr1 and self.strategyCombo.currentData() != "burst":
            self.strategyCombo.blockSignals(True)
            self.strategyCombo.setCurrentIndex(self.strategyCombo.findData("burst"))
            self.strategyCombo.blockSignals(False)
        strategy = str(self.strategyCombo.currentData())
        isContinuous = strategy == "continuous"
        self.strategyCombo.setEnabled(not isSr1 and not isRunning)
        self.countSpin.setEnabled(not isContinuous and not isRunning)
        self.intervalSpin.setEnabled(not isSr1 and not isRunning)
        self.timeoutSpin.setEnabled(isSr1 and not isRunning)
        self.retrySpin.setEnabled(isSr1 and not isRunning)
        self.interfaceCombo.setEnabled(usesInterface and not isRunning)
        if usesInterface:
            self.interfaceCombo.setToolTip("L2 发送会显式使用所选接口。")
        else:
            self.interfaceCombo.setToolTip("L3 send/sr1 由 Scapy 路由自动选择接口。")

    def _handle_execute(self) -> None:
        packets = self._selected_packets()
        if not packets:
            self.statusLabel.setText("请先创建并勾选至少一条流模板。")
            self.statusMessage.emit("发送任务启动失败：没有已勾选的流模板。")
            return
        if self.workerThread is not None:
            self.statusLabel.setText("已有发送任务正在执行，请稍候。")
            return

        request = self._build_request()
        self.resultLogEdit.clear()
        self.answerStructureEdit.clear()
        self.answerHexdumpEdit.clear()
        self.resultSummaryLabel.setText("发送任务执行中...")
        self._apply_task_state(TaskState.running("正在后台执行发送任务..."))
        self.statusMessage.emit(
            f"开始执行发送任务: {request.mode} / {request.sendStrategy} / {len(packets)} 条流"
        )
        self._set_running_state(True)
        self.stopEvent = threading.Event()

        thread = QtCore.QThread(self)
        worker = SendTaskWorker(self.sendTaskService, request, packets, self.stopEvent)
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.finished.connect(self._on_task_finished)
        worker.failed.connect(self._on_task_failed)
        worker.finished.connect(thread.quit)
        worker.failed.connect(thread.quit)
        thread.finished.connect(worker.deleteLater)
        thread.finished.connect(self._on_thread_finished)

        self.workerThread = thread
        self.worker = worker
        thread.start()

    def _handle_stop(self) -> None:
        if self.stopEvent is None or self.stopEvent.is_set():
            return
        self.stopEvent.set()
        self.stopButton.setEnabled(False)
        self.statusLabel.setText("正在停止当前发送任务...")
        self.statusMessage.emit("已请求停止当前发送任务。")

    @QtCore.Slot(object)
    def _on_task_finished(self, result: SendTaskResult) -> None:
        self.resultLogEdit.setPlainText(result.logText)
        if result.answerPreview is None:
            self.answerStructureEdit.setPlainText("本次任务没有应答数据包。")
            self.answerHexdumpEdit.setPlainText("")
        else:
            self.answerStructureEdit.setPlainText(result.answerPreview.structure)
            self.answerHexdumpEdit.setPlainText(result.answerPreview.hexdump)
        self.resultSummaryLabel.setText(result.summaryText)
        self._apply_task_state(result.state)
        self.statusMessage.emit(result.summaryText)

    @QtCore.Slot(object)
    def _on_task_failed(self, error: TaskError) -> None:
        self.resultSummaryLabel.setText(f"发送任务失败: {error.summaryText}")
        self.resultLogEdit.setPlainText(error.logText or error.summaryText)
        self._apply_task_state(error.state)
        self.statusMessage.emit(f"发送任务失败: {error.summaryText}")

    def _on_thread_finished(self) -> None:
        self.workerThread = None
        self.worker = None
        self.stopEvent = None
        self._set_running_state(False)
        self._sync_preview_with_selection()

    def _set_running_state(self, isRunning: bool) -> None:
        self.modeCombo.setEnabled(not isRunning)
        self.streamTable.setEnabled(not isRunning)
        hasSelectedStream = self._current_selected_stream() is not None
        hasTemplates = bool(self.streamTemplates)
        self.selectAllStreamsButton.setEnabled(not isRunning and hasTemplates)
        self.clearCheckedStreamsButton.setEnabled(not isRunning and hasTemplates)
        self.removeStreamButton.setEnabled(not isRunning and hasSelectedStream)
        self.editInBuilderButton.setEnabled(not isRunning and hasSelectedStream)
        self.executeButton.setEnabled(not isRunning and bool(self._selected_packets()))
        self.stopButton.setEnabled(isRunning)
        self._update_mode_state()

    def _apply_task_state(self, state: TaskState) -> None:
        self.currentTaskState = state
        self.statusLabel.setText(state.statusText)

    def _refresh_stream_table(self, selectedTemplateId: int | None = None) -> None:
        currentSelected = selectedTemplateId
        if currentSelected is None:
            currentEntry = self._current_selected_stream()
            currentSelected = currentEntry.templateId if currentEntry is not None else None

        self.streamTable.blockSignals(True)
        self.streamTable.clearContents()
        self.streamTable.setRowCount(len(self.streamTemplates))
        for rowIndex, entry in enumerate(self.streamTemplates):
            self._populate_stream_row(rowIndex, entry)
        self.streamTable.blockSignals(False)

        selectedRow = 0 if self.streamTemplates else -1
        if currentSelected is not None:
            for rowIndex, entry in enumerate(self.streamTemplates):
                if entry.templateId == currentSelected:
                    selectedRow = rowIndex
                    break
        if selectedRow >= 0:
            self.streamTable.selectRow(selectedRow)
        self._sync_preview_with_selection()
        self._set_running_state(self.workerThread is not None)

    def _populate_stream_row(self, rowIndex: int, entry: StreamTemplateEntry) -> None:
        checkContainer = QtWidgets.QWidget()
        checkLayout = QtWidgets.QHBoxLayout(checkContainer)
        checkLayout.setContentsMargins(0, 0, 0, 0)
        checkLayout.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
        checkBox = QtWidgets.QCheckBox()
        checkBox.setChecked(entry.enabled)
        checkBox.stateChanged.connect(
            lambda state, templateId=entry.templateId: self._handle_stream_enabled_changed(templateId, state)
        )
        checkLayout.addWidget(checkBox)
        self.streamTable.setCellWidget(rowIndex, 0, checkContainer)

        nameItem = QtWidgets.QTableWidgetItem(entry.name)
        nameItem.setFlags(nameItem.flags() & ~QtCore.Qt.ItemFlag.ItemIsEditable)
        summaryItem = QtWidgets.QTableWidgetItem(entry.preview.summary)
        summaryItem.setFlags(summaryItem.flags() & ~QtCore.Qt.ItemFlag.ItemIsEditable)
        self.streamTable.setItem(rowIndex, 1, nameItem)
        self.streamTable.setItem(rowIndex, 2, summaryItem)
        self.streamTable.setCellWidget(rowIndex, 3, self._build_mac_editor(entry, "src", entry.sourceMac))
        self.streamTable.setCellWidget(rowIndex, 4, self._build_mac_editor(entry, "dst", entry.destinationMac))

    def _build_mac_editor(
        self,
        entry: StreamTemplateEntry,
        fieldName: str,
        value: str,
    ) -> QtWidgets.QWidget:
        lineEdit = QtWidgets.QLineEdit(value)
        lineEdit.setPlaceholderText("无 Ether 层" if not entry.hasEtherLayer else "00:11:22:33:44:55")
        lineEdit.setEnabled(entry.hasEtherLayer and self.workerThread is None)
        if entry.hasEtherLayer:
            lineEdit.editingFinished.connect(
                lambda templateId=entry.templateId, targetField=fieldName, editor=lineEdit: self._apply_mac_edit(
                    templateId,
                    targetField,
                    editor,
                )
            )
        return lineEdit

    def _handle_stream_enabled_changed(self, templateId: int, state: int) -> None:
        entry = self._find_stream(templateId)
        if entry is None:
            return
        entry.enabled = state == int(QtCore.Qt.CheckState.Checked.value)
        self._set_running_state(self.workerThread is not None)

    def _apply_mac_edit(
        self,
        templateId: int,
        fieldName: str,
        editor: QtWidgets.QLineEdit,
    ) -> None:
        entry = self._find_stream(templateId)
        if entry is None:
            return
        value = editor.text().strip()
        if not value:
            editor.setText(entry.sourceMac if fieldName == "src" else entry.destinationMac)
            return
        if self._MAC_PATTERN.match(value) is None:
            self.statusLabel.setText("MAC 地址格式无效，请使用 00:11:22:33:44:55。")
            editor.setText(entry.sourceMac if fieldName == "src" else entry.destinationMac)
            return
        etherLayer = self._extract_ether_layer(entry.packet)
        if etherLayer is None:
            self.statusLabel.setText("当前流模板不包含 Ether 层，无法修改 MAC 地址。")
            return
        setattr(etherLayer, fieldName, value)
        entry.preview = self.sendTaskService.buildPacketPreview(entry.packet) or entry.preview
        entry.sourceMac, entry.destinationMac, entry.hasEtherLayer = self._extract_mac_fields(entry.packet)
        self.statusLabel.setText(f"已更新 {entry.name} 的 MAC 地址。")
        self._refresh_stream_table(selectedTemplateId=templateId)

    def _set_all_streams_enabled(self, enabled: bool) -> None:
        for entry in self.streamTemplates:
            entry.enabled = enabled
        self._refresh_stream_table()

    def _handle_remove_selected_stream(self) -> None:
        entry = self._current_selected_stream()
        if entry is None:
            return
        self.streamTemplates = [streamEntry for streamEntry in self.streamTemplates if streamEntry.templateId != entry.templateId]
        self.statusLabel.setText(f"已移除流模板: {entry.name}")
        self._refresh_stream_table()

    def _handle_edit_selected_stream(self) -> None:
        entry = self._current_selected_stream()
        if entry is None:
            self.statusLabel.setText("请先选中要跳转编辑的流模板。")
            return
        packet = entry.packet.copy() if hasattr(entry.packet, "copy") else entry.packet
        self.editPacketRequested.emit(packet)
        self.statusMessage.emit(f"跳转到包构建器编辑: {entry.name}")

    def _handle_stream_selection_changed(self) -> None:
        self._sync_preview_with_selection()
        self._set_running_state(self.workerThread is not None)

    def _sync_preview_with_selection(self) -> None:
        entry = self._current_selected_stream()
        if entry is None:
            self.packetSummaryEdit.setText("当前没有可发送的流模板。")
            self.packetStructureEdit.setPlainText("请先在包构建器中创建流模板。")
            self.packetHexdumpEdit.setPlainText("")
            return
        self._apply_preview(entry.preview)

    def _apply_preview(self, preview: PacketPreview) -> None:
        self.packetSummaryEdit.setText(preview.summary)
        self.packetStructureEdit.setPlainText(preview.structure)
        self.packetHexdumpEdit.setPlainText(preview.hexdump)

    def _selected_packets(self) -> list[Any]:
        packets: list[Any] = []
        for entry in self.streamTemplates:
            if not entry.enabled:
                continue
            packets.append(entry.packet.copy() if hasattr(entry.packet, "copy") else entry.packet)
        return packets

    def _current_selected_stream(self) -> StreamTemplateEntry | None:
        selectedItems = self.streamTable.selectedItems()
        if not selectedItems:
            return None
        rowIndex = selectedItems[0].row()
        if rowIndex < 0 or rowIndex >= len(self.streamTemplates):
            return None
        return self.streamTemplates[rowIndex]

    def _find_stream(self, templateId: int) -> StreamTemplateEntry | None:
        for entry in self.streamTemplates:
            if entry.templateId == templateId:
                return entry
        return None

    def _extract_ether_layer(self, packet: Any) -> Any | None:
        if packet is None or not hasattr(packet, "haslayer") or not hasattr(packet, "getlayer"):
            return None
        try:
            if packet.haslayer("Ether"):
                return packet.getlayer("Ether")
        except Exception:
            return None
        return None

    def _extract_mac_fields(self, packet: Any) -> tuple[str, str, bool]:
        etherLayer = self._extract_ether_layer(packet)
        if etherLayer is None:
            return "", "", False
        return (
            str(getattr(etherLayer, "src", "") or ""),
            str(getattr(etherLayer, "dst", "") or ""),
            True,
        )
