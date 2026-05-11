from __future__ import annotations

import collections
from typing import Optional

from PySide6 import QtCore, QtGui, QtWidgets

from packet_studio.domain.packet_models import PcapPacketRecord
from packet_studio.domain.task_models import PcapLoadResult, TaskError, TaskState
from packet_studio.domain.workspace_models import WorkspacePanelSnapshot
from packet_studio.services.pcap_analysis_service import (
    PcapAnalysisService,
)


class OfflineAnalysisWorker(QtCore.QObject):
    finished = QtCore.Signal(object)
    failed = QtCore.Signal(object)

    def __init__(
        self,
        pcapAnalysisService: PcapAnalysisService,
        filePath: str,
        maxPackets: int,
    ) -> None:
        super().__init__()
        self.pcapAnalysisService = pcapAnalysisService
        self.filePath = filePath
        self.maxPackets = maxPackets

    @QtCore.Slot()
    def run(self) -> None:
        try:
            result = self.pcapAnalysisService.loadPackets(self.filePath, self.maxPackets)
        except Exception as exc:
            self.failed.emit(TaskError(message=str(exc), logText=str(exc)))
            return
        self.finished.emit(result)


class OfflineAnalysisWidget(QtWidgets.QWidget):
    """最小离线 pcap 分析工作台。"""

    statusMessage = QtCore.Signal(str)
    importPacketRequested = QtCore.Signal(object)

    def __init__(self, parent: QtWidgets.QWidget | None = None) -> None:
        super().__init__(parent)
        self.pcapAnalysisService = PcapAnalysisService()
        self.packetRecords: list[PcapPacketRecord] = []
        self.visiblePacketIndexes: list[int] = []
        self.currentFilePath = ""
        self.workerThread: Optional[QtCore.QThread] = None
        self.worker: Optional[OfflineAnalysisWorker] = None
        self.currentTaskState = TaskState.idle("准备就绪。")

        self._setup_ui()
        self._update_button_state()

    def isLoading(self) -> bool:
        return self.workerThread is not None

    def closeEvent(self, event: QtGui.QCloseEvent) -> None:
        if self.isLoading():
            QtWidgets.QMessageBox.warning(
                self,
                "离线分析仍在加载",
                "请等待当前离线加载完成后再关闭窗口。",
            )
            event.ignore()
            return
        super().closeEvent(event)

    def buildWorkspaceSnapshot(self) -> WorkspacePanelSnapshot:
        detailText = self.currentFilePath or self.summaryLabel.text()
        return WorkspacePanelSnapshot(
            panelId="offline-analysis",
            title="离线分析",
            taskState=self.currentTaskState,
            itemCount=len(self.packetRecords),
            detailText=detailText,
        )

    def _setup_ui(self) -> None:
        rootLayout = QtWidgets.QVBoxLayout(self)

        controlsLayout = QtWidgets.QGridLayout()
        controlsLayout.addWidget(QtWidgets.QLabel("文件"), 0, 0)
        self.filePathEdit = QtWidgets.QLineEdit()
        self.filePathEdit.setReadOnly(True)
        controlsLayout.addWidget(self.filePathEdit, 0, 1, 1, 3)

        controlsLayout.addWidget(QtWidgets.QLabel("读取上限"), 1, 0)
        self.maxPacketsSpin = QtWidgets.QSpinBox()
        self.maxPacketsSpin.setRange(1, 1000000)
        self.maxPacketsSpin.setValue(500)
        controlsLayout.addWidget(self.maxPacketsSpin, 1, 1)

        controlsLayout.addWidget(QtWidgets.QLabel("显示过滤"), 1, 2)
        self.searchEdit = QtWidgets.QLineEdit()
        self.searchEdit.setPlaceholderText("按摘要、时间、接口、协议关键字搜索")
        self.searchEdit.textChanged.connect(self._handle_search_changed)
        controlsLayout.addWidget(self.searchEdit, 1, 3)

        actionLayout = QtWidgets.QHBoxLayout()
        self.openFileButton = QtWidgets.QPushButton("打开 pcap")
        self.reloadButton = QtWidgets.QPushButton("重新加载")
        self.copyToBuilderButton = QtWidgets.QPushButton("复制到包构建器")
        self.statusLabel = QtWidgets.QLabel("准备就绪。")
        self.statusLabel.setWordWrap(True)
        self.openFileButton.clicked.connect(self._handle_open_file)
        self.reloadButton.clicked.connect(self._handle_reload)
        self.copyToBuilderButton.clicked.connect(self._handle_copy_to_builder)
        actionLayout.addWidget(self.openFileButton)
        actionLayout.addWidget(self.reloadButton)
        actionLayout.addWidget(self.copyToBuilderButton)
        actionLayout.addWidget(self.statusLabel, 1)

        contentSplitter = QtWidgets.QSplitter(QtCore.Qt.Orientation.Horizontal)

        tablePane = QtWidgets.QWidget()
        tableLayout = QtWidgets.QVBoxLayout(tablePane)
        self.summaryLabel = QtWidgets.QLabel("尚未打开离线抓包文件。")
        self.summaryLabel.setWordWrap(True)
        tableLayout.addWidget(self.summaryLabel)
        self.statsLabel = QtWidgets.QLabel("")
        self.statsLabel.setWordWrap(True)
        tableLayout.addWidget(self.statsLabel)
        self.packetTable = QtWidgets.QTableWidget(0, 4)
        self.packetTable.setHorizontalHeaderLabels(["序号", "时间", "接口", "摘要"])
        self.packetTable.setEditTriggers(QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers)
        self.packetTable.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows)
        self.packetTable.setSelectionMode(QtWidgets.QAbstractItemView.SelectionMode.SingleSelection)
        self.packetTable.verticalHeader().setVisible(False)
        self.packetTable.horizontalHeader().setStretchLastSection(True)
        self.packetTable.itemSelectionChanged.connect(self._handle_packet_selection_changed)
        tableLayout.addWidget(self.packetTable, 1)

        detailPane = QtWidgets.QWidget()
        detailLayout = QtWidgets.QVBoxLayout(detailPane)
        self.packetDetailSummary = QtWidgets.QLineEdit()
        self.packetDetailSummary.setReadOnly(True)
        detailLayout.addWidget(self.packetDetailSummary)
        detailTabs = QtWidgets.QTabWidget()
        self.packetStructureEdit = QtWidgets.QPlainTextEdit()
        self.packetStructureEdit.setReadOnly(True)
        self.packetHexdumpEdit = QtWidgets.QPlainTextEdit()
        self.packetHexdumpEdit.setReadOnly(True)
        detailTabs.addTab(self.packetStructureEdit, "结构")
        detailTabs.addTab(self.packetHexdumpEdit, "十六进制")
        detailLayout.addWidget(detailTabs, 1)

        contentSplitter.addWidget(tablePane)
        contentSplitter.addWidget(detailPane)
        contentSplitter.setStretchFactor(0, 1)
        contentSplitter.setStretchFactor(1, 1)

        rootLayout.addLayout(controlsLayout)
        rootLayout.addLayout(actionLayout)
        rootLayout.addWidget(contentSplitter, 1)

    def _handle_open_file(self) -> None:
        filePath, _ = QtWidgets.QFileDialog.getOpenFileName(
            self,
            "打开离线抓包文件",
            "",
            "Capture Files (*.pcap *.pcapng *.cap *.pcap.gz *.pcapng.gz);;All Files (*)",
        )
        if not filePath:
            return
        self._start_loading(filePath)

    def _handle_reload(self) -> None:
        if not self.currentFilePath:
            self.statusLabel.setText("请先打开一个离线抓包文件。")
            return
        self._start_loading(self.currentFilePath)

    def _handle_copy_to_builder(self) -> None:
        selectedItems = self.packetTable.selectedItems()
        if not selectedItems:
            self.statusLabel.setText("请先选择一个离线数据包。")
            return

        rowIndex = int(selectedItems[0].data(QtCore.Qt.ItemDataRole.UserRole))
        record = self.packetRecords[rowIndex]
        self.importPacketRequested.emit(record.packet.copy())
        self.statusLabel.setText("已将选中离线数据包发送到包构建器。")
        self.statusMessage.emit("已将选中离线数据包复制到包构建器。")

    def _handle_search_changed(self, _text: str) -> None:
        self._rebuild_packet_table()

    def _start_loading(self, filePath: str) -> None:
        if self.isLoading():
            self.statusLabel.setText("离线文件仍在加载中，请稍候。")
            return

        self.currentFilePath = filePath
        self.filePathEdit.setText(filePath)
        self._apply_task_state(TaskState.running("正在后台加载离线抓包文件..."))
        self.summaryLabel.setText("正在读取离线抓包文件...")
        self._set_loading_state(True)

        thread = QtCore.QThread(self)
        worker = OfflineAnalysisWorker(
            self.pcapAnalysisService,
            filePath,
            int(self.maxPacketsSpin.value()),
        )
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.finished.connect(self._on_load_finished)
        worker.failed.connect(self._on_load_failed)
        worker.finished.connect(thread.quit)
        worker.failed.connect(thread.quit)
        thread.finished.connect(worker.deleteLater)
        thread.finished.connect(self._on_thread_finished)

        self.workerThread = thread
        self.worker = worker
        thread.start()

    @QtCore.Slot(object)
    def _on_load_finished(self, result: PcapLoadResult) -> None:
        self.currentFilePath = result.filePath
        self.filePathEdit.setText(result.filePath)
        self.packetRecords = list(result.packetRecords)
        self.packetDetailSummary.clear()
        self.packetStructureEdit.clear()
        self.packetHexdumpEdit.clear()
        self._rebuild_packet_table()
        self._apply_task_state(result.state)
        self.statusMessage.emit(result.summaryText)

    @QtCore.Slot(object)
    def _on_load_failed(self, error: TaskError) -> None:
        self.packetRecords = []
        self.packetTable.clearContents()
        self.packetTable.setRowCount(0)
        self.packetDetailSummary.clear()
        self.packetStructureEdit.clear()
        self.packetHexdumpEdit.clear()
        self.summaryLabel.setText(f"离线抓包文件加载失败: {error.summaryText}")
        self.statsLabel.clear()
        self._apply_task_state(error.state)
        self.statusMessage.emit(f"离线抓包文件加载失败: {error.summaryText}")

    def _on_thread_finished(self) -> None:
        self.workerThread = None
        self.worker = None
        self._set_loading_state(False)
        self._update_button_state()

    def _handle_packet_selection_changed(self) -> None:
        selectedItems = self.packetTable.selectedItems()
        self._update_button_state()
        if not selectedItems:
            return
        sourceIndex = int(selectedItems[0].data(QtCore.Qt.ItemDataRole.UserRole))
        record = self.packetRecords[sourceIndex]
        self.packetDetailSummary.setText(record.preview.summary)
        self.packetStructureEdit.setPlainText(record.preview.structure)
        self.packetHexdumpEdit.setPlainText(record.preview.hexdump)

    def _set_loading_state(self, isLoading: bool) -> None:
        self.openFileButton.setEnabled(not isLoading)
        self.reloadButton.setEnabled(not isLoading and bool(self.currentFilePath))
        self.maxPacketsSpin.setEnabled(not isLoading)
        self.packetTable.setEnabled(not isLoading)

    def _update_button_state(self) -> None:
        hasSelection = self.packetTable.currentRow() >= 0
        isLoading = self.isLoading()
        self.copyToBuilderButton.setEnabled(hasSelection and not isLoading)
        self.reloadButton.setEnabled((not isLoading) and bool(self.currentFilePath))

    def _apply_task_state(self, state: TaskState) -> None:
        self.currentTaskState = state
        self.statusLabel.setText(state.statusText)

    def _rebuild_packet_table(self) -> None:
        previousSourceIndex = self._current_selected_source_index()
        self.visiblePacketIndexes = self._filtered_packet_indexes()
        self.packetTable.clearContents()
        self.packetTable.setRowCount(len(self.visiblePacketIndexes))

        for rowIndex, sourceIndex in enumerate(self.visiblePacketIndexes):
            record = self.packetRecords[sourceIndex]
            values = [
                str(record.index),
                record.timestampText,
                record.sourceText,
                record.summary,
            ]
            for columnIndex, value in enumerate(values):
                item = QtWidgets.QTableWidgetItem(value)
                item.setData(QtCore.Qt.ItemDataRole.UserRole, sourceIndex)
                self.packetTable.setItem(rowIndex, columnIndex, item)

        self._refresh_summary_labels()

        if not self.visiblePacketIndexes:
            self.packetDetailSummary.clear()
            self.packetStructureEdit.clear()
            self.packetHexdumpEdit.clear()
            return

        if previousSourceIndex in self.visiblePacketIndexes:
            self.packetTable.selectRow(self.visiblePacketIndexes.index(previousSourceIndex))
            return

        self.packetTable.selectRow(0)

    def _filtered_packet_indexes(self) -> list[int]:
        query = self.searchEdit.text().strip().lower()
        if not query:
            return list(range(len(self.packetRecords)))

        visibleIndexes = []
        for index, record in enumerate(self.packetRecords):
            haystack = "\n".join([
                record.summary,
                record.timestampText,
                record.sourceText,
                record.protocolName,
            ]).lower()
            if query in haystack:
                visibleIndexes.append(index)
        return visibleIndexes

    def _refresh_summary_labels(self) -> None:
        totalCount = len(self.packetRecords)
        visibleCount = len(self.visiblePacketIndexes)
        if totalCount == 0:
            self.summaryLabel.setText("尚未打开离线抓包文件。")
            self.statsLabel.clear()
            return

        if visibleCount == totalCount:
            self.summaryLabel.setText(
                f"已从 {self.currentFilePath} 读取 {totalCount} 个数据包。"
            )
        else:
            self.summaryLabel.setText(
                f"已从 {self.currentFilePath} 读取 {totalCount} 个数据包，当前显示 {visibleCount} 个。"
            )

        counter = collections.Counter(
            self.packetRecords[index].protocolName
            for index in self.visiblePacketIndexes
        )
        statsText = "、".join(
            f"{protocol}: {count}" for protocol, count in counter.most_common(4)
        )
        self.statsLabel.setText(f"基础统计: {statsText}" if statsText else "")

    def _current_selected_source_index(self) -> int | None:
        selectedItems = self.packetTable.selectedItems()
        if not selectedItems:
            return None
        return int(selectedItems[0].data(QtCore.Qt.ItemDataRole.UserRole))
