from __future__ import annotations

from PySide6 import QtCore, QtWidgets

from packet_studio.domain.task_models import TaskState
from packet_studio.domain.workspace_models import WorkspacePanelSnapshot
from packet_studio.services.tool_registry_service import ToolRegistration, ToolRegistryService


class AutomationToolsWidget(QtWidgets.QWidget):
    """最小自动化工具入口页。"""

    openToolRequested = QtCore.Signal(str)
    statusMessage = QtCore.Signal(str)

    def __init__(self, parent: QtWidgets.QWidget | None = None) -> None:
        super().__init__(parent)
        self.toolRegistryService = ToolRegistryService()
        self.currentTaskState = TaskState.idle("请选择一个工具入口。")
        self._setup_ui()
        self._populate_tools()

    def buildWorkspaceSnapshot(self) -> WorkspacePanelSnapshot:
        return WorkspacePanelSnapshot(
            panelId="automation-tools",
            title="自动化工具",
            taskState=self.currentTaskState,
            itemCount=self.toolList.topLevelItemCount(),
            detailText=self.statusLabel.text(),
        )

    def _setup_ui(self) -> None:
        rootLayout = QtWidgets.QVBoxLayout(self)

        titleLabel = QtWidgets.QLabel("自动化工具")
        titleLabel.setStyleSheet("font-size: 22px; font-weight: 700;")
        subtitleLabel = QtWidgets.QLabel(
            "当前阶段先提供最小工具注册入口。后续可在这里接入插件发现、专题协议工具页和自动机向导。"
        )
        subtitleLabel.setWordWrap(True)

        self.toolList = QtWidgets.QTreeWidget()
        self.toolList.setHeaderLabels(["工具", "分类", "说明"])
        self.toolList.header().setStretchLastSection(True)
        self.toolList.itemSelectionChanged.connect(self._handle_selection_changed)

        actionLayout = QtWidgets.QHBoxLayout()
        self.openToolButton = QtWidgets.QPushButton("打开选中工具")
        self.openToolButton.clicked.connect(self._handle_open_tool)
        self.statusLabel = QtWidgets.QLabel("请选择一个工具入口。")
        self.statusLabel.setWordWrap(True)
        actionLayout.addWidget(self.openToolButton)
        actionLayout.addWidget(self.statusLabel, 1)

        rootLayout.addWidget(titleLabel)
        rootLayout.addWidget(subtitleLabel)
        rootLayout.addWidget(self.toolList, 1)
        rootLayout.addLayout(actionLayout)

    def _populate_tools(self) -> None:
        self.toolList.clear()
        for tool in self.toolRegistryService.listTools():
            item = QtWidgets.QTreeWidgetItem([tool.title, tool.category, tool.description])
            item.setData(0, QtCore.Qt.ItemDataRole.UserRole, tool.targetTabTitle)
            self.toolList.addTopLevelItem(item)
        if self.toolList.topLevelItemCount() > 0:
            self.toolList.setCurrentItem(self.toolList.topLevelItem(0))
        self._update_button_state()

    def _handle_selection_changed(self) -> None:
        selectedItems = self.toolList.selectedItems()
        if not selectedItems:
            self.statusLabel.setText("请选择一个工具入口。")
            self.currentTaskState = TaskState.idle(self.statusLabel.text())
            self._update_button_state()
            return

        selectedTitle = selectedItems[0].text(0)
        self.statusLabel.setText(f"已选择工具: {selectedTitle}")
        self.currentTaskState = TaskState.idle(self.statusLabel.text())
        self._update_button_state()

    def _handle_open_tool(self) -> None:
        selectedItems = self.toolList.selectedItems()
        if not selectedItems:
            self.statusLabel.setText("请先选择一个工具入口。")
            return

        targetTabTitle = str(selectedItems[0].data(0, QtCore.Qt.ItemDataRole.UserRole))
        self.openToolRequested.emit(targetTabTitle)
        self.statusLabel.setText(f"正在打开工具: {selectedItems[0].text(0)}")
        self.currentTaskState = TaskState.running(self.statusLabel.text())
        self.statusMessage.emit(f"从自动化工具页打开: {selectedItems[0].text(0)}")

    def _update_button_state(self) -> None:
        self.openToolButton.setEnabled(bool(self.toolList.selectedItems()))