from __future__ import annotations

import ast
import ipaddress
import re
from pathlib import Path

from PySide6 import QtCore, QtGui, QtWidgets

from packet_studio.domain.task_models import TaskState
from packet_studio.domain.workspace_models import WorkspacePanelSnapshot
from packet_studio.services.packet_builder_service import AvailableLayer, LayerFieldRecord, PacketBuilderService


class LayerListWidget(QtWidgets.QListWidget):
    orderChanged = QtCore.Signal()

    def __init__(self, parent: QtWidgets.QWidget | None = None) -> None:
        super().__init__(parent)
        self.setDragDropMode(QtWidgets.QAbstractItemView.DragDropMode.InternalMove)
        self.setDefaultDropAction(QtCore.Qt.DropAction.MoveAction)

    def dropEvent(self, event: QtGui.QDropEvent) -> None:
        super().dropEvent(event)
        self.orderChanged.emit()


class PacketBuilderWidget(QtWidgets.QWidget):
    """最小可用包构建器。"""

    packetChanged = QtCore.Signal(object)
    createStreamRequested = QtCore.Signal(object)
    saveStreamRequested = QtCore.Signal(object)

    def __init__(self, parent: QtWidgets.QWidget | None = None) -> None:
        super().__init__(parent)
        self.packetBuilderService = PacketBuilderService()
        self._availableLayers = self.packetBuilderService.listAvailableLayers()
        self._updatingFieldTable = False
        self._filteredFieldNames: list[str] = []
        self._visibleFieldRecords: dict[str, LayerFieldRecord] = {}
        self._editingStreamMode = False

        self._setup_ui()
        self._refresh_all()

    def getCurrentPacket(self) -> object | None:
        packet = self.packetBuilderService.buildPacket()
        if packet is None:
            return None
        return packet.copy()

    def buildWorkspaceSnapshot(self) -> WorkspacePanelSnapshot:
        statusText = self.builderStatusLabel.text()
        taskState = TaskState.failed(statusText) if "失败" in statusText else TaskState.idle(statusText)
        return WorkspacePanelSnapshot(
            panelId="packet-builder",
            title="包构建器",
            taskState=taskState,
            itemCount=len(self.packetBuilderService.getLayerRecords()),
            detailText=self.summaryEdit.text(),
        )

    def loadPacket(self, packet: object) -> None:
        try:
            self.packetBuilderService.importPacket(packet)
        except Exception as exc:
            self.builderStatusLabel.setText(f"导入数据包失败: {exc}")
            raise

        self.builderStatusLabel.setText("已导入当前数据包。")
        self._refresh_all(selectLast=False, selectedRow=0)

    def _setup_ui(self) -> None:
        rootLayout = QtWidgets.QVBoxLayout(self)

        controlsLayout = QtWidgets.QHBoxLayout()
        self.layerCategoryCombo = QtWidgets.QComboBox()
        self.layerCategoryCombo.addItem("全部", "全部")
        for category in self.packetBuilderService.listAvailableLayerCategories():
            self.layerCategoryCombo.addItem(category, category)
        self.layerTypeCombo = QtWidgets.QComboBox()
        self.layerTypeCombo.setEditable(True)
        self.layerTypeCombo.setInsertPolicy(QtWidgets.QComboBox.InsertPolicy.NoInsert)
        self.layerCategoryCombo.currentIndexChanged.connect(self._handle_layer_category_changed)
        self._rebuild_layer_type_combo(preferredKey="ip")

        self.addLayerButton = QtWidgets.QPushButton("添加层")
        self.removeLayerButton = QtWidgets.QPushButton("删除选中层")
        self.moveLayerUpButton = QtWidgets.QPushButton("上移")
        self.moveLayerDownButton = QtWidgets.QPushButton("下移")
        self.createStreamButton = QtWidgets.QPushButton("创建流")
        self.saveStreamButton = QtWidgets.QPushButton("保存到当前流")
        self.saveTemplateButton = QtWidgets.QPushButton("保存模板")
        self.loadTemplateButton = QtWidgets.QPushButton("加载模板")
        self.resetButton = QtWidgets.QPushButton("重置")
        self.builderStatusLabel = QtWidgets.QLabel("准备就绪。")
        self.builderStatusLabel.setWordWrap(True)

        self.addLayerButton.clicked.connect(self._handle_add_layer)
        self.removeLayerButton.clicked.connect(self._handle_remove_layer)
        self.moveLayerUpButton.clicked.connect(self._handle_move_layer_up)
        self.moveLayerDownButton.clicked.connect(self._handle_move_layer_down)
        self.createStreamButton.clicked.connect(self._handle_create_stream)
        self.saveStreamButton.clicked.connect(self._handle_save_stream)
        self.saveTemplateButton.clicked.connect(self._handle_save_template)
        self.loadTemplateButton.clicked.connect(self._handle_load_template)
        self.resetButton.clicked.connect(self._handle_reset)

        controlsLayout.addWidget(QtWidgets.QLabel("分类"))
        controlsLayout.addWidget(self.layerCategoryCombo)
        controlsLayout.addWidget(QtWidgets.QLabel("层类型"))
        controlsLayout.addWidget(self.layerTypeCombo)
        controlsLayout.addWidget(self.addLayerButton)
        controlsLayout.addWidget(self.removeLayerButton)
        controlsLayout.addWidget(self.moveLayerUpButton)
        controlsLayout.addWidget(self.moveLayerDownButton)
        controlsLayout.addWidget(self.createStreamButton)
        controlsLayout.addWidget(self.saveStreamButton)
        controlsLayout.addWidget(self.saveTemplateButton)
        controlsLayout.addWidget(self.loadTemplateButton)
        controlsLayout.addWidget(self.resetButton)
        controlsLayout.addWidget(self.builderStatusLabel, 1)

        contentSplitter = QtWidgets.QSplitter(QtCore.Qt.Orientation.Horizontal)

        leftPane = QtWidgets.QWidget()
        leftLayout = QtWidgets.QVBoxLayout(leftPane)
        leftLayout.addWidget(QtWidgets.QLabel("当前协议层"))
        self.layerList = LayerListWidget()
        self.layerList.currentRowChanged.connect(self._handle_layer_selection_changed)
        self.layerList.orderChanged.connect(self._handle_layer_reordered)
        leftLayout.addWidget(self.layerList, 1)

        middlePane = QtWidgets.QWidget()
        middleLayout = QtWidgets.QVBoxLayout(middlePane)
        middleLayout.addWidget(QtWidgets.QLabel("字段编辑"))
        self.fieldSearchEdit = QtWidgets.QLineEdit()
        self.fieldSearchEdit.setPlaceholderText("搜索字段名或字段类型")
        self.fieldSearchEdit.textChanged.connect(self._handle_field_search_changed)
        middleLayout.addWidget(self.fieldSearchEdit)
        self.fieldTable = QtWidgets.QTableWidget(0, 4)
        self.fieldTable.setHorizontalHeaderLabels(["字段", "类型", "默认值", "当前值"])
        self.fieldTable.verticalHeader().setVisible(False)
        self.fieldTable.horizontalHeader().setStretchLastSection(True)
        self.fieldTable.setSelectionBehavior(
            QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows
        )
        self.fieldTable.itemChanged.connect(self._handle_field_item_changed)
        middleLayout.addWidget(self.fieldTable, 1)

        self.rawPayloadGroup = QtWidgets.QGroupBox("Raw Payload 编辑")
        rawPayloadLayout = QtWidgets.QVBoxLayout(self.rawPayloadGroup)
        rawPayloadHint = QtWidgets.QLabel(
            "当选中 Raw 层时，可在这里用多行文本编辑 load 字段。"
        )
        rawPayloadHint.setWordWrap(True)
        self.rawPayloadEdit = QtWidgets.QPlainTextEdit()
        self.applyRawPayloadButton = QtWidgets.QPushButton("应用 Payload")
        self.applyRawPayloadButton.clicked.connect(self._handle_apply_raw_payload)
        rawPayloadLayout.addWidget(rawPayloadHint)
        rawPayloadLayout.addWidget(self.rawPayloadEdit, 1)
        rawPayloadLayout.addWidget(self.applyRawPayloadButton)
        self.rawPayloadGroup.setVisible(False)
        middleLayout.addWidget(self.rawPayloadGroup)

        rightPane = QtWidgets.QWidget()
        rightLayout = QtWidgets.QVBoxLayout(rightPane)
        rightLayout.addWidget(QtWidgets.QLabel("摘要"))
        self.summaryEdit = QtWidgets.QLineEdit()
        self.summaryEdit.setReadOnly(True)
        rightLayout.addWidget(self.summaryEdit)

        previewTabs = QtWidgets.QTabWidget()
        self.structureEdit = QtWidgets.QPlainTextEdit()
        self.structureEdit.setReadOnly(True)
        self.hexdumpEdit = QtWidgets.QPlainTextEdit()
        self.hexdumpEdit.setReadOnly(True)
        previewTabs.addTab(self.structureEdit, "结构")
        previewTabs.addTab(self.hexdumpEdit, "十六进制")
        rightLayout.addWidget(previewTabs, 1)

        contentSplitter.addWidget(leftPane)
        contentSplitter.addWidget(middlePane)
        contentSplitter.addWidget(rightPane)
        contentSplitter.setStretchFactor(0, 0)
        contentSplitter.setStretchFactor(1, 1)
        contentSplitter.setStretchFactor(2, 1)

        rootLayout.addLayout(controlsLayout)
        rootLayout.addWidget(contentSplitter, 1)
        self._update_stream_buttons()

    def setEditingStreamMode(self, isEditing: bool) -> None:
        self._editingStreamMode = isEditing
        self._update_stream_buttons()

    def _handle_add_layer(self) -> None:
        layerKey = self._resolve_selected_layer_key()
        if layerKey is None:
            self.builderStatusLabel.setText("请选择有效的协议层。")
            return
        self.packetBuilderService.addLayer(layerKey)
        self.builderStatusLabel.setText(f"已添加协议层: {self.layerTypeCombo.currentText()}")
        self._refresh_all(selectLast=True)

    def _resolve_selected_layer_key(self) -> str | None:
        currentText = self.layerTypeCombo.currentText().strip()
        currentIndex = self.layerTypeCombo.currentIndex()

        if currentIndex >= 0 and self.layerTypeCombo.itemText(currentIndex) == currentText:
            currentData = self.layerTypeCombo.itemData(currentIndex)
            if isinstance(currentData, str) and currentData:
                return currentData

        normalizedText = currentText.casefold()
        for itemIndex in range(self.layerTypeCombo.count()):
            if self.layerTypeCombo.itemText(itemIndex).casefold() != normalizedText:
                continue
            self.layerTypeCombo.setCurrentIndex(itemIndex)
            currentData = self.layerTypeCombo.itemData(itemIndex)
            if isinstance(currentData, str) and currentData:
                return currentData

        return None

    def _handle_layer_category_changed(self) -> None:
        self._rebuild_layer_type_combo()

    def _rebuild_layer_type_combo(self, preferredKey: str | None = None) -> None:
        currentKey = preferredKey or self._resolve_combo_selected_key(self.layerTypeCombo)
        selectedCategory = str(self.layerCategoryCombo.currentData() or "全部")
        visibleLayers = self._filter_layers_by_category(selectedCategory)

        self.layerTypeCombo.blockSignals(True)
        self.layerTypeCombo.clear()
        defaultIndex = 0
        for index, layer in enumerate(visibleLayers):
            self.layerTypeCombo.addItem(layer.label, layer.key)
            if layer.key == currentKey:
                defaultIndex = index
            elif currentKey is None and layer.key == "ip":
                defaultIndex = index
        if self.layerTypeCombo.count() > 0:
            self.layerTypeCombo.setCurrentIndex(defaultIndex)
        self.layerTypeCombo.blockSignals(False)
        self.layerTypeCombo.lineEdit().setPlaceholderText("搜索协议层")
        self._install_contains_completer(self.layerTypeCombo)

    def _filter_layers_by_category(self, category: str) -> list[AvailableLayer]:
        if category == "全部":
            return list(self._availableLayers)
        return [layer for layer in self._availableLayers if layer.category == category]

    def _resolve_combo_selected_key(self, comboBox: QtWidgets.QComboBox) -> str | None:
        currentIndex = comboBox.currentIndex()
        if currentIndex < 0:
            return None
        currentData = comboBox.itemData(currentIndex)
        if isinstance(currentData, str) and currentData:
            return currentData
        return None

    def _install_contains_completer(self, comboBox: QtWidgets.QComboBox) -> None:
        completer = QtWidgets.QCompleter(
            [comboBox.itemText(index) for index in range(comboBox.count())],
            comboBox,
        )
        completer.setCaseSensitivity(QtCore.Qt.CaseSensitivity.CaseInsensitive)
        completer.setFilterMode(QtCore.Qt.MatchFlag.MatchContains)
        comboBox.setCompleter(completer)

    def _handle_remove_layer(self) -> None:
        layerIndex = self.layerList.currentRow()
        if layerIndex < 0:
            self.builderStatusLabel.setText("请先选择要删除的协议层。")
            return
        self.packetBuilderService.removeLayer(layerIndex)
        self.builderStatusLabel.setText("已删除选中协议层。")
        self._refresh_all()

    def _handle_move_layer_up(self) -> None:
        layerIndex = self.layerList.currentRow()
        if layerIndex <= 0:
            self.builderStatusLabel.setText("当前协议层已经在最上方。")
            return
        self.packetBuilderService.moveLayer(layerIndex, layerIndex - 1)
        self.builderStatusLabel.setText("已上移选中协议层。")
        self._refresh_all(selectedRow=layerIndex - 1)

    def _handle_move_layer_down(self) -> None:
        layerIndex = self.layerList.currentRow()
        if layerIndex < 0 or layerIndex >= self.layerList.count() - 1:
            self.builderStatusLabel.setText("当前协议层已经在最下方。")
            return
        self.packetBuilderService.moveLayer(layerIndex, layerIndex + 1)
        self.builderStatusLabel.setText("已下移选中协议层。")
        self._refresh_all(selectedRow=layerIndex + 1)

    def _handle_reset(self) -> None:
        self.packetBuilderService.reset()
        self.builderStatusLabel.setText("包构建器已重置。")
        self._refresh_all()

    def _handle_create_stream(self) -> None:
        packet = self.getCurrentPacket()
        if packet is None:
            self.builderStatusLabel.setText("当前没有可创建流模板的数据包。")
            return
        self.createStreamRequested.emit(packet)
        self.builderStatusLabel.setText("已创建流模板，可在发送任务中勾选发送。")

    def _handle_save_stream(self) -> None:
        packet = self.getCurrentPacket()
        if packet is None:
            self.builderStatusLabel.setText("当前没有可保存回流模板的数据包。")
            return
        self.saveStreamRequested.emit(packet)

    def _handle_save_template(self) -> None:
        filePath, _ = QtWidgets.QFileDialog.getSaveFileName(
            self,
            "保存包模板",
            str(Path.home() / "packet-template.json"),
            "JSON Files (*.json)",
        )
        if not filePath:
            return
        self._save_template_to_path(filePath)

    def _handle_load_template(self) -> None:
        filePath, _ = QtWidgets.QFileDialog.getOpenFileName(
            self,
            "加载包模板",
            str(Path.home()),
            "JSON Files (*.json)",
        )
        if not filePath:
            return
        self._load_template_from_path(filePath)

    def _handle_layer_selection_changed(self, _currentRow: int) -> None:
        self._refresh_field_table()
        self._refresh_layer_actions()
        self._refresh_raw_payload_editor()

    def _update_stream_buttons(self) -> None:
        self.saveStreamButton.setEnabled(self._editingStreamMode)

    def _handle_field_search_changed(self, _text: str) -> None:
        self._refresh_field_table()

    def _handle_layer_reordered(self) -> None:
        order = []
        for rowIndex in range(self.layerList.count()):
            item = self.layerList.item(rowIndex)
            order.append(int(item.data(QtCore.Qt.ItemDataRole.UserRole)))
        self.packetBuilderService.reorderLayers(order)
        currentRow = self.layerList.currentRow()
        self.builderStatusLabel.setText("已通过拖拽调整协议层顺序。")
        self._refresh_all(selectedRow=currentRow)

    def _handle_apply_raw_payload(self) -> None:
        layerIndex = self.layerList.currentRow()
        if layerIndex < 0:
            return
        try:
            self.packetBuilderService.setFieldValue(
                layerIndex,
                "load",
                self.rawPayloadEdit.toPlainText(),
            )
        except Exception as exc:
            self.builderStatusLabel.setText(f"Raw Payload 更新失败: {exc}")
            return

        self.builderStatusLabel.setText("已更新 Raw Payload。")
        self._refresh_all(selectedRow=layerIndex)

    def _save_template_to_path(self, filePath: str) -> None:
        try:
            self.packetBuilderService.saveTemplate(filePath)
        except Exception as exc:
            self.builderStatusLabel.setText(f"模板保存失败: {exc}")
            return
        self.builderStatusLabel.setText(f"模板已保存: {filePath}")

    def _load_template_from_path(self, filePath: str) -> None:
        try:
            self.packetBuilderService.loadTemplate(filePath)
        except Exception as exc:
            self.builderStatusLabel.setText(f"模板加载失败: {exc}")
            return
        self.builderStatusLabel.setText(f"模板已加载: {filePath}")
        self._refresh_all()

    def _handle_field_item_changed(self, item: QtWidgets.QTableWidgetItem) -> None:
        if self._updatingFieldTable:
            return
        if item.column() != 3:
            return

        layerIndex = self.layerList.currentRow()
        if layerIndex < 0:
            return

        fieldNameItem = self.fieldTable.item(item.row(), 0)
        if fieldNameItem is None:
            return

        self._apply_field_value(fieldNameItem.text(), item.text())

    def _refresh_all(
        self,
        selectLast: bool = False,
        selectedRow: int | None = None,
    ) -> None:
        self._refresh_layer_list(preserveSelection=not selectLast)
        if selectedRow is not None and 0 <= selectedRow < self.layerList.count():
            self.layerList.setCurrentRow(selectedRow)
        elif selectLast and self.layerList.count() > 0:
            self.layerList.setCurrentRow(self.layerList.count() - 1)
        elif self.layerList.currentRow() < 0 and self.layerList.count() > 0:
            self.layerList.setCurrentRow(0)
        self._refresh_field_table()
        self._refresh_layer_actions()
        self._refresh_raw_payload_editor()
        self._refresh_previews()
        self.removeLayerButton.setEnabled(self.layerList.count() > 0)

    def _refresh_layer_list(self, preserveSelection: bool = False) -> None:
        selectedRow = self.layerList.currentRow()
        self.layerList.clear()
        for layerRecord in self.packetBuilderService.getLayerRecords():
            item = QtWidgets.QListWidgetItem(
                f"{layerRecord.index + 1}. {layerRecord.name}  [{layerRecord.summary}]"
            )
            item.setData(QtCore.Qt.ItemDataRole.UserRole, layerRecord.index)
            self.layerList.addItem(item)
        if preserveSelection and 0 <= selectedRow < self.layerList.count():
            self.layerList.setCurrentRow(selectedRow)

    def _refresh_field_table(self) -> None:
        layerIndex = self.layerList.currentRow()
        self._updatingFieldTable = True
        self.fieldTable.clearContents()
        self._filteredFieldNames = []
        if layerIndex < 0:
            self.fieldTable.setRowCount(0)
            self._visibleFieldRecords = {}
            self._updatingFieldTable = False
            return

        fieldRecords = self.packetBuilderService.getFieldRecords(layerIndex)
        searchText = self.fieldSearchEdit.text().strip().lower()
        if searchText:
            fieldRecords = [
                fieldRecord for fieldRecord in fieldRecords
                if searchText in fieldRecord.name.lower()
                or searchText in fieldRecord.fieldType.lower()
            ]
        self._visibleFieldRecords = {
            fieldRecord.name: fieldRecord for fieldRecord in fieldRecords
        }
        self._filteredFieldNames = [fieldRecord.name for fieldRecord in fieldRecords]
        self.fieldTable.setRowCount(len(fieldRecords))
        for rowIndex, fieldRecord in enumerate(fieldRecords):
            nameItem = QtWidgets.QTableWidgetItem(fieldRecord.name)
            nameItem.setFlags(nameItem.flags() & ~QtCore.Qt.ItemFlag.ItemIsEditable)
            typeItem = QtWidgets.QTableWidgetItem(fieldRecord.fieldType)
            typeItem.setFlags(typeItem.flags() & ~QtCore.Qt.ItemFlag.ItemIsEditable)
            defaultItem = QtWidgets.QTableWidgetItem(fieldRecord.defaultValue)
            defaultItem.setFlags(defaultItem.flags() & ~QtCore.Qt.ItemFlag.ItemIsEditable)
            self.fieldTable.setItem(rowIndex, 0, nameItem)
            self.fieldTable.setItem(rowIndex, 1, typeItem)
            self.fieldTable.setItem(rowIndex, 2, defaultItem)
            self._populate_value_cell(rowIndex, fieldRecord)
        self._updatingFieldTable = False

    def _refresh_layer_actions(self) -> None:
        currentRow = self.layerList.currentRow()
        layerCount = self.layerList.count()
        hasSelection = currentRow >= 0
        self.removeLayerButton.setEnabled(hasSelection)
        self.moveLayerUpButton.setEnabled(hasSelection and currentRow > 0)
        self.moveLayerDownButton.setEnabled(hasSelection and currentRow < layerCount - 1)

    def _refresh_raw_payload_editor(self) -> None:
        layerIndex = self.layerList.currentRow()
        isRawLayer = False
        if layerIndex >= 0:
            layerRecord = self.packetBuilderService.getLayerRecords()[layerIndex]
            isRawLayer = layerRecord.name == "Raw"
        self.rawPayloadGroup.setVisible(isRawLayer)
        if isRawLayer:
            self.rawPayloadEdit.setPlainText(
                self.packetBuilderService.getFieldValue(layerIndex, "load")
            )

    def _refresh_previews(self) -> None:
        packet = self.packetBuilderService.buildPacket()
        if packet is None:
            self.summaryEdit.setText("尚未添加任何协议层。")
            self.structureEdit.setPlainText("尚未添加任何协议层。")
            self.hexdumpEdit.setPlainText("")
            self.packetChanged.emit(None)
            return

        self.summaryEdit.setText(self.packetBuilderService.buildSummary())
        self.structureEdit.setPlainText(self.packetBuilderService.buildStructureDump())
        self.hexdumpEdit.setPlainText(self.packetBuilderService.buildHexdump())

        self.packetChanged.emit(packet.copy())

    def _populate_value_cell(self, rowIndex: int, fieldRecord: LayerFieldRecord) -> None:
        if fieldRecord.editorKind == "collection":
            container = QtWidgets.QWidget()
            layout = QtWidgets.QHBoxLayout(container)
            layout.setContentsMargins(0, 0, 0, 0)
            valuePreview = QtWidgets.QLineEdit(self._collection_display_text(fieldRecord.currentValue))
            valuePreview.setReadOnly(True)
            valuePreview.setPlaceholderText(fieldRecord.placeholderText)
            editButton = QtWidgets.QPushButton("编辑...")
            editButton.clicked.connect(
                lambda _checked=False, record=fieldRecord: self._open_collection_editor(record)
            )
            layout.addWidget(valuePreview, 1)
            layout.addWidget(editButton)
            self.fieldTable.setCellWidget(rowIndex, 3, container)
            return

        if fieldRecord.editorKind == "enum":
            comboBox = QtWidgets.QComboBox()
            comboBox.setEditable(True)
            comboBox.setInsertPolicy(QtWidgets.QComboBox.InsertPolicy.NoInsert)
            comboBox.addItem("使用默认值", "")
            currentIndex = 0
            for choiceValue, choiceLabel in fieldRecord.choices:
                comboBox.addItem(choiceLabel, choiceValue)
                if choiceValue == fieldRecord.currentValue:
                    currentIndex = comboBox.count() - 1
            if fieldRecord.currentValue and currentIndex == 0:
                comboBox.addItem(f"自定义值 ({fieldRecord.currentValue})", fieldRecord.currentValue)
                currentIndex = comboBox.count() - 1
            comboBox.setCurrentIndex(currentIndex)
            completer = QtWidgets.QCompleter(
                [comboBox.itemText(index) for index in range(comboBox.count())],
                comboBox,
            )
            completer.setCaseSensitivity(QtCore.Qt.CaseSensitivity.CaseInsensitive)
            completer.setFilterMode(QtCore.Qt.MatchFlag.MatchContains)
            comboBox.setCompleter(completer)
            comboBox.activated.connect(
                lambda _index, name=fieldRecord.name, widget=comboBox: self._handle_enum_editor_activated(
                    name,
                    widget,
                )
            )
            comboBox.lineEdit().editingFinished.connect(
                lambda name=fieldRecord.name, widget=comboBox: self._handle_enum_editor_editing_finished(
                    name,
                    widget,
                )
            )
            self.fieldTable.setCellWidget(rowIndex, 3, comboBox)
            return

        if fieldRecord.editorKind == "bool":
            checkBox = QtWidgets.QCheckBox()
            checkBox.setChecked(fieldRecord.currentValue.lower() in {"1", "true"})
            container = QtWidgets.QWidget()
            layout = QtWidgets.QHBoxLayout(container)
            layout.setContentsMargins(6, 0, 6, 0)
            layout.addStretch(1)
            layout.addWidget(checkBox)
            layout.addStretch(1)
            checkBox.toggled.connect(
                lambda checked, name=fieldRecord.name: self._handle_editor_value_changed(
                    name,
                    "1" if checked else "0",
                )
            )
            self.fieldTable.setCellWidget(rowIndex, 3, container)
            return

        if fieldRecord.editorKind == "bytes":
            lineEdit = QtWidgets.QLineEdit(fieldRecord.currentValue)
            lineEdit.setPlaceholderText(fieldRecord.placeholderText)
            lineEdit.setClearButtonEnabled(True)
            lineEdit.editingFinished.connect(
                lambda name=fieldRecord.name, widget=lineEdit: self._handle_editor_value_changed(
                    name,
                    widget.text(),
                )
            )
            self.fieldTable.setCellWidget(rowIndex, 3, lineEdit)
            return

        if fieldRecord.editorKind in {"ipv4", "ipv6", "mac"}:
            lineEdit = QtWidgets.QLineEdit(fieldRecord.currentValue)
            lineEdit.setPlaceholderText(fieldRecord.placeholderText)
            lineEdit.setClearButtonEnabled(True)
            if fieldRecord.editorKind == "mac":
                validator = QtGui.QRegularExpressionValidator(
                    QtCore.QRegularExpression(r"[0-9A-Fa-f:-]{0,17}"),
                    lineEdit,
                )
                lineEdit.setValidator(validator)
            lineEdit.editingFinished.connect(
                lambda name=fieldRecord.name, widget=lineEdit: self._handle_editor_value_changed(
                    name,
                    widget.text(),
                )
            )
            self.fieldTable.setCellWidget(rowIndex, 3, lineEdit)
            return

        valueItem = QtWidgets.QTableWidgetItem(fieldRecord.currentValue)
        self.fieldTable.setItem(rowIndex, 3, valueItem)

    def _open_collection_editor(self, fieldRecord: LayerFieldRecord) -> None:
        if fieldRecord.collectionKind == "ip_options":
            self._open_ip_options_editor(fieldRecord)
            return

        if fieldRecord.collectionKind == "dns_questions":
            self._open_dns_question_editor(fieldRecord)
            return

        if fieldRecord.collectionKind == "literal_list":
            self._open_literal_list_editor(fieldRecord)
            return

        dialog = QtWidgets.QDialog(self)
        dialog.setWindowTitle(f"编辑集合字段: {fieldRecord.name}")
        dialog.resize(720, 420)

        layout = QtWidgets.QVBoxLayout(dialog)
        hintLabel = QtWidgets.QLabel(fieldRecord.placeholderText or "请输入 Python 字面量集合。")
        hintLabel.setWordWrap(True)
        layout.addWidget(hintLabel)

        textEdit = QtWidgets.QPlainTextEdit(fieldRecord.currentValue or fieldRecord.defaultValue)
        layout.addWidget(textEdit, 1)

        buttonBox = QtWidgets.QDialogButtonBox(
            QtWidgets.QDialogButtonBox.StandardButton.Ok
            | QtWidgets.QDialogButtonBox.StandardButton.Cancel
        )
        resetButton = buttonBox.addButton("恢复默认", QtWidgets.QDialogButtonBox.ButtonRole.ResetRole)
        resetButton.clicked.connect(lambda: textEdit.setPlainText(""))
        buttonBox.accepted.connect(dialog.accept)
        buttonBox.rejected.connect(dialog.reject)
        layout.addWidget(buttonBox)

        if dialog.exec() != int(QtWidgets.QDialog.DialogCode.Accepted):
            return

        self._apply_field_value(fieldRecord.name, textEdit.toPlainText().strip())

    def _open_ip_options_editor(self, fieldRecord: LayerFieldRecord) -> None:
        optionItems = self._parse_ip_options_collection(fieldRecord.name)

        dialog = QtWidgets.QDialog(self)
        dialog.setWindowTitle(f"编辑 IP Options: {fieldRecord.name}")
        dialog.resize(860, 460)

        layout = QtWidgets.QVBoxLayout(dialog)
        hintLabel = QtWidgets.QLabel(
            "支持按模板添加常用 IP option：NOP、EOL、RR、LSRR、SSRR、Timestamp、Router Alert、Security。"
        )
        hintLabel.setWordWrap(True)
        layout.addWidget(hintLabel)

        table = QtWidgets.QTableWidget(0, 3)
        table.setHorizontalHeaderLabels(["类型", "主要参数", "摘要"])
        table.horizontalHeader().setStretchLastSection(True)
        table.verticalHeader().setVisible(False)
        for optionItem in optionItems:
            self._append_ip_option_row(table, optionItem)
        layout.addWidget(table, 1)

        buttonLayout = QtWidgets.QHBoxLayout()
        addMenuButton = QtWidgets.QPushButton("添加模板")
        editButton = QtWidgets.QPushButton("编辑")
        removeButton = QtWidgets.QPushButton("删除")
        moveUpButton = QtWidgets.QPushButton("上移")
        moveDownButton = QtWidgets.QPushButton("下移")
        buttonLayout.addWidget(addMenuButton)
        buttonLayout.addWidget(editButton)
        buttonLayout.addWidget(removeButton)
        buttonLayout.addWidget(moveUpButton)
        buttonLayout.addWidget(moveDownButton)
        buttonLayout.addStretch(1)
        layout.addLayout(buttonLayout)

        menu = QtWidgets.QMenu(addMenuButton)
        for optionType in ["NOP", "EOL", "RR", "LSRR", "SSRR", "Timestamp", "RouterAlert", "Security"]:
            action = menu.addAction(optionType)
            action.triggered.connect(
                lambda _checked=False, optionType=optionType: self._add_ip_option_row(table, optionType)
            )
        addMenuButton.setMenu(menu)

        editButton.clicked.connect(lambda: self._edit_ip_option_row(table))
        removeButton.clicked.connect(lambda: self._remove_table_row(table))
        moveUpButton.clicked.connect(lambda: self._move_table_row(table, -1))
        moveDownButton.clicked.connect(lambda: self._move_table_row(table, 1))

        buttonBox = QtWidgets.QDialogButtonBox(
            QtWidgets.QDialogButtonBox.StandardButton.Ok
            | QtWidgets.QDialogButtonBox.StandardButton.Cancel
        )
        buttonBox.accepted.connect(dialog.accept)
        buttonBox.rejected.connect(dialog.reject)
        layout.addWidget(buttonBox)

        if dialog.exec() != int(QtWidgets.QDialog.DialogCode.Accepted):
            return

        optionPayload = []
        for rowIndex in range(table.rowCount()):
            itemData = table.item(rowIndex, 0).data(QtCore.Qt.ItemDataRole.UserRole)
            if itemData is not None:
                optionPayload.append(dict(itemData))
        self._apply_field_value(fieldRecord.name, repr(optionPayload))

    def _open_literal_list_editor(self, fieldRecord: LayerFieldRecord) -> None:
        values = self._parse_literal_collection(fieldRecord.currentValue, fieldRecord.defaultValue)

        dialog = QtWidgets.QDialog(self)
        dialog.setWindowTitle(f"编辑列表字段: {fieldRecord.name}")
        dialog.resize(720, 420)

        layout = QtWidgets.QVBoxLayout(dialog)
        hintLabel = QtWidgets.QLabel("每一项按 Python 字面量编辑，例如 'text'、123、('RA', b'\\x00\\x00')。")
        hintLabel.setWordWrap(True)
        layout.addWidget(hintLabel)

        itemList = QtWidgets.QListWidget()
        for value in values:
            itemList.addItem(repr(value))
        layout.addWidget(itemList, 1)

        buttonLayout = QtWidgets.QHBoxLayout()
        addButton = QtWidgets.QPushButton("添加")
        editButton = QtWidgets.QPushButton("编辑")
        removeButton = QtWidgets.QPushButton("删除")
        moveUpButton = QtWidgets.QPushButton("上移")
        moveDownButton = QtWidgets.QPushButton("下移")
        buttonLayout.addWidget(addButton)
        buttonLayout.addWidget(editButton)
        buttonLayout.addWidget(removeButton)
        buttonLayout.addWidget(moveUpButton)
        buttonLayout.addWidget(moveDownButton)
        buttonLayout.addStretch(1)
        layout.addLayout(buttonLayout)

        addButton.clicked.connect(lambda: self._add_literal_list_item(itemList))
        editButton.clicked.connect(lambda: self._edit_literal_list_item(itemList))
        removeButton.clicked.connect(lambda: self._remove_literal_list_item(itemList))
        moveUpButton.clicked.connect(lambda: self._move_literal_list_item(itemList, -1))
        moveDownButton.clicked.connect(lambda: self._move_literal_list_item(itemList, 1))

        buttonBox = QtWidgets.QDialogButtonBox(
            QtWidgets.QDialogButtonBox.StandardButton.Ok
            | QtWidgets.QDialogButtonBox.StandardButton.Cancel
        )
        buttonBox.accepted.connect(dialog.accept)
        buttonBox.rejected.connect(dialog.reject)
        layout.addWidget(buttonBox)

        if dialog.exec() != int(QtWidgets.QDialog.DialogCode.Accepted):
            return

        items = [itemList.item(index).text() for index in range(itemList.count())]
        rawValue = f"[{', '.join(items)}]" if items else "[]"
        self._apply_field_value(fieldRecord.name, rawValue)

    def _open_dns_question_editor(self, fieldRecord: LayerFieldRecord) -> None:
        questions = self._parse_dns_question_collection(fieldRecord.name)

        dialog = QtWidgets.QDialog(self)
        dialog.setWindowTitle(f"编辑 DNS Question 列表: {fieldRecord.name}")
        dialog.resize(760, 420)

        layout = QtWidgets.QVBoxLayout(dialog)
        hintLabel = QtWidgets.QLabel("支持增删改 DNS question 子项，当前覆盖 qname、qtype、qclass。")
        hintLabel.setWordWrap(True)
        layout.addWidget(hintLabel)

        table = QtWidgets.QTableWidget(0, 3)
        table.setHorizontalHeaderLabels(["qname", "qtype", "qclass"])
        table.horizontalHeader().setStretchLastSection(True)
        table.verticalHeader().setVisible(False)
        for question in questions:
            self._append_dns_question_row(table, question)
        layout.addWidget(table, 1)

        buttonLayout = QtWidgets.QHBoxLayout()
        addButton = QtWidgets.QPushButton("添加")
        removeButton = QtWidgets.QPushButton("删除")
        moveUpButton = QtWidgets.QPushButton("上移")
        moveDownButton = QtWidgets.QPushButton("下移")
        buttonLayout.addWidget(addButton)
        buttonLayout.addWidget(removeButton)
        buttonLayout.addWidget(moveUpButton)
        buttonLayout.addWidget(moveDownButton)
        buttonLayout.addStretch(1)
        layout.addLayout(buttonLayout)

        addButton.clicked.connect(lambda: self._append_dns_question_row(table, {}))
        removeButton.clicked.connect(lambda: self._remove_table_row(table))
        moveUpButton.clicked.connect(lambda: self._move_table_row(table, -1))
        moveDownButton.clicked.connect(lambda: self._move_table_row(table, 1))

        buttonBox = QtWidgets.QDialogButtonBox(
            QtWidgets.QDialogButtonBox.StandardButton.Ok
            | QtWidgets.QDialogButtonBox.StandardButton.Cancel
        )
        buttonBox.accepted.connect(dialog.accept)
        buttonBox.rejected.connect(dialog.reject)
        layout.addWidget(buttonBox)

        if dialog.exec() != int(QtWidgets.QDialog.DialogCode.Accepted):
            return

        questionItems = []
        for rowIndex in range(table.rowCount()):
            qname = self._table_item_text(table, rowIndex, 0)
            if not qname:
                continue
            questionItem = {
                "qname": qname,
                "qtype": self._table_item_text(table, rowIndex, 1) or "A",
                "qclass": self._table_item_text(table, rowIndex, 2) or "IN",
            }
            questionItems.append(questionItem)

        self._apply_field_value(fieldRecord.name, repr(questionItems))

    def _add_literal_list_item(self, itemList: QtWidgets.QListWidget) -> None:
        value = self._prompt_literal_value("添加列表项", "请输入 Python 字面量")
        if value is None:
            return
        itemList.addItem(value)
        itemList.setCurrentRow(itemList.count() - 1)

    def _edit_literal_list_item(self, itemList: QtWidgets.QListWidget) -> None:
        currentItem = itemList.currentItem()
        if currentItem is None:
            return
        value = self._prompt_literal_value("编辑列表项", "请输入 Python 字面量", currentItem.text())
        if value is None:
            return
        currentItem.setText(value)

    def _remove_literal_list_item(self, itemList: QtWidgets.QListWidget) -> None:
        currentRow = itemList.currentRow()
        if currentRow < 0:
            return
        itemList.takeItem(currentRow)

    def _move_literal_list_item(self, itemList: QtWidgets.QListWidget, step: int) -> None:
        currentRow = itemList.currentRow()
        targetRow = currentRow + step
        if currentRow < 0 or targetRow < 0 or targetRow >= itemList.count():
            return
        item = itemList.takeItem(currentRow)
        itemList.insertItem(targetRow, item)
        itemList.setCurrentRow(targetRow)

    def _prompt_literal_value(
        self,
        title: str,
        label: str,
        initialValue: str = "",
    ) -> str | None:
        value, accepted = QtWidgets.QInputDialog.getMultiLineText(
            self,
            title,
            label,
            initialValue,
        )
        if not accepted:
            return None
        value = value.strip()
        if value == "":
            return None
        try:
            ast.literal_eval(value)
        except Exception as exc:
            self.builderStatusLabel.setText(f"列表项字面量无效: {exc}")
            return None
        return value

    def _append_dns_question_row(
        self,
        table: QtWidgets.QTableWidget,
        question: dict[str, object],
    ) -> None:
        rowIndex = table.rowCount()
        table.insertRow(rowIndex)
        table.setItem(rowIndex, 0, QtWidgets.QTableWidgetItem(str(question.get("qname", ""))))
        table.setItem(rowIndex, 1, QtWidgets.QTableWidgetItem(str(question.get("qtype", "A"))))
        table.setItem(rowIndex, 2, QtWidgets.QTableWidgetItem(str(question.get("qclass", "IN"))))

    def _append_ip_option_row(
        self,
        table: QtWidgets.QTableWidget,
        optionItem: dict[str, object],
    ) -> None:
        rowIndex = table.rowCount()
        table.insertRow(rowIndex)
        typeItem = QtWidgets.QTableWidgetItem(str(optionItem.get("type", "NOP")))
        typeItem.setData(QtCore.Qt.ItemDataRole.UserRole, dict(optionItem))
        argsItem = QtWidgets.QTableWidgetItem(self._ip_option_argument_text(optionItem))
        summaryItem = QtWidgets.QTableWidgetItem(self._ip_option_summary(optionItem))
        table.setItem(rowIndex, 0, typeItem)
        table.setItem(rowIndex, 1, argsItem)
        table.setItem(rowIndex, 2, summaryItem)

    def _add_ip_option_row(self, table: QtWidgets.QTableWidget, optionType: str) -> None:
        optionItem = self._default_ip_option_item(optionType)
        editedItem = self._edit_ip_option_item(optionItem)
        if editedItem is None:
            return
        self._append_ip_option_row(table, editedItem)
        table.setCurrentCell(table.rowCount() - 1, 0)

    def _edit_ip_option_row(self, table: QtWidgets.QTableWidget) -> None:
        currentRow = table.currentRow()
        if currentRow < 0:
            return
        typeItem = table.item(currentRow, 0)
        if typeItem is None:
            return
        optionItem = typeItem.data(QtCore.Qt.ItemDataRole.UserRole)
        if not isinstance(optionItem, dict):
            return
        editedItem = self._edit_ip_option_item(dict(optionItem))
        if editedItem is None:
            return
        typeItem.setText(str(editedItem.get("type", "NOP")))
        typeItem.setData(QtCore.Qt.ItemDataRole.UserRole, editedItem)
        table.item(currentRow, 1).setText(self._ip_option_argument_text(editedItem))
        table.item(currentRow, 2).setText(self._ip_option_summary(editedItem))

    def _edit_ip_option_item(self, optionItem: dict[str, object]) -> dict[str, object] | None:
        optionType = str(optionItem.get("type", "NOP"))
        if optionType in {"NOP", "EOL", "RouterAlert"}:
            return optionItem

        if optionType in {"RR", "LSRR", "SSRR"}:
            routers, accepted = QtWidgets.QInputDialog.getMultiLineText(
                self,
                f"编辑 {optionType}",
                "请输入路由器 IP 列表，每行一个地址",
                "\n".join(optionItem.get("routers", [])),
            )
            if not accepted:
                return None
            optionItem["routers"] = [line.strip() for line in routers.splitlines() if line.strip()]
            return optionItem

        if optionType == "Timestamp":
            dialog = QtWidgets.QDialog(self)
            dialog.setWindowTitle("编辑 Timestamp")
            form = QtWidgets.QFormLayout(dialog)
            flgCombo = QtWidgets.QComboBox()
            flgCombo.addItem("timestamp_only", "timestamp_only")
            flgCombo.addItem("timestamp_and_ip_addr", "timestamp_and_ip_addr")
            flgCombo.addItem("prespecified_ip_addr", "prespecified_ip_addr")
            currentFlag = str(optionItem.get("flg", "timestamp_only"))
            index = flgCombo.findData(currentFlag)
            flgCombo.setCurrentIndex(index if index >= 0 else 0)
            addressEdit = QtWidgets.QLineEdit(str(optionItem.get("internet_address", "0.0.0.0")))
            timestampSpin = QtWidgets.QSpinBox()
            timestampSpin.setRange(0, 2_147_483_647)
            timestampSpin.setValue(int(optionItem.get("timestamp", 0)))
            form.addRow("模式", flgCombo)
            form.addRow("地址", addressEdit)
            form.addRow("时间戳", timestampSpin)
            buttonBox = QtWidgets.QDialogButtonBox(
                QtWidgets.QDialogButtonBox.StandardButton.Ok
                | QtWidgets.QDialogButtonBox.StandardButton.Cancel
            )
            form.addRow(buttonBox)
            buttonBox.accepted.connect(dialog.accept)
            buttonBox.rejected.connect(dialog.reject)
            if dialog.exec() != int(QtWidgets.QDialog.DialogCode.Accepted):
                return None
            optionItem["flg"] = str(flgCombo.currentData())
            optionItem["internet_address"] = addressEdit.text().strip() or "0.0.0.0"
            optionItem["timestamp"] = int(timestampSpin.value())
            return optionItem

        if optionType == "Security":
            dialog = QtWidgets.QDialog(self)
            dialog.setWindowTitle("编辑 Security")
            form = QtWidgets.QFormLayout(dialog)
            securitySpin = QtWidgets.QSpinBox()
            compartmentSpin = QtWidgets.QSpinBox()
            restrictionsSpin = QtWidgets.QSpinBox()
            for widget, value in [
                (securitySpin, int(optionItem.get("security", 0))),
                (compartmentSpin, int(optionItem.get("compartment", 0))),
                (restrictionsSpin, int(optionItem.get("handling_restrictions", 0))),
            ]:
                widget.setRange(0, 65535)
                widget.setValue(value)
            tccEdit = QtWidgets.QLineEdit(str(optionItem.get("transmission_control_code", "xxx")))
            form.addRow("security", securitySpin)
            form.addRow("compartment", compartmentSpin)
            form.addRow("handling_restrictions", restrictionsSpin)
            form.addRow("transmission_control_code", tccEdit)
            buttonBox = QtWidgets.QDialogButtonBox(
                QtWidgets.QDialogButtonBox.StandardButton.Ok
                | QtWidgets.QDialogButtonBox.StandardButton.Cancel
            )
            form.addRow(buttonBox)
            buttonBox.accepted.connect(dialog.accept)
            buttonBox.rejected.connect(dialog.reject)
            if dialog.exec() != int(QtWidgets.QDialog.DialogCode.Accepted):
                return None
            optionItem["security"] = int(securitySpin.value())
            optionItem["compartment"] = int(compartmentSpin.value())
            optionItem["handling_restrictions"] = int(restrictionsSpin.value())
            optionItem["transmission_control_code"] = tccEdit.text().strip() or "xxx"
            return optionItem

        return optionItem

    def _default_ip_option_item(self, optionType: str) -> dict[str, object]:
        defaults: dict[str, dict[str, object]] = {
            "NOP": {"type": "NOP"},
            "EOL": {"type": "EOL"},
            "RR": {"type": "RR", "routers": []},
            "LSRR": {"type": "LSRR", "routers": []},
            "SSRR": {"type": "SSRR", "routers": []},
            "Timestamp": {
                "type": "Timestamp",
                "flg": "timestamp_only",
                "internet_address": "0.0.0.0",
                "timestamp": 0,
            },
            "RouterAlert": {"type": "RouterAlert"},
            "Security": {
                "type": "Security",
                "security": 0,
                "compartment": 0,
                "handling_restrictions": 0,
                "transmission_control_code": "xxx",
            },
        }
        return dict(defaults[optionType])

    def _ip_option_argument_text(self, optionItem: dict[str, object]) -> str:
        optionType = str(optionItem.get("type", "NOP"))
        if optionType in {"RR", "LSRR", "SSRR"}:
            routers = optionItem.get("routers", [])
            return ", ".join(str(router) for router in routers) or "无"
        if optionType == "Timestamp":
            return f"{optionItem.get('flg', 'timestamp_only')}, ts={optionItem.get('timestamp', 0)}"
        if optionType == "Security":
            return f"sec={optionItem.get('security', 0)}, comp={optionItem.get('compartment', 0)}"
        return "-"

    def _ip_option_summary(self, optionItem: dict[str, object]) -> str:
        optionType = str(optionItem.get("type", "NOP"))
        summaryMap = {
            "NOP": "No Operation",
            "EOL": "End of Options List",
            "RR": "Record Route",
            "LSRR": "Loose Source Route",
            "SSRR": "Strict Source Route",
            "Timestamp": "Timestamp",
            "RouterAlert": "Router Alert",
            "Security": "Security",
        }
        return summaryMap.get(optionType, optionType)

    def _remove_table_row(self, table: QtWidgets.QTableWidget) -> None:
        currentRow = table.currentRow()
        if currentRow >= 0:
            table.removeRow(currentRow)

    def _move_table_row(self, table: QtWidgets.QTableWidget, step: int) -> None:
        currentRow = table.currentRow()
        targetRow = currentRow + step
        if currentRow < 0 or targetRow < 0 or targetRow >= table.rowCount():
            return

        rowItems = [table.takeItem(currentRow, column) for column in range(table.columnCount())]
        table.removeRow(currentRow)
        table.insertRow(targetRow)
        for columnIndex, item in enumerate(rowItems):
            if item is None:
                item = QtWidgets.QTableWidgetItem("")
            table.setItem(targetRow, columnIndex, item)
        table.setCurrentCell(targetRow, 0)

    def _table_item_text(self, table: QtWidgets.QTableWidget, rowIndex: int, columnIndex: int) -> str:
        item = table.item(rowIndex, columnIndex)
        return item.text().strip() if item is not None else ""

    def _parse_literal_collection(self, currentValue: str, defaultValue: str) -> list[object]:
        for candidate in [currentValue, defaultValue]:
            candidate = candidate.strip()
            if not candidate:
                continue
            try:
                value = ast.literal_eval(candidate)
            except Exception:
                continue
            if isinstance(value, tuple):
                return list(value)
            if isinstance(value, list):
                return list(value)
        return []

    def _parse_dns_question_collection(self, fieldName: str) -> list[dict[str, object]]:
        layerIndex = self.layerList.currentRow()
        if layerIndex < 0:
            return []

        nativeValue = self.packetBuilderService.getFieldNativeValue(layerIndex, fieldName)
        questions: list[dict[str, object]] = []
        for item in nativeValue or []:
            if isinstance(item, dict):
                questions.append(
                    {
                        "qname": str(item.get("qname", "")),
                        "qtype": str(item.get("qtype", "A")),
                        "qclass": str(item.get("qclass", "IN")),
                    }
                )
                continue

            if isinstance(item, str):
                questions.append({"qname": item, "qtype": "A", "qclass": "IN"})
                continue

            if item.__class__.__name__ == "DNSQR":
                qname = getattr(item, "qname", b"")
                if isinstance(qname, bytes):
                    qname = qname.decode("utf-8", errors="replace")
                questions.append(
                    {
                        "qname": str(qname).rstrip("."),
                        "qtype": self._dns_question_field_label(item, "qtype", "A"),
                        "qclass": self._dns_question_field_label(item, "qclass", "IN"),
                    }
                )

        return questions

    def _dns_question_field_label(self, packet: object, fieldName: str, fallback: str) -> str:
        try:
            field = packet.get_field(fieldName)
        except Exception:
            return fallback

        fieldValue = getattr(packet, fieldName, fallback)
        label = field.i2repr(packet, fieldValue)
        if isinstance(label, str) and label:
            return label
        return str(fieldValue)

    def _parse_ip_options_collection(self, fieldName: str) -> list[dict[str, object]]:
        layerIndex = self.layerList.currentRow()
        if layerIndex < 0:
            return []

        nativeValue = self.packetBuilderService.getFieldNativeValue(layerIndex, fieldName)
        optionItems: list[dict[str, object]] = []
        for item in nativeValue or []:
            className = item.__class__.__name__
            if className == "IPOption_NOP":
                optionItems.append({"type": "NOP"})
            elif className == "IPOption_EOL":
                optionItems.append({"type": "EOL"})
            elif className in {"IPOption_RR", "IPOption_LSRR", "IPOption_SSRR"}:
                optionItems.append(
                    {
                        "type": className.removeprefix("IPOption_"),
                        "routers": list(getattr(item, "routers", [])),
                    }
                )
            elif className == "IPOption_Timestamp":
                optionItems.append(
                    {
                        "type": "Timestamp",
                        "flg": str(getattr(item, "flg", "timestamp_only")),
                        "internet_address": str(getattr(item, "internet_address", "0.0.0.0")),
                        "timestamp": int(getattr(item, "timestamp", 0)),
                    }
                )
            elif className == "IPOption_Router_Alert":
                optionItems.append({"type": "RouterAlert"})
            elif className == "IPOption_Security":
                optionItems.append(
                    {
                        "type": "Security",
                        "security": int(getattr(item, "security", 0)),
                        "compartment": int(getattr(item, "compartment", 0)),
                        "handling_restrictions": int(getattr(item, "handling_restrictions", 0)),
                        "transmission_control_code": str(getattr(item, "transmission_control_code", "xxx")),
                    }
                )
        return optionItems

    def _handle_editor_value_changed(self, fieldName: str, rawValue: str) -> None:
        if self._updatingFieldTable:
            return
        self._apply_field_value(fieldName, rawValue)

    def _handle_enum_editor_activated(
        self,
        fieldName: str,
        comboBox: QtWidgets.QComboBox,
    ) -> None:
        self._handle_editor_value_changed(fieldName, self._current_combo_value(comboBox))

    def _handle_enum_editor_editing_finished(
        self,
        fieldName: str,
        comboBox: QtWidgets.QComboBox,
    ) -> None:
        if comboBox.view().isVisible():
            return

        completer = comboBox.completer()
        if completer is not None and completer.popup().isVisible():
            return

        self._handle_editor_value_changed(fieldName, self._current_combo_value(comboBox))

    def _apply_field_value(self, fieldName: str, rawValue: str) -> None:
        layerIndex = self.layerList.currentRow()
        if layerIndex < 0:
            return

        validationError = self._validate_field_value(fieldName, rawValue)
        if validationError:
            self.builderStatusLabel.setText(validationError)
            self._refresh_field_table()
            return

        try:
            self.packetBuilderService.setFieldValue(layerIndex, fieldName, rawValue)
        except Exception as exc:
            self.builderStatusLabel.setText(f"字段更新失败: {exc}")
            self._refresh_field_table()
            return

        self.builderStatusLabel.setText(f"已更新字段: {fieldName}")
        self._refresh_previews()
        self._refresh_layer_list(preserveSelection=True)
        self._refresh_raw_payload_editor()

    def _current_combo_value(self, comboBox: QtWidgets.QComboBox) -> str:
        if comboBox.isEditable():
            currentText = comboBox.lineEdit().text().strip()
            if currentText:
                currentIndex = comboBox.currentIndex()
                selectedText = comboBox.itemText(currentIndex).strip() if currentIndex >= 0 else ""
                if currentText != selectedText:
                    return self._normalize_combo_text(currentText)

        currentData = comboBox.currentData()
        if currentData is not None and comboBox.currentIndex() >= 0:
            return str(currentData)

        currentText = comboBox.currentText().strip()
        return self._normalize_combo_text(currentText)

    def _normalize_combo_text(self, currentText: str) -> str:
        if currentText == "使用默认值":
            return ""

        match = re.search(r"\(([^()]+)\)\s*$", currentText)
        if match:
            return match.group(1).strip()
        return currentText

    def _validate_field_value(self, fieldName: str, rawValue: str) -> str | None:
        if rawValue == "":
            return None

        fieldRecord = self._visibleFieldRecords.get(fieldName)
        if fieldRecord is None:
            return None

        if fieldRecord.editorKind == "ipv4":
            try:
                ipaddress.IPv4Address(rawValue)
            except ValueError:
                return f"字段 {fieldName} 需要合法的 IPv4 地址。"

        if fieldRecord.editorKind == "ipv6":
            try:
                ipaddress.IPv6Address(rawValue)
            except ValueError:
                return f"字段 {fieldName} 需要合法的 IPv6 地址。"

        if fieldRecord.editorKind == "mac":
            if not re.fullmatch(r"([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}", rawValue):
                return f"字段 {fieldName} 需要合法的 MAC 地址。"

        return None

    def _collection_display_text(self, rawValue: str) -> str:
        compactValue = rawValue.replace("\n", " ").strip()
        if not compactValue:
            return "使用默认值"
        if len(compactValue) > 80:
            return f"{compactValue[:77]}..."
        return compactValue