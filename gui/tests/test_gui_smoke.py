from __future__ import annotations

import os
import time
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import scapy.all as scapy
from PySide6 import QtCore, QtWidgets
from scapy.contrib.mac_control import MACControlPause

from packet_studio.domain.packet_models import PacketPreview, PcapPacketRecord
from packet_studio.domain.task_models import PcapLoadResult, SendTaskResult, TaskState
from packet_studio.widgets.offline_analysis_widget import OfflineAnalysisWidget
from packet_studio.widgets.packet_builder_widget import PacketBuilderWidget
from packet_studio.widgets.send_task_widget import SendTaskWidget


def getOrCreateApplication() -> QtWidgets.QApplication:
    application = QtWidgets.QApplication.instance()
    if application is None:
        application = QtWidgets.QApplication([])
    return application


class FakePacket:
    def __init__(self, summary: str, structure: str, payload: bytes) -> None:
        self._summary = summary
        self._structure = structure
        self._payload = payload

    def copy(self) -> "FakePacket":
        return FakePacket(self._summary, self._structure, self._payload)

    def summary(self) -> str:
        return self._summary

    def show(self, dump: bool = False) -> str:
        if dump:
            return self._structure
        raise AssertionError("仅测试 dump=True 路径")

    def __bytes__(self) -> bytes:
        return self._payload


class FakeSendTaskService:
    def buildPacketPreview(self, packet: FakePacket | None) -> PacketPreview | None:
        if packet is None:
            return None
        return PacketPreview(
            summary=packet.summary(),
            structure=packet.show(dump=True),
            hexdump="0000  01 02                                            ..",
        )

    def execute(
        self,
        _request: object,
        _packets: object | None,
        stopRequested: object | None = None,
    ) -> SendTaskResult:
        return SendTaskResult(
            mode="send",
            sentCount=1,
            packetPreview=PacketPreview(
                summary="IP / TCP",
                structure="request dump",
                hexdump="0000  01                                               .",
            ),
            answerPreview=PacketPreview(
                summary="IP / ICMP",
                structure="reply dump",
                hexdump="0000  08 00                                            ..",
            ),
            unansweredCount=0,
            summaryText="模式: send，已发送 1 个数据包，未应答 0 个。",
            logText="执行模式: send (L3)",
            state=TaskState.succeeded("发送任务执行完成。"),
        )


class GuiSmokeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.application = getOrCreateApplication()

    def waitUntil(self, predicate: object, timeoutSeconds: float = 3.0) -> None:
        deadline = time.monotonic() + timeoutSeconds
        while time.monotonic() < deadline:
            self.application.processEvents(QtCore.QEventLoop.ProcessEventsFlag.AllEvents, 50)
            if predicate():
                return
            time.sleep(0.01)
        self.fail("等待 GUI 状态变化超时。")

    def test_packet_builder_widget_add_layer_updates_preview(self) -> None:
        widget = PacketBuilderWidget()
        emittedPackets: list[object | None] = []
        widget.packetChanged.connect(emittedPackets.append)
        emittedPackets.clear()

        widget.addLayerButton.click()

        self.application.processEvents()
        self.assertNotEqual(widget.summaryEdit.text(), "尚未添加任何协议层。")
        self.assertTrue(widget.structureEdit.toPlainText())
        self.assertTrue(widget.hexdumpEdit.toPlainText())
        self.assertTrue(emittedPackets)
        self.assertIsNotNone(emittedPackets[-1])
        widget.deleteLater()

    def test_packet_builder_widget_category_filter_hides_common_layers(self) -> None:
        widget = PacketBuilderWidget()

        wirelessIndex = widget.layerCategoryCombo.findText("无线与近场")
        self.assertGreaterEqual(wirelessIndex, 0)

        widget.layerCategoryCombo.setCurrentIndex(wirelessIndex)
        self.application.processEvents()

        self.assertEqual(widget.layerTypeCombo.findData("ip"), -1)
        self.assertGreater(widget.layerTypeCombo.count(), 0)

        allIndex = widget.layerCategoryCombo.findText("全部")
        widget.layerCategoryCombo.setCurrentIndex(allIndex)
        self.application.processEvents()

        self.assertGreaterEqual(widget.layerTypeCombo.findData("ip"), 0)
        widget.deleteLater()

    def test_packet_builder_enum_popup_does_not_commit_on_open(self) -> None:
        widget = PacketBuilderWidget()
        widget.packetBuilderService.addLayer("icmp")
        widget._refresh_all(selectLast=True)

        typeRow = -1
        for rowIndex in range(widget.fieldTable.rowCount()):
            item = widget.fieldTable.item(rowIndex, 0)
            if item is not None and item.text() == "type":
                typeRow = rowIndex
                break

        self.assertGreaterEqual(typeRow, 0)
        comboBox = widget.fieldTable.cellWidget(typeRow, 3)
        self.assertIsInstance(comboBox, QtWidgets.QComboBox)

        appliedValues: list[tuple[str, str]] = []
        originalApplyFieldValue = widget._apply_field_value

        def trackingApplyFieldValue(fieldName: str, rawValue: str) -> None:
            appliedValues.append((fieldName, rawValue))
            originalApplyFieldValue(fieldName, rawValue)

        widget._apply_field_value = trackingApplyFieldValue
        comboBox.showPopup()
        self.application.processEvents()
        comboBox.lineEdit().editingFinished.emit()
        self.application.processEvents()

        self.assertEqual(appliedValues, [])
        self.assertTrue(comboBox.view().isVisible())
        comboBox.hidePopup()
        widget.deleteLater()

    def test_packet_builder_enum_custom_hex_value_is_applied(self) -> None:
        widget = PacketBuilderWidget()
        widget.packetBuilderService.addLayer("ether")
        widget._refresh_all(selectLast=True)

        typeRow = -1
        for rowIndex in range(widget.fieldTable.rowCount()):
            item = widget.fieldTable.item(rowIndex, 0)
            if item is not None and item.text() == "type":
                typeRow = rowIndex
                break

        self.assertGreaterEqual(typeRow, 0)
        comboBox = widget.fieldTable.cellWidget(typeRow, 3)
        self.assertIsInstance(comboBox, QtWidgets.QComboBox)

        comboBox.lineEdit().setText("0x8808")
        widget._handle_enum_editor_editing_finished("type", comboBox)
        self.application.processEvents()

        self.assertEqual(widget.packetBuilderService.getFieldNativeValue(0, "type"), 0x8808)
        self.assertEqual(widget.packetBuilderService.getFieldValue(0, "type"), "0x8808")
        self.assertIn("0x8808", widget.summaryEdit.text())
        widget.deleteLater()

    def test_send_task_widget_execute_updates_result_preview(self) -> None:
        packet = FakePacket("IP / TCP", "request dump", b"\x01\x02")
        widget = SendTaskWidget()
        widget.sendTaskService = FakeSendTaskService()
        widget.addStreamFromPacket(packet.copy())

        widget.executeButton.click()

        self.waitUntil(lambda: widget.workerThread is None)
        self.assertEqual(widget.streamTable.rowCount(), 1)
        self.assertEqual(widget.packetSummaryEdit.text(), "IP / TCP")
        self.assertIn("request dump", widget.packetStructureEdit.toPlainText())
        self.assertIn("已发送 1 个数据包", widget.resultSummaryLabel.text())
        self.assertIn("reply dump", widget.answerStructureEdit.toPlainText())
        widget.deleteLater()

    def test_send_task_widget_only_enables_interface_for_sendp(self) -> None:
        widget = SendTaskWidget()

        self.assertTrue(widget.interfaceCombo.isEnabled())
        widget.modeCombo.setCurrentIndex(0)
        self.application.processEvents()
        self.assertFalse(widget.interfaceCombo.isEnabled())
        widget.modeCombo.setCurrentIndex(2)
        self.application.processEvents()
        self.assertFalse(widget.interfaceCombo.isEnabled())
        widget.deleteLater()

    def test_send_task_widget_defaults_to_l2_mode_and_fixed_width_columns(self) -> None:
        widget = SendTaskWidget()

        self.assertEqual(widget.modeCombo.currentData(), "sendp")
        self.assertEqual(widget.streamTable.columnWidth(1), 130)
        self.assertEqual(widget.streamTable.columnWidth(2), 220)
        widget.deleteLater()

    def test_packet_builder_create_stream_emits_packet(self) -> None:
        widget = PacketBuilderWidget()
        emittedPackets: list[object] = []
        widget.createStreamRequested.connect(emittedPackets.append)

        widget.addLayerButton.click()
        self.application.processEvents()
        widget.createStreamButton.click()
        self.application.processEvents()

        self.assertEqual(len(emittedPackets), 1)
        self.assertIsNotNone(emittedPackets[0])
        self.assertIn("已创建流模板", widget.builderStatusLabel.text())
        widget.deleteLater()

    def test_packet_builder_save_stream_emits_packet_in_edit_mode(self) -> None:
        widget = PacketBuilderWidget()
        savedPackets: list[object] = []
        widget.saveStreamRequested.connect(savedPackets.append)

        widget.addLayerButton.click()
        self.application.processEvents()
        self.assertFalse(widget.saveStreamButton.isEnabled())

        widget.setEditingStreamMode(True)
        self.application.processEvents()
        self.assertTrue(widget.saveStreamButton.isEnabled())

        widget.saveStreamButton.click()
        self.application.processEvents()

        self.assertEqual(len(savedPackets), 1)
        self.assertIsNotNone(savedPackets[0])
        widget.deleteLater()

    def test_offline_analysis_widget_load_result_populates_table_and_copy(self) -> None:
        widget = OfflineAnalysisWidget()
        emittedPackets: list[object] = []
        widget.importPacketRequested.connect(emittedPackets.append)
        packet = FakePacket("IP / UDP", "offline dump", b"\x11\x22")
        result = PcapLoadResult(
            filePath="capture.pcap",
            packetRecords=[
                PcapPacketRecord(
                    index=1,
                    timestampText="2026-05-11 10:00:00.000",
                    sourceText="Ethernet0",
                    protocolName="UDP",
                    preview=PacketPreview(
                        summary="IP / UDP",
                        structure="offline dump",
                        hexdump="0000  11 22                                            .\"",
                    ),
                    packet=packet,
                ),
            ],
            summaryText="离线抓包文件加载完成，共 1 个数据包。",
            logText="离线抓包文件加载完成，共 1 个数据包。",
            state=TaskState.succeeded("离线抓包文件加载完成。"),
        )

        widget._on_load_finished(result)

        self.application.processEvents()
        self.assertEqual(widget.packetTable.rowCount(), 1)
        self.assertIn("capture.pcap", widget.summaryLabel.text())
        self.assertEqual(widget.packetDetailSummary.text(), "IP / UDP")
        widget.copyToBuilderButton.click()
        self.application.processEvents()
        self.assertEqual(len(emittedPackets), 1)
        self.assertEqual(emittedPackets[0].summary(), "IP / UDP")
        widget.deleteLater()

    def test_packet_builder_widget_loads_decoded_mac_control_pause_packet(self) -> None:
        widget = PacketBuilderWidget()
        packet = scapy.Ether(
            bytes(
                scapy.Ether(type=0x8808)
                / MACControlPause(pause_time=3)
            )
        )

        widget.loadPacket(packet)

        self.application.processEvents()
        self.assertEqual(widget.builderStatusLabel.text(), "已导入当前数据包。")
        self.assertEqual(
            [record.name for record in widget.packetBuilderService.getLayerRecords()],
            ["Ethernet", "MACControlPause", "Raw"],
        )
        self.assertIn("MACControlPause", widget.summaryEdit.text())
        widget.deleteLater()


if __name__ == "__main__":
    unittest.main()