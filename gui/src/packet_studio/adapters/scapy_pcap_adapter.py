from __future__ import annotations

from datetime import datetime
from typing import Any

from packet_studio.adapters.scapy_packet_adapter import ScapyPacketAdapter
from packet_studio.domain.packet_models import PcapPacketRecord


class ScapyPcapAdapter:
    """提供 pcap 记录到领域模型的稳定适配接口。"""

    def __init__(self, packetAdapter: ScapyPacketAdapter | None = None) -> None:
        self._packetAdapter = packetAdapter or ScapyPacketAdapter()

    def buildPacketRecord(self, index: int, packet: Any) -> PcapPacketRecord:
        packetCopy = self._packetAdapter.clonePacket(packet)
        return PcapPacketRecord(
            index=index,
            timestampText=self.formatTimestamp(getattr(packet, "time", None)),
            sourceText=self._packetAdapter.buildSourceText(packet),
            protocolName=self._packetAdapter.buildPrimaryProtocolName(packet),
            preview=self._packetAdapter.buildPreview(packetCopy),
            packet=packetCopy,
        )

    def formatTimestamp(self, rawTime: Any) -> str:
        if rawTime is None:
            return ""

        try:
            timestamp = float(rawTime)
        except Exception:
            return str(rawTime)

        try:
            return datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        except Exception:
            return str(rawTime)