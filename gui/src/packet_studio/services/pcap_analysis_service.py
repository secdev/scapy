from __future__ import annotations

from typing import Any

from packet_studio.adapters.scapy_pcap_adapter import ScapyPcapAdapter
from packet_studio.domain.packet_models import PcapPacketRecord
from packet_studio.domain.task_models import PcapLoadResult, TaskState


class PcapAnalysisService:
    """封装 pcap/pcapng 基础读取流程。"""

    def __init__(
        self,
        pcapReaderFactory: Any | None = None,
        pcapAdapter: ScapyPcapAdapter | None = None,
    ) -> None:
        if pcapReaderFactory is None:
            from scapy.utils import PcapReader

            self._pcapReaderFactory = PcapReader
        else:
            self._pcapReaderFactory = pcapReaderFactory
        self._pcapAdapter = pcapAdapter or ScapyPcapAdapter()

    def loadPackets(self, filePath: str, maxPackets: int = 500) -> PcapLoadResult:
        packetRecords: list[PcapPacketRecord] = []
        with self._pcapReaderFactory(filePath) as reader:
            for index, packet in enumerate(reader, start=1):
                packetRecords.append(self._pcapAdapter.buildPacketRecord(index, packet))
                if maxPackets > 0 and index >= maxPackets:
                    break

        summaryText = f"离线抓包文件加载完成，共 {len(packetRecords)} 个数据包。"

        return PcapLoadResult(
            filePath=filePath,
            packetRecords=packetRecords,
            summaryText=summaryText,
            logText=summaryText,
            state=TaskState.succeeded("离线抓包文件加载完成。"),
        )
