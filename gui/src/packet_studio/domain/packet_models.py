from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class PacketPreview:
    summary: str
    structure: str
    hexdump: str


@dataclass(frozen=True)
class CapturedPacketRecord:
    packet: Any
    sourceText: str
    protocolName: str
    preview: PacketPreview

    @property
    def summary(self) -> str:
        return self.preview.summary


@dataclass(frozen=True)
class PcapPacketRecord:
    index: int
    timestampText: str
    sourceText: str
    protocolName: str
    preview: PacketPreview
    packet: Any

    @property
    def summary(self) -> str:
        return self.preview.summary