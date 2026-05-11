from __future__ import annotations

from typing import Any

from packet_studio.domain.packet_models import CapturedPacketRecord, PacketPreview


class ScapyPacketAdapter:
    """提供 Packet 预览和复制的稳定适配接口。"""

    def clonePacket(self, packet: Any | None) -> Any | None:
        if packet is None:
            return None
        return packet.copy()

    def buildPreview(self, packet: Any) -> PacketPreview:
        return PacketPreview(
            summary=self.buildSummary(packet),
            structure=self.buildStructureDump(packet),
            hexdump=self.buildHexdump(packet),
        )

    def buildCapturedRecord(self, packet: Any) -> CapturedPacketRecord:
        packetCopy = self.clonePacket(packet)
        return CapturedPacketRecord(
            packet=packetCopy,
            sourceText=self.buildSourceText(packet),
            protocolName=self.buildPrimaryProtocolName(packet),
            preview=self.buildPreview(packetCopy),
        )

    def buildSummary(self, packet: Any) -> str:
        return packet.summary()

    def buildSourceText(self, packet: Any) -> str:
        return str(getattr(packet, "sniffed_on", "") or "")

    def buildPrimaryProtocolName(self, packet: Any) -> str:
        for protocolName in ["ARP", "DNS", "ICMP", "ICMPv6Unknown", "TCP", "UDP", "IPv6", "IP", "Raw"]:
            if packet.haslayer(protocolName):
                return protocolName
        return packet.__class__.__name__

    def buildStructureDump(self, packet: Any) -> str:
        return packet.show(dump=True)

    def buildHexdump(self, packet: Any) -> str:
        payload = bytes(packet)
        if not payload:
            return ""

        lines = []
        for offset in range(0, len(payload), 16):
            chunk = payload[offset:offset + 16]
            hexPart = " ".join(f"{byte:02x}" for byte in chunk)
            asciiPart = "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in chunk)
            lines.append(f"{offset:04x}  {hexPart:<47}  {asciiPart}")
        return "\n".join(lines)