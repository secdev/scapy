from __future__ import annotations

import unittest

from packet_studio.adapters.scapy_packet_adapter import ScapyPacketAdapter


class FakePacket:
    def __init__(self, summary: str, dump: str, payload: bytes) -> None:
        self._summary = summary
        self._dump = dump
        self._payload = payload

    def copy(self) -> "FakePacket":
        return FakePacket(self._summary, self._dump, self._payload)

    def summary(self) -> str:
        return self._summary

    def show(self, dump: bool = False) -> str:
        if dump:
            return self._dump
        raise AssertionError("仅测试 dump=True 路径")

    def __bytes__(self) -> bytes:
        return self._payload


class ScapyPacketAdapterTests(unittest.TestCase):
    def test_build_preview_formats_packet_fields(self) -> None:
        adapter = ScapyPacketAdapter()
        packet = FakePacket("IP / TCP", "packet dump", b"\x01\x02ABC")

        preview = adapter.buildPreview(packet)

        self.assertEqual(preview.summary, "IP / TCP")
        self.assertEqual(preview.structure, "packet dump")
        self.assertIn("0000", preview.hexdump)
        self.assertIn("01 02 41 42 43", preview.hexdump)

    def test_clone_packet_returns_copy(self) -> None:
        adapter = ScapyPacketAdapter()
        packet = FakePacket("IP", "dump", b"\x00")

        clonedPacket = adapter.clonePacket(packet)

        self.assertIsNot(packet, clonedPacket)
        self.assertEqual(bytes(clonedPacket), bytes(packet))


if __name__ == "__main__":
    unittest.main()