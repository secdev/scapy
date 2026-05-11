from __future__ import annotations

import os
import tempfile
import unittest

import scapy.all as scapy

from packet_studio.domain.task_models import TaskPhase
from packet_studio.services.pcap_analysis_service import PcapAnalysisService


class PcapAnalysisServiceTests(unittest.TestCase):
    def test_load_packets_reads_expected_count(self) -> None:
        fd, filePath = tempfile.mkstemp(suffix=".pcap")
        os.close(fd)
        try:
            scapy.wrpcap(
                filePath,
                [
                    scapy.IP(dst="1.1.1.1") / scapy.ICMP(),
                    scapy.IP(dst="8.8.8.8") / scapy.UDP(dport=53),
                ],
            )

            service = PcapAnalysisService()
            result = service.loadPackets(filePath, maxPackets=10)

            self.assertEqual(result.packetCount, 2)
            self.assertIn("ICMP", result.packetRecords[0].summary)
            self.assertIn("UDP", result.packetRecords[1].summary)
            self.assertEqual(result.packetRecords[0].protocolName, "ICMP")
            self.assertIn("IP", result.packetRecords[0].preview.structure)
            self.assertTrue(result.packetRecords[0].preview.hexdump)
            self.assertIn("加载完成，共 2 个数据包", result.summaryText)
            self.assertEqual(result.state.phase, TaskPhase.SUCCEEDED)
        finally:
            if os.path.exists(filePath):
                os.unlink(filePath)

    def test_load_packets_honors_limit(self) -> None:
        fd, filePath = tempfile.mkstemp(suffix=".pcap")
        os.close(fd)
        try:
            scapy.wrpcap(
                filePath,
                [
                    scapy.IP(dst="1.1.1.1") / scapy.ICMP(),
                    scapy.IP(dst="8.8.8.8") / scapy.UDP(dport=53),
                ],
            )

            service = PcapAnalysisService()
            result = service.loadPackets(filePath, maxPackets=1)

            self.assertEqual(result.packetCount, 1)
        finally:
            if os.path.exists(filePath):
                os.unlink(filePath)


if __name__ == "__main__":
    unittest.main()