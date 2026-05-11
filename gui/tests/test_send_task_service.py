from __future__ import annotations

import unittest
from itertools import count

from packet_studio.domain.task_models import TaskPhase
from packet_studio.services.send_task_service import SendTaskRequest, SendTaskService


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


class FakeScapy:
    def __init__(self) -> None:
        self.calls: list[tuple[str, object, dict[str, object]]] = []
        self.sr1Response: object | None = None

    def send(self, packet: object, **kwargs: object) -> list[object]:
        self.calls.append(("send", packet, dict(kwargs)))
        count = int(kwargs.get("count", 1))
        return [packet] * count

    def sendp(self, packet: object, **kwargs: object) -> list[object]:
        self.calls.append(("sendp", packet, dict(kwargs)))
        count = int(kwargs.get("count", 1))
        return [packet] * count

    def sr1(self, packet: object, **kwargs: object) -> object | None:
        self.calls.append(("sr1", packet, dict(kwargs)))
        return self.sr1Response


class SendTaskServiceTests(unittest.TestCase):
    def test_send_ignores_interface_for_l3_mode(self) -> None:
        fakeScapy = FakeScapy()
        service = SendTaskService(fakeScapy)
        packet = FakePacket("IP / TCP", "packet dump", b"\x01\x02")

        result = service.execute(
            SendTaskRequest(
                mode="send",
                interfaceName="Ethernet0",
                count=3,
                intervalSeconds=0.25,
            ),
            packet,
        )

        self.assertEqual(result.sentCount, 3)
        self.assertEqual(fakeScapy.calls[0][0], "send")
        self.assertNotIn("iface", fakeScapy.calls[0][2])
        self.assertEqual(len(fakeScapy.calls), 3)
        self.assertEqual(fakeScapy.calls[0][2]["count"], 1)
        self.assertEqual(fakeScapy.calls[0][2]["inter"], 0.0)
        self.assertIn("未显式传入 iface", result.logText)
        self.assertIn("已完成发送 3 个", result.summaryText)
        self.assertEqual(result.state.phase, TaskPhase.SUCCEEDED)

    def test_sendp_passes_interface_for_l2_mode(self) -> None:
        fakeScapy = FakeScapy()
        service = SendTaskService(fakeScapy)
        packet = FakePacket("Ether / ARP", "arp dump", b"\xaa\xbb")

        result = service.execute(
            SendTaskRequest(
                mode="sendp",
                interfaceName="\\Device\\NPF_{123}",
                count=2,
                intervalSeconds=0.1,
            ),
            packet,
        )

        self.assertEqual(result.sentCount, 2)
        self.assertEqual(fakeScapy.calls[0][0], "sendp")
        self.assertEqual(fakeScapy.calls[0][2]["iface"], "\\Device\\NPF_{123}")
        self.assertIn("未应答 0 个", result.summaryText)
        self.assertEqual(result.state.phase, TaskPhase.SUCCEEDED)

    def test_sr1_returns_answer_preview(self) -> None:
        fakeScapy = FakeScapy()
        fakeScapy.sr1Response = FakePacket("IP / ICMP", "reply dump", b"\x08\x00")
        service = SendTaskService(fakeScapy)
        packet = FakePacket("IP / ICMP", "request dump", b"\x01")

        result = service.execute(
            SendTaskRequest(
                mode="sr1",
                timeoutSeconds=2.5,
                retryCount=1,
            ),
            packet,
        )

        self.assertEqual(result.sentCount, 1)
        self.assertEqual(result.unansweredCount, 0)
        self.assertIsNotNone(result.answerPreview)
        self.assertEqual(result.answerPreview.summary, "IP / ICMP")
        self.assertEqual(fakeScapy.calls[0][0], "sr1")
        self.assertEqual(fakeScapy.calls[0][2]["timeout"], 2.5)
        self.assertEqual(fakeScapy.calls[0][2]["retry"], 1)
        self.assertIn("未应答 0 个", result.summaryText)
        self.assertEqual(result.state.phase, TaskPhase.SUCCEEDED)

    def test_send_rotates_across_multiple_streams(self) -> None:
        fakeScapy = FakeScapy()
        service = SendTaskService(fakeScapy)
        packets = [
            FakePacket("IP / TCP 1", "packet dump 1", b"\x01"),
            FakePacket("IP / TCP 2", "packet dump 2", b"\x02"),
        ]

        result = service.execute(
            SendTaskRequest(
                mode="send",
                count=2,
                intervalSeconds=0.0,
            ),
            packets,
        )

        self.assertEqual(result.sentCount, 4)
        self.assertEqual(len(fakeScapy.calls), 4)
        self.assertIn("流数量: 2", result.logText)
        self.assertIn("共 2 条流", result.summaryText)

    def test_continuous_send_can_be_stopped(self) -> None:
        fakeScapy = FakeScapy()
        service = SendTaskService(fakeScapy)
        packet = FakePacket("IP / TCP", "packet dump", b"\x01\x02")
        invocationCounter = count()

        def stopRequested() -> bool:
            return next(invocationCounter) >= 3

        sleepCalls: list[float] = []

        result = service.execute(
            SendTaskRequest(
                mode="send",
                sendStrategy="continuous",
                intervalSeconds=0.2,
            ),
            packet,
            stopRequested=stopRequested,
            sleep=sleepCalls.append,
        )

        self.assertEqual(result.sentCount, 2)
        self.assertEqual(result.state.phase, TaskPhase.STOPPED)
        self.assertEqual(sleepCalls, [0.2])
        self.assertIn("已停止发送 2 个数据包", result.summaryText)

    def test_sr1_continuous_is_rejected(self) -> None:
        fakeScapy = FakeScapy()
        service = SendTaskService(fakeScapy)
        packet = FakePacket("IP / ICMP", "request dump", b"\x01")

        with self.assertRaisesRegex(ValueError, "sr1 当前仅支持 burst 模式"):
            service.execute(
                SendTaskRequest(mode="sr1", sendStrategy="continuous"),
                packet,
            )


if __name__ == "__main__":
    unittest.main()