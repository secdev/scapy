from __future__ import annotations

import time
from typing import Any, Callable, Optional

from packet_studio.adapters.scapy_packet_adapter import ScapyPacketAdapter
from packet_studio.domain.packet_models import PacketPreview
from packet_studio.domain.task_models import SendTaskResult, TaskState


from dataclasses import dataclass


@dataclass(frozen=True)
class SendTaskRequest:
    mode: str
    sendStrategy: str = "burst"
    interfaceName: str = ""
    count: int = 1
    intervalSeconds: float = 0.0
    timeoutSeconds: float = 1.0
    retryCount: int = 0


class SendTaskService:
    """封装 send、sendp 和 sr1 的最小服务层。"""

    def __init__(
        self,
        scapyModule: Any | None = None,
        packetAdapter: ScapyPacketAdapter | None = None,
    ) -> None:
        if scapyModule is None:
            import scapy.all as scapy

            self._scapy = scapy
        else:
            self._scapy = scapyModule
        self._packetAdapter = packetAdapter or ScapyPacketAdapter()

    def buildPacketPreview(self, packet: Any | None) -> Optional[PacketPreview]:
        if packet is None:
            return None
        packetCopy = self._packetAdapter.clonePacket(packet)
        return self._packetAdapter.buildPreview(packetCopy)

    def execute(
        self,
        request: SendTaskRequest,
        packetOrPackets: Any | list[Any] | None,
        stopRequested: Callable[[], bool] | None = None,
        sleep: Callable[[float], None] | None = None,
    ) -> SendTaskResult:
        packets = self._normalize_packets(packetOrPackets)
        if not packets:
            raise ValueError("当前没有可发送的数据包，请先在包构建器中添加协议层。")
        if request.sendStrategy not in {"burst", "continuous"}:
            raise ValueError(f"不支持的发送策略: {request.sendStrategy}")
        if request.mode == "sr1" and request.sendStrategy == "continuous":
            raise ValueError("sr1 当前仅支持 burst 模式，不支持 continuous 持续发送。")

        shouldStop = stopRequested or (lambda: False)
        sleepFn = sleep or time.sleep
        packetPreview = self._packetAdapter.buildPreview(
            self._packetAdapter.clonePacket(packets[0])
        )
        interfaceName = request.interfaceName.strip()
        streamCount = len(packets)
        logLines = [
            f"执行模式: {request.mode}",
            f"发送策略: {request.sendStrategy}",
            f"流数量: {streamCount}",
        ]

        if request.mode == "send":
            sentCount, stoppedEarly = self._run_send_loop(
                packets=packets,
                request=request,
                interfaceName=interfaceName,
                shouldStop=shouldStop,
                sleepFn=sleepFn,
            )
            logLines.extend(
                [
                    "底层发送: send (L3)",
                    f"发送轮次: {'持续发送' if request.sendStrategy == 'continuous' else request.count}",
                    f"发送数量: {sentCount}",
                    f"发送间隔: {request.intervalSeconds:.3f}s",
                ]
            )
            if interfaceName:
                logLines.append("L3 send 由 Scapy 路由自动选择接口，未显式传入 iface。")
            state = TaskState.stopped("发送任务已停止。") if stoppedEarly else TaskState.succeeded("发送任务执行完成。")
            summaryPrefix = "已停止" if stoppedEarly else "已完成"
            summaryText = (
                f"模式: {request.mode}，{summaryPrefix}发送 {sentCount} 个数据包，"
                f"共 {streamCount} 条流，未应答 0 个。"
            )
            return SendTaskResult(
                mode=request.mode,
                sentCount=sentCount,
                packetPreview=packetPreview,
                answerPreview=None,
                unansweredCount=0,
                summaryText=summaryText,
                logText="\n".join(logLines),
                state=state,
            )

        if request.mode == "sendp":
            sentCount, stoppedEarly = self._run_send_loop(
                packets=packets,
                request=request,
                interfaceName=interfaceName,
                shouldStop=shouldStop,
                sleepFn=sleepFn,
            )
            logLines.extend(
                [
                    "底层发送: sendp (L2)",
                    f"发送轮次: {'持续发送' if request.sendStrategy == 'continuous' else request.count}",
                    f"发送数量: {sentCount}",
                    f"发送间隔: {request.intervalSeconds:.3f}s",
                    f"发送接口: {interfaceName or '自动'}",
                ]
            )
            state = TaskState.stopped("发送任务已停止。") if stoppedEarly else TaskState.succeeded("发送任务执行完成。")
            summaryPrefix = "已停止" if stoppedEarly else "已完成"
            summaryText = (
                f"模式: {request.mode}，{summaryPrefix}发送 {sentCount} 个数据包，"
                f"共 {streamCount} 条流，未应答 0 个。"
            )
            return SendTaskResult(
                mode=request.mode,
                sentCount=sentCount,
                packetPreview=packetPreview,
                answerPreview=None,
                unansweredCount=0,
                summaryText=summaryText,
                logText="\n".join(logLines),
                state=state,
            )

        if request.mode == "sr1":
            sentCount, unansweredCount, answerPreview, stoppedEarly = self._run_sr1_loop(
                packets=packets,
                request=request,
                shouldStop=shouldStop,
            )
            logLines.extend(
                [
                    "底层发送: sr1 (L3 请求/响应)",
                    f"发送轮次: {request.count}",
                    f"发送数量: {sentCount}",
                    f"超时时间: {request.timeoutSeconds:.3f}s",
                    f"重试次数: {request.retryCount}",
                ]
            )
            if interfaceName:
                logLines.append("L3 sr1 由 Scapy 路由自动选择接口，未显式传入 iface。")
            logLines.append("收到应答。" if answerPreview is not None else "未收到应答。")
            state = TaskState.stopped("发送任务已停止。") if stoppedEarly else TaskState.succeeded("发送任务执行完成。")
            summaryPrefix = "已停止" if stoppedEarly else "已完成"
            summaryText = (
                f"模式: {request.mode}，{summaryPrefix}发送 {sentCount} 个数据包，"
                f"共 {streamCount} 条流，未应答 {unansweredCount} 个。"
            )
            return SendTaskResult(
                mode=request.mode,
                sentCount=sentCount,
                packetPreview=packetPreview,
                answerPreview=answerPreview,
                unansweredCount=unansweredCount,
                summaryText=summaryText,
                logText="\n".join(logLines),
                state=state,
            )

        raise ValueError(f"不支持的发送模式: {request.mode}")

    def _normalize_packets(self, packetOrPackets: Any | list[Any] | None) -> list[Any]:
        if packetOrPackets is None:
            return []
        if isinstance(packetOrPackets, list):
            return [packet for packet in packetOrPackets if packet is not None]
        return [packetOrPackets]

    def _run_send_loop(
        self,
        packets: list[Any],
        request: SendTaskRequest,
        interfaceName: str,
        shouldStop: Callable[[], bool],
        sleepFn: Callable[[float], None],
    ) -> tuple[int, bool]:
        sentCount = 0
        completedRounds = 0

        while True:
            for packet in packets:
                if shouldStop():
                    return sentCount, True
                sendArgs: dict[str, Any] = {
                    "count": 1,
                    "inter": 0.0,
                    "verbose": False,
                    "return_packets": True,
                }
                if request.mode == "sendp" and interfaceName:
                    sendArgs["iface"] = interfaceName
                sendMethod = self._scapy.sendp if request.mode == "sendp" else self._scapy.send
                sentPackets = sendMethod(self._packetAdapter.clonePacket(packet), **sendArgs)
                sentCount += len(sentPackets or [])
                if request.intervalSeconds > 0 and not shouldStop():
                    sleepFn(request.intervalSeconds)

            completedRounds += 1
            if request.sendStrategy == "burst" and completedRounds >= request.count:
                return sentCount, False

    def _run_sr1_loop(
        self,
        packets: list[Any],
        request: SendTaskRequest,
        shouldStop: Callable[[], bool],
    ) -> tuple[int, int, PacketPreview | None, bool]:
        sentCount = 0
        unansweredCount = 0
        answerPreview: PacketPreview | None = None

        for _roundIndex in range(request.count):
            for packet in packets:
                if shouldStop():
                    return sentCount, unansweredCount, answerPreview, True
                answerPacket = self._scapy.sr1(
                    self._packetAdapter.clonePacket(packet),
                    timeout=request.timeoutSeconds,
                    retry=request.retryCount,
                    verbose=False,
                )
                sentCount += 1
                if answerPacket is None:
                    unansweredCount += 1
                    continue
                answerPreview = self._packetAdapter.buildPreview(answerPacket)

        return sentCount, unansweredCount, answerPreview, False
