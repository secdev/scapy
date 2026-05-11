from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional

from packet_studio.domain.packet_models import PacketPreview, PcapPacketRecord


class TaskPhase(str, Enum):
    IDLE = "idle"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    PAUSED = "paused"
    STOPPED = "stopped"


@dataclass(frozen=True)
class TaskState:
    phase: TaskPhase
    statusText: str

    @classmethod
    def idle(cls, statusText: str) -> "TaskState":
        return cls(TaskPhase.IDLE, statusText)

    @classmethod
    def running(cls, statusText: str) -> "TaskState":
        return cls(TaskPhase.RUNNING, statusText)

    @classmethod
    def succeeded(cls, statusText: str) -> "TaskState":
        return cls(TaskPhase.SUCCEEDED, statusText)

    @classmethod
    def failed(cls, statusText: str) -> "TaskState":
        return cls(TaskPhase.FAILED, statusText)

    @classmethod
    def paused(cls, statusText: str) -> "TaskState":
        return cls(TaskPhase.PAUSED, statusText)

    @classmethod
    def stopped(cls, statusText: str) -> "TaskState":
        return cls(TaskPhase.STOPPED, statusText)


@dataclass(frozen=True)
class TaskError:
    message: str
    logText: str = ""
    state: TaskState = TaskState.failed("任务失败。")

    @property
    def summaryText(self) -> str:
        return self.message


@dataclass(frozen=True)
class SendTaskResult:
    mode: str
    sentCount: int
    packetPreview: PacketPreview
    answerPreview: Optional[PacketPreview]
    unansweredCount: int
    summaryText: str
    logText: str
    state: TaskState = TaskState.succeeded("发送任务执行完成。")


@dataclass(frozen=True)
class CaptureStopResult:
    capturedCount: int
    storedResultCount: int
    summaryText: str
    logText: str = ""
    state: TaskState = TaskState.stopped("抓包已停止。")


@dataclass(frozen=True)
class PcapLoadResult:
    filePath: str
    packetRecords: list[PcapPacketRecord]
    summaryText: str
    logText: str = ""
    state: TaskState = TaskState.succeeded("离线抓包文件加载完成。")

    @property
    def packetCount(self) -> int:
        return len(self.packetRecords)