from __future__ import annotations

from dataclasses import dataclass

from packet_studio.domain.task_models import TaskPhase, TaskState


@dataclass(frozen=True)
class TaskRecord:
    sequenceNumber: int
    sourceTitle: str
    message: str
    phase: TaskPhase
    detailText: str = ""


@dataclass(frozen=True)
class WorkspacePanelSnapshot:
    panelId: str
    title: str
    taskState: TaskState
    itemCount: int = 0
    detailText: str = ""


@dataclass(frozen=True)
class WorkspaceDocument:
    activeTabTitle: str
    openTabTitles: list[str]
    panelSnapshots: list[WorkspacePanelSnapshot]
    taskRecords: list[TaskRecord]
    interfaceCount: int
    interfaceSummaryText: str

    @property
    def taskCount(self) -> int:
        return len(self.taskRecords)

    def to_multiline_text(self) -> str:
        lines = [
            "工作区状态概览",
            "",
            f"当前页签: {self.activeTabTitle}",
            f"已打开页签数: {len(self.openTabTitles)}",
            f"接口数量: {self.interfaceCount}",
            f"接口摘要: {self.interfaceSummaryText}",
            f"任务记录数: {self.taskCount}",
        ]

        if self.taskRecords:
            latestTask = self.taskRecords[-1]
            lines.append(
                f"最近任务: #{latestTask.sequenceNumber} {latestTask.sourceTitle} / {latestTask.phase.value} / {latestTask.message}"
            )

        lines.append("")
        lines.append("面板快照")
        for snapshot in self.panelSnapshots:
            detailText = f" / {snapshot.detailText}" if snapshot.detailText else ""
            lines.append(
                f"- {snapshot.title}: {snapshot.taskState.phase.value} / {snapshot.taskState.statusText} / 项目数 {snapshot.itemCount}{detailText}"
            )
        return "\n".join(lines)