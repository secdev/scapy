from __future__ import annotations

from packet_studio.domain.task_models import TaskPhase
from packet_studio.domain.workspace_models import TaskRecord, WorkspaceDocument, WorkspacePanelSnapshot


class WorkspaceDocumentService:
    """构建工作区快照与任务记录。"""

    def createTaskRecord(
        self,
        sequenceNumber: int,
        sourceTitle: str,
        message: str,
        phase: TaskPhase,
        detailText: str = "",
    ) -> TaskRecord:
        return TaskRecord(
            sequenceNumber=sequenceNumber,
            sourceTitle=sourceTitle,
            message=message,
            phase=phase,
            detailText=detailText,
        )

    def buildWorkspaceDocument(
        self,
        activeTabTitle: str,
        openTabTitles: list[str],
        panelSnapshots: list[WorkspacePanelSnapshot],
        taskRecords: list[TaskRecord],
        interfaceCount: int,
        interfaceSummaryText: str,
    ) -> WorkspaceDocument:
        return WorkspaceDocument(
            activeTabTitle=activeTabTitle,
            openTabTitles=list(openTabTitles),
            panelSnapshots=list(panelSnapshots),
            taskRecords=list(taskRecords),
            interfaceCount=interfaceCount,
            interfaceSummaryText=interfaceSummaryText,
        )