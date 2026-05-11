from __future__ import annotations

import unittest

from packet_studio.domain.task_models import TaskPhase, TaskState
from packet_studio.domain.workspace_models import WorkspacePanelSnapshot
from packet_studio.services.workspace_document_service import WorkspaceDocumentService


class WorkspaceDocumentServiceTests(unittest.TestCase):
    def test_create_task_record_assigns_fields(self) -> None:
        service = WorkspaceDocumentService()

        record = service.createTaskRecord(
            sequenceNumber=3,
            sourceTitle="发送任务",
            message="发送任务执行完成。",
            phase=TaskPhase.SUCCEEDED,
            detailText="模式: send",
        )

        self.assertEqual(record.sequenceNumber, 3)
        self.assertEqual(record.sourceTitle, "发送任务")
        self.assertEqual(record.phase, TaskPhase.SUCCEEDED)
        self.assertEqual(record.detailText, "模式: send")

    def test_build_workspace_document_generates_summary_text(self) -> None:
        service = WorkspaceDocumentService()
        panelSnapshots = [
            WorkspacePanelSnapshot(
                panelId="send-task",
                title="发送任务",
                taskState=TaskState.succeeded("发送任务执行完成。"),
                itemCount=1,
                detailText="模式: send",
            ),
        ]
        taskRecords = [
            service.createTaskRecord(1, "发送任务", "发送任务执行完成。", TaskPhase.SUCCEEDED),
        ]

        document = service.buildWorkspaceDocument(
            activeTabTitle="发送任务",
            openTabTitles=["欢迎", "发送任务"],
            panelSnapshots=panelSnapshots,
            taskRecords=taskRecords,
            interfaceCount=2,
            interfaceSummaryText="已发现 2 个可用接口。",
        )

        self.assertEqual(document.taskCount, 1)
        summaryText = document.to_multiline_text()
        self.assertIn("当前页签: 发送任务", summaryText)
        self.assertIn("任务记录数: 1", summaryText)
        self.assertIn("发送任务", summaryText)


if __name__ == "__main__":
    unittest.main()