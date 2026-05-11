from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ToolRegistration:
    toolId: str
    title: str
    description: str
    targetTabTitle: str
    category: str


class ToolRegistryService:
    """提供最小内置工具注册表。"""

    def listTools(self) -> list[ToolRegistration]:
        return [
            ToolRegistration(
                toolId="packet-builder",
                title="包构建器",
                description="构建多层数据包，逐字段编辑并实时查看结构与十六进制预览。",
                targetTabTitle="包构建器",
                category="核心工作流",
            ),
            ToolRegistration(
                toolId="send-task",
                title="发送任务",
                description="执行 send、sendp、sr1 任务，并查看请求响应结果。",
                targetTabTitle="发送任务",
                category="核心工作流",
            ),
            ToolRegistration(
                toolId="offline-analysis",
                title="离线分析",
                description="打开 pcap 或 pcapng 文件，浏览离线抓包结果并复制回构建器。",
                targetTabTitle="离线分析",
                category="核心工作流",
            ),
        ]