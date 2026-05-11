from __future__ import annotations

import unittest

from packet_studio.services.tool_registry_service import ToolRegistryService


class ToolRegistryServiceTests(unittest.TestCase):
    def test_list_tools_contains_core_entries(self) -> None:
        service = ToolRegistryService()

        tools = service.listTools()

        self.assertGreaterEqual(len(tools), 3)
        titles = [tool.title for tool in tools]
        self.assertIn("包构建器", titles)
        self.assertIn("发送任务", titles)
        self.assertIn("离线分析", titles)


if __name__ == "__main__":
    unittest.main()