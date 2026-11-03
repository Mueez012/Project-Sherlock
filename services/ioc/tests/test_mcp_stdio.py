"""Real stdio protocol smoke check; no enrichment/network requests."""
import importlib.util
from pathlib import Path
import sys
import unittest

@unittest.skipUnless(importlib.util.find_spec("mcp"), "Optional MCP SDK not installed")
class MCPStdioTests(unittest.IsolatedAsyncioTestCase):
    async def test_server_handshake_and_method_discovery(self):
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client
        params = StdioServerParameters(command=sys.executable,
                                       args=["-m", "ioc_hunter.mcp_server"],
                                       cwd=str(Path(__file__).resolve().parents[1]))
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                tools = await session.list_tools()
                self.assertIn("lookup_ioc", {tool.name for tool in tools.tools})
                methods = await session.call_tool("list_methods", {"input_type": "domain", "implemented_only": True})
                self.assertFalse(methods.isError)
                self.assertIn("rapiddns.domain_to_ipv4", str(methods.content))

if __name__ == "__main__":
    unittest.main()
