"""Thin stdio MCP interface; all enrichment logic lives in the Python library."""
import asyncio
from dataclasses import asdict
from .lookup import LookupClient
from .methods import list_methods as catalogue
from .models import IOC

class LookupTools:
    """Ordinary callables shared by MCP and integration tests."""
    def __init__(self, client=None):
        self.client = client or LookupClient()
    def list_methods(self, input_type: str = "", implemented_only: bool = False) -> list[dict]:
        return [{**asdict(m), "implemented": m.implemented, "description": m.description}
                for m in catalogue(input_type or None, implemented_only=implemented_only)]
    def lookup_ioc(self, value: str, ioc_type: str, method_id: str) -> list[dict]:
        return [asdict(ioc) for ioc in self.client.lookup(IOC(value, ioc_type), method_id)]
    def get_latest_lookup(self, value: str, ioc_type: str, method_id: str) -> dict:
        return self.client.latest_record(IOC(value, ioc_type), method_id) or {}
    def get_lookup_evidence(self, lookup_id: str, include_raw: bool = False) -> dict:
        record = self.client.store.get_record(lookup_id)
        if include_raw:
            record["raw_responses"] = [self.client.store.get_snapshot(r["snapshot_id"]) for r in record["responses"]]
        return record

def create_server(client=None):
    from mcp.server.fastmcp import FastMCP
    server = FastMCP("IOC Hunter")
    tools = LookupTools(client)
    @server.tool(description="List directed methods and unavailable catalogue candidates.")
    async def list_methods(input_type: str = "", implemented_only: bool = False) -> list[dict]:
        return tools.list_methods(input_type, implemented_only)

    @server.tool(description="Return validated related IOCs; no expansion scoring or graph mutation.")
    async def lookup_ioc(value: str, ioc_type: str, method_id: str) -> list[dict]:
        # Sync Playwright cannot run inside the SDK's asyncio loop.
        return await asyncio.to_thread(tools.lookup_ioc, value, ioc_type, method_id)

    @server.tool(description="Get the latest lookup ID, status and completeness for an IOC/method.")
    async def get_latest_lookup(value: str, ioc_type: str, method_id: str) -> dict:
        return await asyncio.to_thread(tools.get_latest_lookup, value, ioc_type, method_id)

    @server.tool(description="Read stored evidence and optionally raw responses for a lookup ID.")
    async def get_lookup_evidence(lookup_id: str, include_raw: bool = False) -> dict:
        return await asyncio.to_thread(tools.get_lookup_evidence, lookup_id, include_raw)

    return server

def main():
    try:
        create_server().run(transport="stdio")
    except ImportError as exc:
        raise SystemExit("Install the mcp optional dependency: pip install -e .[mcp]") from exc

if __name__ == "__main__":
    main()
