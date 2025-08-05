from __future__ import annotations

import contextlib
from typing import TYPE_CHECKING, Any, Unpack

from fastmcp.client.transports import FastMCPTransport, MCPConfigTransport, SessionKwargs
from fastmcp.mcp_config import MCPConfig
from fastmcp.server.server import FastMCP

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from mcp import ClientSession

__all = ("CompositeMCPConfigTransport",)


class CompositeMCPConfigTransport(MCPConfigTransport):
    """
    A `MCPConfigTransport` that always creates a composite client by mounting
    all servers on a single FastMCP instance, with each server's name used as
    its mounting prefix.

    Tools are accessible with the prefix pattern `{server_name}_{tool_name}`
    and resources with the pattern `protocol://{server_name}/path/to/resource`.
    """

    def __init__(self, config: MCPConfig | dict[str, Any]):
        if isinstance(config, dict):
            config = MCPConfig.from_dict(config)
        self.config = config

        if len(self.config.mcpServers) == 0:
            raise ValueError("No MCP servers defined in the config")

        composite_server = FastMCP()

        for name, server in self.config.mcpServers.items():
            composite_server.mount(
                prefix=name,
                server=FastMCP.as_proxy(backend=server.to_transport()),
            )

        self.transport = FastMCPTransport(mcp=composite_server)  # type: ignore[assignment]

    @contextlib.asynccontextmanager
    async def connect_session(self, **session_kwargs: Unpack[SessionKwargs]) -> AsyncIterator[ClientSession]:
        async with self.transport.connect_session(**session_kwargs) as session:
            yield session

    def __repr__(self) -> str:
        return f"<CompositeMCPConfigTransport(config='{self.config}')>"
