from __future__ import annotations

from typing import TYPE_CHECKING

from fastmcp import FastMCP

from pangea_authz_fastmcp import PangeaAuthzMiddleware

if TYPE_CHECKING:
    from fastmcp.server.dependencies import AccessToken
    from fastmcp.server.middleware import MiddlewareContext
    from mcp.types import CallToolRequestParams, ReadResourceRequestParams


async def get_subject_ids(
    access_token: AccessToken,
    context: MiddlewareContext[CallToolRequestParams] | MiddlewareContext[ReadResourceRequestParams],
) -> list[str]:
    return ["id1", "id2"]


def test_middleware() -> None:
    mcp = FastMCP(name="My MCP Server")
    mcp.add_middleware(PangeaAuthzMiddleware(pangea_authz_token="pangea_authz_token", get_subject_ids=get_subject_ids))
    assert mcp.middleware
    assert len(mcp.middleware) == 1
