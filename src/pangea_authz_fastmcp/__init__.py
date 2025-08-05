from __future__ import annotations

from importlib.metadata import version
from typing import TYPE_CHECKING, override

from fastmcp.exceptions import ResourceError, ToolError
from fastmcp.server.dependencies import AccessToken, get_access_token
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
from fastmcp.server.server import add_resource_prefix
from pangea.services import AuthN, AuthZ
from pangea.services.authz import BulkCheckRequestItem, Resource, Subject

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from fastmcp.tools.tool import ToolResult
    from mcp.types import CallToolRequestParams, ReadResourceRequestParams, ReadResourceResult
    from pydantic import AnyUrl

__version__ = version(__package__)

__all__ = ("sanitize_resource_uri", "PangeaAuthzMiddleware")


_DEFAULT_SUBJECT_TYPE = "group"
_DEFAULT_SUBJECT_ACTION = "member"
_DEFAULT_RESOURCE_ACTION = "read"
_DEFAULT_TOOL_ACTION = "call"
_DEFAULT_RESOURCE_RESOURCE_TYPE = "resource"
_DEFAULT_TOOL_RESOURCE_TYPE = "tool"


def sanitize_resource_uri(uri: AnyUrl | str) -> str:
    """
    Sanitize an MCP resource URI.

    This is primarily required because Pangea AuthZ does not support have a
    colon (":") in subject IDs.
    """

    return str(uri).replace(":", "")


class PangeaAuthzMiddleware(Middleware):
    def __init__(
        self,
        *,
        pangea_authz_token: str,
        pangea_authn_token: str | None = None,
        get_subject_ids: Callable[
            [AccessToken, MiddlewareContext[CallToolRequestParams] | MiddlewareContext[ReadResourceRequestParams]],
            Awaitable[list[str]],
        ]
        | None = None,
        prefix: str | None = None,
        subject_type: str = _DEFAULT_SUBJECT_TYPE,
        subject_action: str | None = _DEFAULT_SUBJECT_ACTION,
        resource_action: str = _DEFAULT_RESOURCE_ACTION,
        tool_action: str = _DEFAULT_TOOL_ACTION,
        resource_resource_type: str = _DEFAULT_RESOURCE_RESOURCE_TYPE,
        tool_resource_type: str = _DEFAULT_TOOL_RESOURCE_TYPE,
    ):
        """
        Args:
            pangea_authz_token: Pangea AuthZ API token.
            pangea_authn_token: Pangea AuthN API token.
            get_subject_ids: Function to map an access token to its subject ID(s).
            prefix: Prefix to add to tool names and resource URIs.
            subject_type: Pangea AuthZ subject type.
            subject_action: Pangea AuthZ subject action.
            resource_action: Pangea AuthZ action for MCP resources.
            tool_action: Pangea AuthZ action for MCP tools.
            resource_resource_type: Pangea AuthZ resource type for MCP resources.
            tool_resource_type: Pangea AuthZ resource type for MCP tools.
        """
        if not pangea_authn_token and not get_subject_ids:
            raise ValueError("Either `pangea_authn_token` or `get_subject_ids` must be provided.")

        super().__init__()

        self.authz_client = AuthZ(token=pangea_authz_token)
        self.pangea_authn_token = pangea_authn_token
        self.get_subject_ids = get_subject_ids or self._get_authn_group_ids
        self.prefix = prefix
        self.subject_type = subject_type
        self.subject_action = subject_action
        self.resource_action = resource_action
        self.tool_action = tool_action
        self.resource_resource_type = resource_resource_type
        self.tool_resource_type = tool_resource_type

    async def _get_authn_group_ids(
        self,
        access_token: AccessToken,
        context: MiddlewareContext[CallToolRequestParams] | MiddlewareContext[ReadResourceRequestParams],
    ) -> list[str]:
        if not context.fastmcp_context:
            raise ValueError("Missing FastMCP context")

        try:
            from pangea_authn_fastmcp import PangeaOAuthProvider
        except ImportError:
            raise Exception("pangea-authn-fastmcp package is not installed.")

        auth = context.fastmcp_context.fastmcp.auth
        if not isinstance(auth, PangeaOAuthProvider):
            raise Exception(
                "FastMCP was not configured to use PangeaOAuthProvider from the pangea-authn-fastmcp package."
            )

        verified = await auth.verify_token(access_token.token)
        if not verified:
            raise ValueError("Invalid access token")

        pangea_token = await auth.client_to_authn.get(f"client_to_authn_{verified.client_id}")
        if not pangea_token:
            raise Exception("Could not map MCP client ID to a Pangea AuthN token.")

        assert self.pangea_authn_token
        authn = AuthN(token=self.pangea_authn_token)

        token_check_response = authn.client.token_endpoints.check(pangea_token.token)
        assert token_check_response.result
        user_id = token_check_response.result.identity

        list_groups_response = authn.user.group.list(user_id)
        assert list_groups_response.result
        return [group.id for group in list_groups_response.result.groups]

    @override
    async def on_call_tool(
        self,
        context: MiddlewareContext[CallToolRequestParams],
        call_next: CallNext[CallToolRequestParams, ToolResult],
    ) -> ToolResult:
        access_token: AccessToken | None = get_access_token()

        if context.fastmcp_context and access_token:
            tool = await context.fastmcp_context.fastmcp.get_tool(context.message.name)

            subject_ids = await self.get_subject_ids(access_token, context)

            if len(subject_ids) == 0:
                raise ToolError("Unauthorized")

            bulk_check_response = self.authz_client.bulk_check(
                [
                    BulkCheckRequestItem(
                        subject=Subject(type=self.subject_type, id=subject_id, action=self.subject_action),
                        action=self.tool_action,
                        resource=Resource(
                            type=self.tool_resource_type, id=f"{self.prefix}_{tool.name}" if self.prefix else tool.name
                        ),
                    )
                    for subject_id in subject_ids
                ]
            )
            if bulk_check_response.result and not bulk_check_response.result.allowed:
                raise ToolError("Unauthorized")

        return await call_next(context)

    @override
    async def on_read_resource(
        self,
        context: MiddlewareContext[ReadResourceRequestParams],
        call_next: CallNext[ReadResourceRequestParams, ReadResourceResult],
    ) -> ReadResourceResult:
        access_token: AccessToken | None = get_access_token()

        if context.fastmcp_context and access_token:
            resource = await context.fastmcp_context.fastmcp.get_resource(str(context.message.uri))

            subject_ids = await self.get_subject_ids(access_token, context)

            if len(subject_ids) == 0:
                raise ResourceError("Unauthorized")

            bulk_check_response = self.authz_client.bulk_check(
                [
                    BulkCheckRequestItem(
                        subject=Subject(type=self.subject_type, id=subject_id, action=self.subject_action),
                        action=self.resource_action,
                        resource=Resource(
                            type=self.resource_resource_type,
                            id=sanitize_resource_uri(
                                add_resource_prefix(str(resource.uri), self.prefix) if self.prefix else resource.uri
                            ),
                        ),
                    )
                    for subject_id in subject_ids
                ]
            )
            if bulk_check_response.result and not bulk_check_response.result.allowed:
                raise ResourceError("Unauthorized")

        return await call_next(context)
