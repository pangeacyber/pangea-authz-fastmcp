from __future__ import annotations

from importlib.metadata import version
from typing import TYPE_CHECKING, override

from fastmcp.exceptions import ToolError
from fastmcp.server.dependencies import AccessToken, get_access_token
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
from pangea.services import AuthN, AuthZ
from pangea.services.authz import Resource, Subject

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from mcp.types import CallToolRequestParams, CallToolResult

__version__ = version(__package__)

__all__ = ("PangeaAuthzMiddleware",)


_DEFAULT_SUBJECT_TYPE = "group"
_DEFAULT_SUBJECT_ACTION = "member"
_DEFAULT_ACTION = "call"
_DEFAULT_RESOURCE_TYPE = "tool"


class PangeaAuthzMiddleware(Middleware):
    def __init__(
        self,
        *,
        pangea_authz_token: str,
        pangea_authn_token: str | None = None,
        get_subject_ids: Callable[[AccessToken, MiddlewareContext[CallToolRequestParams]], Awaitable[list[str]]]
        | None = None,
        subject_type: str = _DEFAULT_SUBJECT_TYPE,
        subject_action: str | None = _DEFAULT_SUBJECT_ACTION,
        action: str = _DEFAULT_ACTION,
        resource_type: str = _DEFAULT_RESOURCE_TYPE,
    ):
        if not pangea_authn_token and not get_subject_ids:
            raise ValueError("Either `pangea_authn_token` or `get_subject_ids` must be provided.")

        super().__init__()

        self.authz_client = AuthZ(token=pangea_authz_token)
        self.pangea_authn_token = pangea_authn_token
        self.get_subject_ids = get_subject_ids or self._get_authn_group_ids
        self.subject_type = subject_type
        self.subject_action = subject_action
        self.action = action
        self.resource_type = resource_type

    async def _get_authn_group_ids(
        self, access_token: AccessToken, context: MiddlewareContext[CallToolRequestParams]
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
        call_next: CallNext[CallToolRequestParams, CallToolResult],
    ) -> CallToolResult:
        access_token: AccessToken | None = get_access_token()

        if context.fastmcp_context and access_token:
            tool = await context.fastmcp_context.fastmcp.get_tool(context.message.name)

            subject_ids = await self.get_subject_ids(access_token, context)

            # TODO: use bulk check endpoint.
            if not any(
                (resp.result and resp.result.allowed)
                for resp in (
                    self.authz_client.check(
                        subject=Subject(type=self.subject_type, id=subject_id, action=self.subject_action),
                        action=self.action,
                        resource=Resource(type=self.resource_type, id=tool.name),
                    )
                    for subject_id in subject_ids
                )
            ):
                raise ToolError("Unauthorized")

        return await call_next(context)
