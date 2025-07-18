from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Annotated

import cyclopts
import pyjson5
from beaupy import select_multiple  # type: ignore[import-untyped]
from fastmcp import Client
from fastmcp.mcp_config import MCPConfig
from google_auth_oauthlib.flow import InstalledAppFlow  # type: ignore[import-untyped]
from googleapiclient.discovery import build
from pangea.services import AuthZ
from pangea.services.authz import Resource, Subject, Tuple

import pangea_authz_fastmcp
from pangea_authz_fastmcp.cli.transports import CompositeMCPConfigTransport

_DEFAULT_SUBJECT_TYPE = "group"
_DEFAULT_RELATION = "caller"
_DEFAULT_RESOURCE_TYPE = "tool"

if sys.platform == "linux" or sys.platform == "linux2":
    _CLIENT_PATHS = {
        "cursor": ["~/.cursor/mcp.json"],
        "windsurf": ["~/.codeium/windsurf/mcp_config.json"],
    }
    _WELL_KNOWN_MCP_PATHS = [path for _client, paths in _CLIENT_PATHS.items() for path in paths]
elif sys.platform == "darwin":
    _CLIENT_PATHS = {
        "claude": ["~/Library/Application Support/Claude/claude_desktop_config.json"],
        "cursor": ["~/.cursor/mcp.json"],
        "windsurf": ["~/.codeium/windsurf/mcp_config.json"],
    }
    _WELL_KNOWN_MCP_PATHS = [path for _client, paths in _CLIENT_PATHS.items() for path in paths]
elif sys.platform == "win32":
    _CLIENT_PATHS = {
        "claude": ["~/AppData/Roaming/Claude/claude_desktop_config.json"],
        "cursor": ["~/.cursor/mcp.json"],
        "windsurf": ["~/.codeium/windsurf/mcp_config.json"],
    }

    _WELL_KNOWN_MCP_PATHS = [path for _client, paths in _CLIENT_PATHS.items() for path in paths]
else:
    _WELL_KNOWN_MCP_PATHS = []


app = cyclopts.App(name="pangea-authz-fastmcp", help="TODO", version=pangea_authz_fastmcp.__version__)


@app.command
async def google_workspace(
    customer: Annotated[
        str | None, cyclopts.Parameter("--customer", help="The unique ID for the customer's Google Workspace account.")
    ] = None,
    domain: Annotated[
        str | None,
        cyclopts.Parameter(
            "--domain",
            help="The domain name. Use this flag to get groups from only one "
            "domain. To return all domains for a customer account, use the "
            "`--customer` flag instead.",
        ),
    ] = None,
    credentials: Annotated[
        cyclopts.types.ExistingJsonPath,
        cyclopts.Parameter("--credentials", help="The path to the credentials file."),
    ] = Path("credentials.json"),
    max_groups: Annotated[
        int,
        cyclopts.Parameter(
            "--max-groups",
            help="Maximum number of groups to fetch.",
            validator=cyclopts.validators.Number(gte=0, lte=200),
        ),
    ] = 30,
    files: Annotated[
        list[str], cyclopts.Parameter("--files", help="Files to discover MCP servers from.")
    ] = _WELL_KNOWN_MCP_PATHS,
    subject_type: Annotated[str, cyclopts.Parameter("--subject-type")] = _DEFAULT_SUBJECT_TYPE,
    relation: Annotated[str, cyclopts.Parameter("--relation")] = _DEFAULT_RELATION,
    resource_type: Annotated[str, cyclopts.Parameter("--resource-type")] = _DEFAULT_RESOURCE_TYPE,
) -> None:
    pangea_authz_token = os.getenv("PANGEA_AUTHZ_TOKEN")
    if not pangea_authz_token:
        raise ValueError("Missing `PANGEA_AUTHZ_TOKEN` environment variable.")

    if not customer and not domain:
        raise ValueError("Either --customer or --domain must be provided.")

    flow = InstalledAppFlow.from_client_secrets_file(
        credentials, ["https://www.googleapis.com/auth/admin.directory.group.readonly"]
    )
    google_credentials = flow.run_local_server(port=0)
    service = build("admin", "directory_v1", credentials=google_credentials)
    if customer:
        groups_list = service.groups().list(customer=customer, maxResults=max_groups).execute()
    elif domain:
        groups_list = service.groups().list(domain=domain, maxResults=max_groups).execute()
    else:
        raise ValueError("Either --customer or --domain must be provided.")

    groups = groups_list.get("groups", [])

    print("Which groups would you like to grant tool access for?")
    selected_groups = select_multiple(groups, preprocessor=lambda group: f"({group['id']}) {group['name']}")
    print()

    existing_files = [Path(file).expanduser() for file in files if Path(file).expanduser().exists()]
    print("Found the following MCP config files:")
    for file in existing_files:
        print(f"  - {file}")
    print()

    merged_mcp_config = MCPConfig(mcpServers={})
    for file in existing_files:
        content = file.read_text("utf-8")
        raw_config = pyjson5.loads(content)
        mcp_config = MCPConfig.from_dict(raw_config)
        merged_mcp_config.mcpServers.update(mcp_config.mcpServers)

    mcp_client = Client(CompositeMCPConfigTransport(merged_mcp_config))

    print("Connecting to MCP servers...")
    async with mcp_client:
        tools = await mcp_client.list_tools()
        tool_names = {tool.name for tool in tools}

    print("Which tools would you like these groups to be able to call?")
    selected_tools = select_multiple(sorted(tool_names))
    print()

    authz = AuthZ(token=pangea_authz_token)
    authz.tuple_create(
        [
            Tuple(
                subject=Subject(type=subject_type, id=group["id"], action="member"),
                relation=relation,
                resource=Resource(type=resource_type, id=tool),
            )
            for tool in selected_tools
            for group in selected_groups
        ]
    )

    print(f"Created {len(selected_groups) * len(selected_tools)} AuthZ tuples.")

    await mcp_client.close()
    sys.exit(0)


if __name__ == "__main__":
    app()
