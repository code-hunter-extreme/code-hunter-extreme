"""
MCP (Model Context Protocol) client for OmniCLI.

Connects to MCP servers (stdio or SSE), auto-discovers their tools, and
wraps them as OmniCLI BaseTool instances for use by agents.

Modeled after OpenManus's MCP client implementation.
"""

from __future__ import annotations

import asyncio
import os
from contextlib import AsyncExitStack
from typing import Any, Dict, List, Optional

from mcp import ClientSession, StdioServerParameters
from mcp.client.sse import sse_client
from mcp.client.stdio import stdio_client
from mcp.types import ImageContent, ListToolsResult, TextContent

from omnicli.base_tool import BaseTool, ToolResult
from omnicli.tool_collection import ToolCollection
from pydantic import Field


class MCPClientTool(BaseTool):
    """Represents a tool exposed by a remote MCP server.

    Calls are forwarded to the MCP server via its ClientSession.
    """

    session: Optional[ClientSession] = Field(default=None, exclude=True)
    server_id: str = Field(default="", exclude=True)
    original_name: str = Field(default="")

    async def execute(self, **kwargs: Any) -> ToolResult:
        """Call the tool on the remote MCP server."""
        if not self.session:
            return ToolResult(error="Not connected to MCP server")
        try:
            result = await self.session.call_tool(self.original_name, kwargs)
            content_str = ", ".join(
                item.text
                for item in result.content
                if isinstance(item, TextContent)
            )
            image = next(
                (item.data for item in result.content if isinstance(item, ImageContent)),
                None,
            )
            return ToolResult(
                output=content_str or ("Image returned." if image else "No output returned."),
                base64_image=image,
            )
        except Exception as exc:  # noqa: BLE001
            return ToolResult(error=f"Error executing MCP tool: {exc}")


class MCPClients(ToolCollection):
    """
    Collection of tools connected to MCP servers.

    Manages connections to multiple MCP servers (stdio or SSE transport),
    auto-discovers their tools, and wraps them as MCPClientTool instances
    for use by agents.
    """

    sessions: Dict[str, ClientSession] = Field(default_factory=dict, exclude=True)
    exit_stacks: Dict[str, AsyncExitStack] = Field(default_factory=dict, exclude=True)
    server_instructions: Dict[str, str] = Field(default_factory=dict, exclude=True)

    class Config:
        arbitrary_types_allowed = True

    def __init__(self, **data: Any):
        super().__init__(**data)
        self.name = "mcp"
        self.sessions: Dict[str, ClientSession] = {}
        self.exit_stacks: Dict[str, AsyncExitStack] = {}
        self.server_instructions: Dict[str, str] = {}

    async def connect_sse(self, server_url: str, server_id: Optional[str] = None) -> None:
        """Connect to an MCP server using SSE transport."""
        if not server_url:
            raise ValueError("Server URL is required.")
        server_id = server_id or server_url

        if server_id in self.sessions:
            await self.disconnect(server_id)

        exit_stack = AsyncExitStack()
        self.exit_stacks[server_id] = exit_stack

        streams_context = sse_client(url=server_url)
        streams = await exit_stack.enter_async_context(streams_context)
        session = await exit_stack.enter_async_context(ClientSession(*streams))
        self.sessions[server_id] = session

        await self._initialize_and_list_tools(server_id)

    async def connect_stdio(
        self,
        command: str,
        args: Optional[List[str]] = None,
        server_id: Optional[str] = None,
        tool_name_prefix: bool = True,
        env: Optional[Dict[str, str]] = None,
    ) -> None:
        """Connect to an MCP server using stdio transport."""
        if not command:
            raise ValueError("Server command is required.")
        server_id = server_id or command

        if server_id in self.sessions:
            await self.disconnect(server_id)

        exit_stack = AsyncExitStack()
        self.exit_stacks[server_id] = exit_stack

        server_params = StdioServerParameters(command=command, args=args or [], env=env)
        stdio_transport = await exit_stack.enter_async_context(
            stdio_client(server_params)
        )
        read, write = stdio_transport
        session = await exit_stack.enter_async_context(ClientSession(read, write))
        self.sessions[server_id] = session

        await self._initialize_and_list_tools(server_id, tool_name_prefix=tool_name_prefix)

    async def _initialize_and_list_tools(
        self,
        server_id: str,
        tool_name_prefix: bool = True,
    ) -> None:
        """Initialize session and populate tool map from server capabilities."""
        session = self.sessions.get(server_id)
        if not session:
            raise RuntimeError(f"Session not initialized for server {server_id}")

        initialization = await session.initialize()
        if initialization.instructions:
            self.server_instructions[server_id] = initialization.instructions
        response: ListToolsResult = await session.list_tools()

        for tool in response.tools:
            original_name = tool.name
            tool_name = (
                f"mcp_{server_id}_{original_name}"
                if tool_name_prefix
                else original_name
            )
            tool_name = self._sanitize_tool_name(tool_name)

            server_tool = MCPClientTool(
                name=tool_name,
                description=tool.description or "",
                parameters=tool.inputSchema or {},
                session=session,
                server_id=server_id,
                original_name=original_name,
            )
            self.tool_map[tool_name] = server_tool

        self.tools = tuple(self.tool_map.values())

    def _sanitize_tool_name(self, name: str) -> str:
        """Sanitize tool names to valid identifier characters."""
        import re
        sanitized = re.sub(r"[^a-zA-Z0-9_-]", "_", name)
        sanitized = re.sub(r"_+", "_", sanitized)
        sanitized = sanitized.strip("_")
        if len(sanitized) > 64:
            sanitized = sanitized[:64]
        return sanitized

    async def disconnect(self, server_id: Optional[str] = "") -> None:
        """Disconnect from a specific MCP server or all servers."""
        if server_id:
            if server_id in self.sessions:
                try:
                    exit_stack = self.exit_stacks.get(server_id)
                    if exit_stack:
                        try:
                            await exit_stack.aclose()
                        except RuntimeError:
                            pass
                    self.sessions.pop(server_id, None)
                    self.exit_stacks.pop(server_id, None)
                    self.server_instructions.pop(server_id, None)
                    self.tool_map = {
                        k: v
                        for k, v in self.tool_map.items()
                        if v.server_id != server_id
                    }
                    self.tools = tuple(self.tool_map.values())
                except Exception as exc:  # noqa: BLE001
                    import logging
                    logger = logging.getLogger(__name__)
                    logger.error(f"Error disconnecting from server {server_id}: {exc}")
        else:
            for sid in sorted(list(self.sessions.keys())):
                await self.disconnect(sid)
            self.tool_map = {}
            self.tools = tuple()

    async def cleanup(self) -> None:
        """Disconnect from all MCP servers."""
        await self.disconnect()