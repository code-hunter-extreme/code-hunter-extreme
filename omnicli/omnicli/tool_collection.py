"""
Tool collection for managing and executing registered tools.

Provides a registry of BaseTool instances with name-based lookup and
async execution. Mirrors OpenManus's ToolCollection pattern.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from omnicli.base_tool import BaseTool, ToolResult


class ToolCollection(BaseModel):
    """Collection of registered agent tools.

    Provides name-based lookup and async execution. Tools are added
    via add_tool() and looked up by name for execution.
    """

    class Config:
        arbitrary_types_allowed = True

    tools: List[BaseTool] = Field(default_factory=list)
    tool_map: Dict[str, BaseTool] = Field(default_factory=dict)

    def __init__(self, *tools: BaseTool, **data: Any):
        super().__init__(tools=list(tools), **data)
        self.tool_map = {tool.name: tool for tool in self.tools}

    def __iter__(self):
        return iter(self.tools)

    def to_params(self) -> List[Dict[str, Any]]:
        """Convert all tools to OpenAI-compatible function-calling parameters."""
        return [tool.to_param() for tool in self.tools]

    async def execute(
        self, *, name: str, tool_input: Optional[Dict[str, Any]] = None
    ) -> ToolResult:
        """Execute a registered tool by name with the given input dict."""
        tool = self.tool_map.get(name)
        if not tool:
            return ToolResult(error=f"Tool {name} is invalid")
        try:
            tool_input = tool_input or {}
            result = await tool(**tool_input)
            return result
        except Exception as e:  # noqa: BLE001
            return ToolResult(error=f"Tool {name} error: {e}")

    def get_tool(self, name: str) -> Optional[BaseTool]:
        """Return a registered tool by name, or None if not found."""
        return self.tool_map.get(name)

    def add_tool(self, tool: BaseTool) -> "ToolCollection":
        """Add a single tool to the collection.

        If a tool with the same name already exists, it is skipped.
        """
        if tool.name in self.tool_map:
            return self
        self.tools.append(tool)
        self.tool_map[tool.name] = tool
        return self

    def add_tools(self, *tools: BaseTool) -> "ToolCollection":
        """Add multiple tools to the collection."""
        for tool in tools:
            self.add_tool(tool)
        return self