"""OmniCLI package."""
__version__ = "1.0.0"

# Fix IPv6 TCP SYN blackhole on Linux environments
import socket
_orig_getaddrinfo = socket.getaddrinfo
def _ipv4_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    return _orig_getaddrinfo(host, port, socket.AF_INET, type, proto, flags)
socket.getaddrinfo = _ipv4_getaddrinfo

# Agent framework exports (OpenManus-inspired agent architecture)
from omnicli.base_tool import BaseTool, ToolResult
from omnicli.tool_collection import ToolCollection
from omnicli.base_agent import AgentState, BaseAgent, Memory
from omnicli.tool_call_agent import ToolCallAgent
from omnicli.mcp_client import MCPClientTool, MCPClients
from omnicli.tools.computer_use import ComputerUseTool
from omnicli.tools.crawl4ai import Crawl4aiTool
from omnicli.tools.planning import PlanningTool
from omnicli.tools.python_execute import PythonExecuteTool

__all__ = [
    "BaseTool",
    "ToolResult",
    "ToolCollection",
    "AgentState",
    "BaseAgent",
    "Memory",
    "ToolCallAgent",
    "MCPClientTool",
    "MCPClients",
    "ComputerUseTool",
    "Crawl4aiTool",
    "PlanningTool",
    "PythonExecuteTool",
]

