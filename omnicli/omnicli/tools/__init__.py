"""OmniCLI tools package.

This package carries two layers:

1. The legacy core tool engine (``omnicli.tools.core``): tool definitions,
   execution dispatch, workspace/file/bash/verify tools, and the helpers
   other modules import (``TOOL_DEFINITIONS``, ``execute_tool_call``,
   ``resolve_workspace_root``, ``_iter_workspace_files``, ...).

2. The agent-framework tools (OpenManus-inspired): ``ComputerUseTool``,
   ``Crawl4aiTool``, ``PlanningTool``, ``PythonExecuteTool``.

``omnicli.tools`` must present the SAME import surface the old single-module
``omnicli/tools.py`` presented: callers do ``from omnicli.tools import X`` for
public and underscore names alike. Every non-dunder attribute defined by
``core`` is therefore mirrored onto this package namespace.
"""

from types import ModuleType as _ModuleType

from omnicli.tools import core as _core

# Mirror the full core surface (public + underscore helpers) so existing
# imports keep resolving exactly as they did before the package split.
for _name in dir(_core):
    if _name.startswith("__"):
        continue
    _value = getattr(_core, _name)
    if isinstance(_value, _ModuleType):
        continue  # never re-export core's own stdlib imports
    globals()[_name] = _value
del _name, _value, _ModuleType, _core

# Agent-framework tools (explicit exports)
from omnicli.tools.computer_use import ComputerUseTool  # noqa: E402
from omnicli.tools.crawl4ai import Crawl4aiTool  # noqa: E402
from omnicli.tools.planning import PlanningTool  # noqa: E402
from omnicli.tools.python_execute import PythonExecuteTool  # noqa: E402

__all__ = [
    # legacy core surface
    "TOOL_DEFINITIONS",
    "execute_tool_call",
    "resolve_workspace_root",
    "resolve_workspace_path",
    "registry_db_path",
    "scan_directory_sources",
    "check_workspace_jail",
    "format_tool_error",
    "tool_bash",
    "tool_edit_file",
    "tool_find_files",
    "tool_list_directory",
    "tool_read_file",
    "tool_search_code",
    "tool_verify_code",
    "tool_verify_consensus",
    "tool_verify_http",
    "tool_write_file",
    "tool_analyze_python_security",
    "tool_registry_search",
    "detect_truncated_rewrite",
    # agent-framework tools
    "ComputerUseTool",
    "Crawl4aiTool",
    "PlanningTool",
    "PythonExecuteTool",
]
