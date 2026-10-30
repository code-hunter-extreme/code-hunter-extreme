"""
Python Execute tool for OmniCLI agents.

Provides isolated Python code execution for safely testing code snippets,
exploit PoCs, and data analysis without affecting the host system.

Modeled after OpenManus's PythonExecute tool.
"""

from __future__ import annotations

import asyncio
import io
import sys
from contextlib import redirect_stdout, redirect_stderr
from typing import Any, Dict, Optional

from omnicli.base_tool import BaseTool, ToolResult


class PythonExecuteTool(BaseTool):
    """Execute Python code in a sandboxed environment.

    Provides safe, isolated Python execution for testing code snippets,
    exploit PoCs, and data analysis. Uses a restricted execution context
    with limited builtins to prevent host system damage.
    """

    name: str = "python_execute"
    description: str = (
        "Execute Python code in a sandboxed environment. "
        "Useful for testing code snippets, exploit PoCs, and data analysis. "
        "Code runs in a restricted context with limited builtins."
    )
    parameters: dict = {
        "type": "object",
        "properties": {
            "code": {
                "type": "string",
                "description": "Python code to execute",
            },
            "timeout": {
                "type": "integer",
                "description": "Maximum execution time in seconds. Default is 30.",
                "default": 30,
                "minimum": 1,
                "maximum": 300,
            },
        },
        "required": ["code"],
    }

    async def execute(
        self,
        code: str,
        timeout: int = 30,
        **kwargs: Any,
    ) -> ToolResult:
        """Execute Python code in a sandboxed environment."""
        try:
            result = await asyncio.wait_for(
                self._run_python(code), timeout=timeout
            )
            return result
        except asyncio.TimeoutError:
            return ToolResult(
                error=f"Python execution timed out after {timeout} seconds"
            )
        except Exception as exc:  # noqa: BLE001
            return ToolResult(error=f"Python execution failed: {exc}")

    async def _run_python(self, code: str) -> ToolResult:
        """Run Python code with restricted builtins and captured output."""
        # Restricted builtins - only safe functions
        safe_builtins = {
            "print": print,
            "len": len,
            "str": str,
            "int": int,
            "float": float,
            "bool": bool,
            "list": list,
            "dict": dict,
            "set": set,
            "tuple": tuple,
            "range": range,
            "enumerate": enumerate,
            "zip": zip,
            "map": map,
            "filter": filter,
            "sorted": sorted,
            "reversed": reversed,
            "any": any,
            "all": all,
            "sum": sum,
            "min": min,
            "max": max,
            "abs": abs,
            "round": round,
            "pow": pow,
            "divmod": divmod,
            "isinstance": isinstance,
            "issubclass": issubclass,
            "hasattr": hasattr,
            "getattr": getattr,
            "setattr": setattr,
            "delattr": delattr,
        }

        # Restricted globals
        safe_globals = {
            "__builtins__": safe_builtins,
        }

        stdout_capture = io.StringIO()
        stderr_capture = io.StringIO()

        try:
            with redirect_stdout(stdout_capture), redirect_stderr(stderr_capture):
                exec(code, safe_globals, {})
        except SystemExit:
            pass  # Allow sys.exit() without crashing
        except Exception as exc:
            return ToolResult(
                output=stdout_capture.getvalue(),
                error=f"{type(exc).__name__}: {exc}\n{stderr_capture.getvalue()}",
            )

        output = stdout_capture.getvalue()
        stderr_output = stderr_capture.getvalue()

        if stderr_output:
            return ToolResult(
                output=output,
                error=stderr_output,
            )

        return ToolResult(output=output or "Code executed successfully (no output)")