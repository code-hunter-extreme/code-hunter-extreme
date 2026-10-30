"""
Base tool abstraction for OmniCLI agent tool calling.

Modeled after OpenManus's tool system: every tool has a name, description,
JSON-schema parameters, and an async execute() method returning a ToolResult.
Tools are registered in a ToolCollection and called by name from the agent's
think/act loop.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field


class ToolResult(BaseModel):
    """Result of a tool execution.

    output:   Human-readable result text (success case).
    error:    Error message if execution failed.
    base64_image: Optional base64-encoded image (screenshots, etc.).
    system:   Optional system-level metadata.
    """

    output: Optional[str] = Field(default=None)
    error: Optional[str] = Field(default=None)
    base64_image: Optional[str] = Field(default=None)
    system: Optional[str] = Field(default=None)

    def __bool__(self) -> bool:
        """A result is truthy if it has any content."""
        return any(
            getattr(self, field) for field in self.__fields__
        )

    def __add__(self, other: "ToolResult") -> "ToolResult":
        """Combine two results. Concatenates text outputs."""
        return ToolResult(
            output=self._combine(self.output, other.output, True),
            error=self._combine(self.error, other.error, True),
            base64_image=self.base64_image or other.base64_image,
            system=self.system or other.system,
        )

    @staticmethod
    def _combine(a: Optional[str], b: Optional[str], concatenate: bool) -> Optional[str]:
        if a and b:
            return a + b if concatenate else None
        return a or b

    def __str__(self) -> str:
        return f"Error: {self.error}" if self.error else (self.output or "")

    def replace(self, **kwargs: Any) -> "ToolResult":
        """Return a new ToolResult with fields replaced."""
        return type(self)(**{**self.model_dump(), **kwargs})


class BaseTool(ABC, BaseModel):
    """Base class for all agent tools.

    Subclasses define name, description, parameters (JSON schema dict), and
    implement the async execute() method. Instances are registered in a
    ToolCollection and invoked by name from the agent loop.
    """

    name: str
    description: str
    parameters: Optional[dict] = Field(default=None)

    class Config:
        arbitrary_types_allowed = True

    async def __call__(self, **kwargs: Any) -> ToolResult:
        """Execute the tool with the given keyword arguments."""
        return await self.execute(**kwargs)

    @abstractmethod
    async def execute(self, **kwargs: Any) -> ToolResult:
        """Execute the tool logic. Subclasses must implement."""

    def to_param(self) -> Dict[str, Any]:
        """Convert the tool to an OpenAI-compatible function-calling parameter."""
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters or {
                    "type": "object",
                    "properties": {},
                },
            },
        }

    def success_response(self, data: Any) -> ToolResult:
        """Wrap data as a successful ToolResult."""
        text = data if isinstance(data, str) else json.dumps(data, indent=2)
        return ToolResult(output=text)

    def fail_response(self, msg: str) -> ToolResult:
        """Wrap an error message as a failed ToolResult."""
        return ToolResult(error=msg)