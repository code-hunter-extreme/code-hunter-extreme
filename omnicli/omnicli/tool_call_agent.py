"""
ToolCallAgent - LLM-driven tool-calling agent for OmniCLI.

Extends BaseAgent with an LLM-driven think/act loop:
- think(): calls the LLM with available tools as function-calling parameters,
           parses tool calls from the response
- act(): executes the selected tools via ToolCollection, feeds results back to memory

Modeled after OpenManus's ToolCallAgent but using OmniClient for LLM access
and OmniCLI's ToolCollection for tool execution.
"""

from __future__ import annotations

import json
from typing import Any, List, Optional

from pydantic import Field

from omnicli.base_agent import AgentState, BaseAgent, Memory
from omnicli.base_tool import BaseTool, ToolResult
from omnicli.tool_collection import ToolCollection
from omnicli.client import OmniClient
from omnicli.config import ConfigManager


class ToolCallAgent(BaseAgent):
    """Agent that uses an LLM to select and call tools from a ToolCollection.

    think(): builds a prompt from memory + system prompt, calls LLM with
             available tools as function-calling parameters, parses tool calls.
    act(): executes each tool call via ToolCollection, appends results to memory.
    """

    name: str = Field(default="toolcall", description="Agent name")
    description: str = Field(default="LLM-driven tool-calling agent")

    system_prompt: Optional[str] = Field(
        default=None, description="System instruction prompt"
    )
    next_step_prompt: Optional[str] = Field(
        default=None, description="Prompt for the next action"
    )

    llm: Any = Field(default=None, description="LLM client instance")
    provider: Optional[str] = Field(
        default=None, description="LLM provider name (uses config default if None)"
    )

    available_tools: ToolCollection = Field(
        default_factory=ToolCollection, description="Registered tools"
    )
    tool_choices: str = Field(
        default="auto", description="Tool choice mode: auto, required, none"
    )

    tool_calls: List[dict] = Field(
        default_factory=list, description="Pending tool calls from LLM"
    )
    max_steps: int = Field(default=30, description="Maximum execution steps")
    max_observe: Optional[int] = Field(
        default=None, description="Max chars of tool output to observe"
    )

    class Config:
        arbitrary_types_allowed = True

    async def think(self) -> bool:
        """Call the LLM with available tools, parse tool calls into memory."""
        if not self.llm:
            self.update_memory(
                "system",
                "No LLM client configured. Cannot proceed.",
            )
            return False

        # Build messages from memory
        messages = self.memory.get_messages()

        # Add next_step_prompt as a user message if present
        if self.next_step_prompt:
            messages = list(messages)
            messages.append({"role": "user", "content": self.next_step_prompt})

        system_msgs = (
            [{"role": "system", "content": self.system_prompt}]
            if self.system_prompt
            else None
        )

        try:
            response = await self.llm.chat_complete(
                messages=messages,
                system_prompt=self.system_prompt,
                tools=self.available_tools.to_params(),
                tool_choice=self.tool_choices,
                provider=self.provider,
            )
        except Exception as exc:  # noqa: BLE001
            self.update_memory(
                "assistant",
                f"LLM call failed: {exc}",
            )
            return False

        # Parse response
        content = response.get("content") or ""
        tool_calls = response.get("tool_calls") or []

        self.tool_calls = tool_calls

        # Log thoughts
        if content:
            self.update_memory("assistant", content)

        # Handle different tool_choice modes
        if self.tool_choices == "none":
            if tool_calls:
                self.update_memory(
                    "assistant",
                    f"Model tried to use tools when none were allowed: {[tc.get('function', {}).get('name') for tc in tool_calls]}",
                )
            return bool(content)

        if self.tool_choices == "required" and not tool_calls:
            # LLM didn't call a tool when required; treat as acting anyway
            return True

        if self.tool_choices == "auto" and not tool_calls:
            return bool(content)

        return bool(tool_calls)

    async def act(self) -> str:
        """Execute pending tool calls via ToolCollection, feed results to memory."""
        if not self.tool_calls:
            if self.tool_choices == "required":
                raise ValueError("Tool calls required but none provided")
            last = self.memory.get_messages()[-1] if self.memory.get_messages() else {}
            return last.get("content", "No content or commands to execute")

        results: List[str] = []
        for command in self.tool_calls:
            name = command.get("function", {}).get("name", "")
            args_str = command.get("function", {}).get("arguments", "{}")
            tool_call_id = command.get("id")

            try:
                args = json.loads(args_str) if args_str else {}
            except json.JSONDecodeError:
                error_msg = f"Error parsing arguments for {name}: invalid JSON"
                self.update_memory(
                    "tool",
                    error_msg,
                    tool_call_id=tool_call_id,
                    name=name,
                )
                results.append(error_msg)
                continue

            try:
                result: ToolResult = await self.available_tools.execute(
                    name=name, tool_input=args
                )
            except Exception as exc:  # noqa: BLE001
                error_msg = f"Tool '{name}' error: {exc}"
                self.update_memory(
                    "tool",
                    error_msg,
                    tool_call_id=tool_call_id,
                    name=name,
                )
                results.append(error_msg)
                continue

            # Truncate observation if max_observe is set
            observation = str(result)
            if self.max_observe is not None and len(observation) > self.max_observe:
                observation = observation[: self.max_observe] + "..."

            tool_msg = f"Observed output of cmd `{name}` executed:\n{observation}"
            self.update_memory(
                "tool",
                tool_msg,
                tool_call_id=tool_call_id,
                name=name,
            )
            results.append(tool_msg)

        self.memory.add_messages(
            [
                {"role": "user", "content": "\n\n".join(results)}
            ]
            if results
            else []
        )
        return "\n\n".join(results)

    async def cleanup(self) -> None:
        """Clean up agent resources (e.g., close LLM connections)."""
        if self.llm and hasattr(self.llm, "cleanup"):
            await self.llm.cleanup()