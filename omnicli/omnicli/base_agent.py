"""
Base agent class for OmniCLI agent execution.

Provides foundational functionality for agent state management, memory,
and the think/act/step execution loop. Modeled after OpenManus's BaseAgent
but adapted for OmniCLI's multi-provider LLM client and deterministic
verification tooling.

Subclasses must implement `think()` and `act()`.
"""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from contextlib import asynccontextmanager
from typing import Any, List, Optional

from pydantic import BaseModel, Field

from omnicli.base_tool import BaseTool, ToolResult


class AgentState(str):
    """Agent lifecycle states."""

    IDLE = "idle"
    RUNNING = "running"
    FINISHED = "finished"
    ERROR = "error"


class Memory:
    """Simple in-memory message store for agent conversation history."""

    def __init__(self) -> None:
        self.messages: List[dict] = []

    def add_message(
        self,
        role: str,
        content: str,
        tool_call_id: Optional[str] = None,
        name: Optional[str] = None,
    ) -> None:
        """Append a message to the conversation history."""
        msg: dict = {"role": role, "content": content}
        if tool_call_id is not None:
            msg["tool_call_id"] = tool_call_id
        if name is not None:
            msg["name"] = name
        self.messages.append(msg)

    def add_messages(self, messages: List[dict]) -> None:
        """Append multiple messages at once."""
        self.messages.extend(messages)

    def get_messages(self) -> List[dict]:
        """Return a copy of the full message history."""
        return list(self.messages)


class BaseAgent(BaseModel, ABC):  # type: ignore[misc]
    """Abstract base class for OmniCLI agents.

    Provides:
    - State machine: IDLE -> RUNNING -> FINISHED/ERROR
    - Memory store for conversation history
    - Think/act/step execution loop
    - Max steps guard against infinite loops
    - Duplicate-response detection with automatic strategy nudge

    Subclasses must implement think() and act().
    """

    name: str = Field(..., description="Unique agent name")
    description: Optional[str] = Field(None, description="Agent description")

    system_prompt: Optional[str] = Field(None, description="System-level instruction")
    next_step_prompt: Optional[str] = Field(None, description="Next-step hint prompt")

    llm: Any = Field(default=None, description="LLM client instance")
    memory: Memory = Field(default_factory=Memory)
    state: str = Field(default=AgentState.IDLE)

    max_steps: int = Field(default=10, description="Maximum steps before termination")
    current_step: int = Field(default=0, description="Current execution step")

    duplicate_threshold: int = Field(default=2, description="Duplicate responses before nudge")

    class Config:
        arbitrary_types_allowed = True

    def __init__(self, **data: Any) -> None:
        super().__init__(**data)
        if self.memory is None:
            self.memory = Memory()

    @asynccontextmanager
    async def state_context(self, new_state: str):
        """Context manager for safe state transitions."""
        previous = self.state
        self.state = new_state
        try:
            yield
        except Exception as exc:
            self.state = AgentState.ERROR
            raise exc
        finally:
            self.state = previous

    def update_memory(
        self,
        role: str,
        content: str,
        tool_call_id: Optional[str] = None,
        name: Optional[str] = None,
    ) -> None:
        """Add a message to agent memory."""
        self.memory.add_message(role, content, tool_call_id, name)

    def get_memory(self) -> List[dict]:
        """Return conversation history."""
        return self.memory.get_messages()

    def is_stuck(self) -> bool:
        """Detect if the agent is repeating the same response (loop detection)."""
        if len(self.memory.messages) < 2:
            return False
        last = self.memory.messages[-1]
        if not last.get("content"):
            return False
        dup_count = sum(
            1
            for msg in reversed(self.memory.messages[:-1])
            if msg.get("role") == "assistant" and msg.get("content") == last["content"]
        )
        return dup_count >= self.duplicate_threshold

    def handle_stuck_state(self) -> None:
        """Inject a strategy nudge when the agent is stuck in a loop."""
        nudge = (
            "\nObserved duplicate responses. Consider new strategies and avoid "
            "repeating ineffective paths already attempted."
        )
        if self.next_step_prompt:
            self.next_step_prompt = f"{nudge}\n{self.next_step_prompt}"
        else:
            self.next_step_prompt = nudge

    async def run(self, request: Optional[str] = None) -> str:
        """Execute the agent loop: think -> act -> step until FINISHED or max steps."""
        if self.state != AgentState.IDLE:
            raise RuntimeError(f"Cannot run agent from state: {self.state}")

        if request:
            self.update_memory("user", request)

        results: List[str] = []
        async with self.state_context(AgentState.RUNNING):
            while self.current_step < self.max_steps and self.state != AgentState.FINISHED:
                self.current_step += 1
                step_result = await self.step()

                if self.is_stuck():
                    self.handle_stuck_state()

                results.append(f"Step {self.current_step}: {step_result}")

            if self.current_step >= self.max_steps:
                self.current_step = 0
                self.state = AgentState.IDLE
                results.append(f"Terminated: reached max steps ({self.max_steps})")

        return "\n".join(results) if results else "No steps executed"

    async def step(self) -> str:
        """Execute one think-act cycle."""
        should_act = await self.think()
        if not should_act:
            return "Thinking complete - no action needed"
        return await self.act()

    @abstractmethod
    async def think(self) -> bool:
        """Decide whether to act and what to do. Return True to proceed to act()."""

    @abstractmethod
    async def act(self) -> str:
        """Execute the decided action."""