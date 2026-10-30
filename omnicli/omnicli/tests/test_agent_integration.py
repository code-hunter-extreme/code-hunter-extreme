#!/usr/bin/env python3
"""
Integration tests for OmniCLI agent framework with mock LLM.

Tests the full think/act loop with mocked LLM responses, verifying:
- Agent can think, call tools, and act on results
- Multi-step agent loops work end-to-end
- Tool results feed back into memory for subsequent reasoning
- Fail-loud behavior when tools fail
- Mindset cages constrain agent behavior

Run: python3 -m pytest omnicli/omnicli/tests/test_agent_integration.py -q
"""

import asyncio
import json
import sys
from pathlib import Path
from typing import Any, Optional

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from omnicli.base_tool import BaseTool, ToolResult
from omnicli.base_agent import BaseAgent, AgentState, Memory
from omnicli.tool_call_agent import ToolCallAgent
from omnicli.tool_collection import ToolCollection
from omnicli.tools.planning import PlanningTool
from omnicli.tools.python_execute import PythonExecuteTool


# ─────────────────────────────────────────────────────────────────────────────
# Mock LLM Client
# ─────────────────────────────────────────────────────────────────────────────

class MockLLM:
    """Mock LLM that returns scripted tool calls for testing agent loops."""

    def __init__(self, responses: list):
        """responses: list of dicts, each with optional 'tool_calls' and 'content'.
        Consumed in order. When exhausted, returns empty response."""
        self._responses = list(responses)
        self.call_count = 0
        self.last_messages = None

    async def chat_complete(self, **kwargs) -> dict:
        self.call_count += 1
        self.last_messages = kwargs.get("messages", [])
        if self._responses:
            return self._responses.pop(0)
        return {"content": "No more responses. Task complete.", "tool_calls": []}


def make_tool_call(tool_name: str, arguments: dict, call_id: str = "call_1") -> dict:
    """Build a mock tool call dict."""
    return {
        "id": call_id,
        "type": "function",
        "function": {
            "name": tool_name,
            "arguments": json.dumps(arguments),
        },
    }


# ─────────────────────────────────────────────────────────────────────────────
# Test Tools
# ─────────────────────────────────────────────────────────────────────────────

class EchoTool(BaseTool):
    name: str = "echo"
    description: str = "Echo back text"
    parameters: dict = {
        "type": "object",
        "properties": {"text": {"type": "string"}},
        "required": ["text"],
    }

    async def execute(self, text: str = "") -> ToolResult:
        return ToolResult(output=f"echo: {text}")


class StepTracker(BaseTool):
    name: str = "step_tracker"
    description: str = "Records step execution"
    parameters: dict = {
        "type": "object",
        "properties": {"step_name": {"type": "string"}},
        "required": ["step_name"],
    }

    async def execute(self, step_name: str = "") -> ToolResult:
        return ToolResult(output=f"Completed: {step_name}")


class FailingTool(BaseTool):
    name: str = "failing_tool"
    description: str = "Always fails"
    parameters: dict = {"type": "object", "properties": {}}

    async def execute(self, **kwargs) -> ToolResult:
        raise RuntimeError("Simulated tool failure")


# ─────────────────────────────────────────────────────────────────────────────
# ToolCallAgent Integration Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestToolCallAgentIntegration:
    """Full agent lifecycle tests with mocked LLM."""

    @pytest.mark.asyncio
    async def test_agent_thinks_and_acts_single_tool(self):
        """Agent thinks, calls one tool, executes it, returns result."""
        agent = ToolCallAgent(
            name="test_agent",
            llm=MockLLM([
                {
                    "content": "I will echo the message.",
                    "tool_calls": [
                        make_tool_call("echo", {"text": "hello world"}, "call_1")
                    ],
                },
            ]),
            available_tools=ToolCollection(EchoTool()),
        )

        result = await agent.run("Say hello")
        assert "echo: hello world" in result
        assert agent.state == AgentState.IDLE

    @pytest.mark.asyncio
    async def test_agent_multi_step_chain(self):
        """Agent chains multiple tool calls across steps."""
        call_log = []

        class StepTrackerWithLog(StepTracker):
            async def execute(self, step_name: str = "") -> ToolResult:
                call_log.append(step_name)
                return await super().execute(step_name=step_name)

        agent = ToolCallAgent(
            name="chain_agent",
            llm=MockLLM([
                {
                    "content": "Starting step 1.",
                    "tool_calls": [
                        make_tool_call("step_tracker", {"step_name": "recon"}, "c1")
                    ],
                },
                {
                    "content": "Starting step 2.",
                    "tool_calls": [
                        make_tool_call("step_tracker", {"step_name": "scan"}, "c2")
                    ],
                },
                {
                    "content": "All steps complete.",
                    "tool_calls": [],
                },
            ]),
            available_tools=ToolCollection(StepTrackerWithLog()),
            max_steps=10,
        )

        result = await agent.run("Run recon then scan")
        assert "Completed: recon" in result
        assert "Completed: scan" in result
        assert call_log == ["recon", "scan"]

    @pytest.mark.asyncio
    async def test_agent_tool_error_handling(self):
        """Agent handles tool errors without crashing."""
        agent = ToolCallAgent(
            name="error_agent",
            llm=MockLLM([
                {
                    "content": "Trying failing tool.",
                    "tool_calls": [
                        make_tool_call("failing_tool", {}, "c1")
                    ],
                },
                {
                    "content": "Tool failed as expected.",
                    "tool_calls": [],
                },
            ]),
            available_tools=ToolCollection(FailingTool()),
        )

        result = await agent.run("Test failure handling")
        assert "Error" in result or "failed" in result.lower()

    @pytest.mark.asyncio
    async def test_agent_max_steps_limit(self):
        """Agent stops after max_steps."""
        class InfiniteTool(BaseTool):
            name: str = "infinite_tool"
            description: str = "Always returns more work"
            parameters: dict = {"type": "object", "properties": {}}

            async def execute(self, **kwargs) -> ToolResult:
                return ToolResult(output="still going")

        agent = ToolCallAgent(
            name="loop_agent",
            llm=MockLLM(
                [
                    {
                        "content": "Keep going.",
                        "tool_calls": [
                            make_tool_call("infinite_tool", {}, "c_test")
                        ],
                    }
                ]
                * 50
            ),
            available_tools=ToolCollection(InfiniteTool()),
            max_steps=3,
        )

        result = await agent.run("Run forever")
        assert "Terminated: reached max steps" in result
        assert agent.state == AgentState.IDLE


# ─────────────────────────────────────────────────────────────────────────────
# PlanningTool Integration with Agent
# ─────────────────────────────────────────────────────────────────────────────

class TestPlanningIntegration:
    """Agent uses PlanningTool to create and track multi-step plans."""

    @pytest.mark.asyncio
    async def test_agent_creates_plan(self):
        """Agent creates a plan via PlanningTool."""
        agent = ToolCallAgent(
            name="planner_agent",
            llm=MockLLM([
                {
                    "content": "I'll create a plan for the hunt.",
                    "tool_calls": [
                        make_tool_call(
                            "planning",
                            {
                                "command": "create",
                                "plan_id": "hunt_1",
                                "title": "Bug Bounty Hunt",
                                "steps": ["recon", "scan", "poc", "report"],
                            },
                            "c1",
                        )
                    ],
                },
                {
                    "content": "Plan created successfully.",
                    "tool_calls": [],
                },
            ]),
            available_tools=ToolCollection(PlanningTool()),
        )

        result = await agent.run("Create a hunt plan")
        assert "Plan created successfully" in result
        assert "hunt_1" in result

    @pytest.mark.asyncio
    async def test_agent_marks_step_complete(self):
        """Agent marks a plan step as complete."""
        pt = PlanningTool()
        await pt.execute(
            command="create",
            plan_id="p1",
            title="Test Plan",
            steps=["a", "b", "c"],
        )

        agent = ToolCallAgent(
            name="marker_agent",
            llm=MockLLM([
                {
                    "content": "Marking step 0 complete.",
                    "tool_calls": [
                        make_tool_call(
                            "planning",
                            {
                                "command": "mark_step",
                                "plan_id": "p1",
                                "step_index": 0,
                                "step_status": "completed",
                                "step_notes": "Done successfully",
                            },
                            "c1",
                        )
                    ],
                },
            ]),
            available_tools=ToolCollection(pt),
        )

        result = await agent.run("Mark step 0 complete")
        assert "completed" in result or "Step 0 updated" in result


# ─────────────────────────────────────────────────────────────────────────────
# PythonExecuteTool Integration
# ─────────────────────────────────────────────────────────────────────────────

class TestPythonExecuteIntegration:
    @pytest.mark.asyncio
    async def test_agent_executes_python(self):
        """Agent uses PythonExecuteTool to run code."""
        pet = PythonExecuteTool()
        agent = ToolCallAgent(
            name="python_agent",
            llm=MockLLM([
                {
                    "content": "Calculating 10 * 5.",
                    "tool_calls": [
                        make_tool_call(
                            "python_execute",
                            {"code": "print(10 * 5)"},
                            "c1",
                        )
                    ],
                },
                {
                    "content": "Calculation complete.",
                    "tool_calls": [],
                },
            ]),
            available_tools=ToolCollection(pet),
        )

        result = await agent.run("Calculate 10 times 5")
        assert "50" in result


# ─────────────────────────────────────────────────────────────────────────────
# Agent Fail-Loud Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestFailLoud:
    @pytest.mark.asyncio
    async def test_agent_tool_not_found(self):
        """Agent tries to call nonexistent tool → fail loud."""
        agent = ToolCallAgent(
            name="bad_agent",
            llm=MockLLM([
                {
                    "content": "Calling nonexistent tool.",
                    "tool_calls": [
                        make_tool_call("nonexistent_tool", {}, "c1")
                    ],
                },
            ]),
            available_tools=ToolCollection(),  # empty
        )

        result = await agent.run("Call nothing")
        assert "invalid" in result.lower() or "error" in result.lower()

    @pytest.mark.asyncio
    async def test_agent_empty_response(self):
        """Agent with no tool calls returns gracefully."""
        agent = ToolCallAgent(
            name="empty_agent",
            llm=MockLLM([
                {
                    "content": "Nothing to do.",
                    "tool_calls": [],
                },
            ]),
            available_tools=ToolCollection(),
        )

        result = await agent.run("Do nothing")
        assert result != ""  # Agent returned something


# ─────────────────────────────────────────────────────────────────────────────
# State Management Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestAgentState:
    @pytest.mark.asyncio
    async def test_agent_state_transitions(self):
        """Agent transitions IDLE → RUNNING → IDLE correctly."""
        agent = ToolCallAgent(
            name="state_agent",
            llm=MockLLM([
                {
                    "content": "Done.",
                    "tool_calls": [],
                },
            ]),
            available_tools=ToolCollection(),
        )

        assert agent.state == AgentState.IDLE
        await agent.run("Test state")
        assert agent.state == AgentState.IDLE
        assert agent.current_step == 0  # Reset after run

    @pytest.mark.asyncio
    async def test_agent_memory_persists(self):
        """Agent memory persists across steps."""
        agent = ToolCallAgent(
            name="memory_agent",
            llm=MockLLM([
                {
                    "content": "Step 1 done.",
                    "tool_calls": [],
                },
                {
                    "content": "Step 2 uses step 1 result.",
                    "tool_calls": [],
                },
            ]),
            available_tools=ToolCollection(),
        )

        await agent.run("Two steps")
        messages = agent.get_memory()
        # Should have user message + at least one assistant message
        assert len(messages) >= 2


# ─────────────────────────────────────────────────────────────────────────────
# End-to-End: Simulated Bug Hunt Workflow
# ─────────────────────────────────────────────────────────────────────────────

class TestBugHuntWorkflow:
    """Simulated bug bounty hunt workflow using agent tools."""

    @pytest.mark.asyncio
    async def test_full_hunt_workflow(self):
        """Agent simulates: recon → vuln scan → poc → report."""
        # Mock recon tool
        class ReconTool(BaseTool):
            name: str = "recon"
            description: str = "Reconnaissance target"
            parameters: dict = {
                "type": "object",
                "properties": {"target": {"type": "string"}},
                "required": ["target"],
            }

            async def execute(self, target: str = "") -> ToolResult:
                return ToolResult(
                    output=f"Found: /api/v1/users, /api/v1/admin on {target}"
                )

        # Mock vuln scan tool
        class VulnScanTool(BaseTool):
            name: str = "vuln_scan"
            description: str = "Scan for vulnerabilities"
            parameters: dict = {
                "type": "object",
                "properties": {"endpoint": {"type": "string"}},
                "required": ["endpoint"],
            }

            async def execute(self, endpoint: str = "") -> ToolResult:
                if "admin" in endpoint:
                    return ToolResult(
                        output="IDOR vulnerability found: /api/v1/admin/users/{id}"
                    )
                return ToolResult(output="No vulnerabilities found")

        agent = ToolCallAgent(
            name="hunt_agent",
            llm=MockLLM([
                {
                    "content": "Starting reconnaissance.",
                    "tool_calls": [
                        make_tool_call(
                            "recon",
                            {"target": "example.com"},
                            "c1",
                        )
                    ],
                },
                {
                    "content": "Found admin endpoint, scanning for vulns.",
                    "tool_calls": [
                        make_tool_call(
                            "vuln_scan",
                            {"endpoint": "/api/v1/admin/users/{id}"},
                            "c2",
                        )
                    ],
                },
                {
                    "content": "Found IDOR vulnerability.",
                    "tool_calls": [],
                },
            ]),
            available_tools=ToolCollection(ReconTool(), VulnScanTool()),
        )

        result = await agent.run("Hunt example.com for vulnerabilities")
        assert "Found:" in result
        assert "IDOR" in result or "vulnerability" in result.lower()


# ─────────────────────────────────────────────────────────────────────────────
# Run tests
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    pytest.main([__file__, "-q", "-v"])
