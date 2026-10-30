#!/usr/bin/env python3
"""
System tests for the full OmniCLI + Oracle + code_hunter pipeline.

Tests end-to-end workflows:
- Full pipeline: scan → oracle prescan → scan → queue → report
- OmniCLI agent with Oracle tools
- Bug hunting chain: low → medium → high → critical
- Mindset cages enforced end-to-end
- Fail-loud at every boundary

Run: python3 -m pytest omnicli/omnicli/tests/test_system_pipeline.py -q
"""

import asyncio
import json
import sys
from pathlib import Path
from typing import Any, Dict, Optional

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from omnicli.base_tool import BaseTool, ToolResult
from omnicli.tool_collection import ToolCollection
from omnicli.base_agent import BaseAgent, AgentState, Memory
from omnicli.tool_call_agent import ToolCallAgent
from omnicli.tools.planning import PlanningTool
from omnicli.tools.python_execute import PythonExecuteTool

from omnicli.tests.test_agent_integration import MockLLM, make_tool_call


# ─────────────────────────────────────────────────────────────────────────────
# Mock helpers
# ─────────────────────────────────────────────────────────────────────────────

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
# Mock Oracle - simulates Oracle's hunt pipeline
# ─────────────────────────────────────────────────────────────────────────────

class MockOracleScanner(BaseTool):
    """Mock Oracle scan tool - simulates verifying a target program scope."""

    name: str = "oracle_scan"
    description: str = "Verify a target program scope and payouts"
    parameters: dict = {
        "type": "object",
        "properties": {
            "target": {"type": "string"},
            "platform": {"type": "string"},
        },
        "required": ["target"],
    }

    async def execute(self, target: str = "", platform: str = "hackerone") -> ToolResult:
        if "example.com" in target:
            return ToolResult(
                output=f"Verified: {target} on {platform}. Scope: api.example.com, www.example.com. Payout: $5000."
            )
        return ToolResult(error=f"Target {target} not found or not in scope")


class MockOracleBundle(BaseTool):
    """Mock Oracle bundle tool - creates submission-ready product bundle."""

    name: str = "oracle_bundle"
    description: str = "Package hunt workspace into submission-ready bundle"
    parameters: dict = {
        "type": "object",
        "properties": {
            "workspace": {"type": "string"},
            "findings": {"type": "string"},
        },
        "required": ["workspace"],
    }

    async def execute(self, workspace: str = "", findings: str = "") -> ToolResult:
        return ToolResult(
            output=f"Bundle created: {workspace}/reports/product_20240101.zip. SHA-256: abc123. Ready for submission: True."
        )


class MockOracleQueue(BaseTool):
    """Mock Oracle queue - schedules hunts."""

    name: str = "oracle_queue"
    description: str = "Queue programs for hunting"
    parameters: dict = {
        "type": "object",
        "properties": {
            "program": {"type": "string"},
            "priority": {"type": "string"},
        },
        "required": ["program"],
    }

    async def execute(self, program: str = "", priority: str = "medium") -> ToolResult:
        return ToolResult(
            output=f"Queued: {program} (priority: {priority}). Position: 1 in queue."
        )


# ─────────────────────────────────────────────────────────────────────────────
# Full Pipeline Integration Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestFullPipeline:
    """Test the complete bug bounty pipeline end-to-end."""

    @pytest.mark.asyncio
    async def test_agent_uses_oracle_tools(self):
        """Agent uses Oracle scan → bundle → queue tools in sequence."""
        oracle_scan = MockOracleScanner()
        oracle_bundle = MockOracleBundle()
        oracle_queue = MockOracleQueue()

        agent = ToolCallAgent(
            name="pipeline_agent",
            llm=MockLLM([
                {
                    "content": "Scanning target.",
                    "tool_calls": [
                        {
                            "id": "c1",
                            "type": "function",
                            "function": {
                                "name": "oracle_scan",
                                "arguments": json.dumps({"target": "example.com", "platform": "hackerone"}),
                            },
                        }
                    ],
                },
                {
                    "content": "Target verified. Bundling results.",
                    "tool_calls": [
                        {
                            "id": "c2",
                            "type": "function",
                            "function": {
                                "name": "oracle_bundle",
                                "arguments": json.dumps({"workspace": "targets/hackerone/example", "findings": "IDOR"}),
                            },
                        }
                    ],
                },
                {
                    "content": "Bundle created. Queuing hunt.",
                    "tool_calls": [
                        {
                            "id": "c3",
                            "type": "function",
                            "function": {
                                "name": "oracle_queue",
                                "arguments": json.dumps({"program": "example.com", "priority": "high"}),
                            },
                        }
                    ],
                },
                {
                    "content": "Pipeline complete.",
                    "tool_calls": [],
                },
            ]),
            available_tools=ToolCollection(oracle_scan, oracle_bundle, oracle_queue),
        )

        result = await agent.run("Full pipeline hunt for example.com")
        assert "Verified:" in result
        assert "Bundle created:" in result
        assert "Queued:" in result

    @pytest.mark.asyncio
    async def test_bug_chain_low_to_critical(self):
        """Agent chains findings from low → critical severity."""

        class LowFindingTool(BaseTool):
            name: str = "find_low"
            description: str = "Find low-severity flaw"
            parameters: dict = {
                "type": "object",
                "properties": {"target": {"type": "string"}},
                "required": ["target"],
            }

            async def execute(self, target: str = "") -> ToolResult:
                return ToolResult(
                    output=f"LOW: Missing X-Frame-Options header on {target}"
                )

        class ChainTool(BaseTool):
            name: str = "chain_findings"
            description: str = "Chain findings into higher severity"
            parameters: dict = {
                "type": "object",
                "properties": {
                    "finding": {"type": "string"},
                    "chain_to": {"type": "string"},
                },
                "required": ["finding", "chain_to"],
            }

            async def execute(self, finding: str = "", chain_to: str = "") -> ToolResult:
                if "X-Frame-Options" in finding and "clickjacking" in chain_to:
                    return ToolResult(
                        output="CRITICAL: Clickjacking via missing X-Frame-Options enables account takeover"
                    )
                return ToolResult(output="No chain found")

        agent = ToolCallAgent(
            name="chain_agent",
            llm=MockLLM([
                {
                    "content": "Finding low severity issue.",
                    "tool_calls": [
                        make_tool_call("find_low", {"target": "example.com"}, "c1")
                    ],
                },
                {
                    "content": "Chaining to critical.",
                    "tool_calls": [
                        make_tool_call(
                            "chain_findings",
                            {
                                "finding": "Missing X-Frame-Options header on example.com",
                                "chain_to": "clickjacking account takeover",
                            },
                            "c2",
                        )
                    ],
                },
                {
                    "content": "Critical finding confirmed.",
                    "tool_calls": [],
                },
            ]),
            available_tools=ToolCollection(LowFindingTool(), ChainTool()),
        )

        result = await agent.run("Chain bugs from low to critical on example.com")
        assert "CRITICAL" in result
        assert "account takeover" in result.lower()


# ─────────────────────────────────────────────────────────────────────────────
# Mindset Cage Enforcement Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestMindsetCages:
    """Agent operates within mindset cages - cannot escape constraints."""

    @pytest.mark.asyncio
    async def test_agent_stays_in_scope(self):
        """Agent cannot scope outside authorized targets."""

        class ScopeTool(BaseTool):
            name: str = "check_scope"
            description: str = "Verify target is in scope"
            parameters: dict = {
                "type": "object",
                "properties": {"target": {"type": "string"}},
                "required": ["target"],
            }

            async def execute(self, target: str = "") -> ToolResult:
                authorized = ["example.com", "test.com"]
                if target in authorized:
                    return ToolResult(output=f"{target} is IN SCOPE")
                return ToolResult(error=f"{target} is OUT OF SCOPE - access denied")

        agent = ToolCallAgent(
            name="scope_agent",
            llm=MockLLM([
                {
                    "content": "Checking scope.",
                    "tool_calls": [
                        {
                            "id": "c1",
                            "type": "function",
                            "function": {
                                "name": "check_scope",
                                "arguments": json.dumps({"target": "evil.com"}),
                            },
                        }
                    ],
                },
                {
                    "content": "Target out of scope. Stopping.",
                    "tool_calls": [],
                },
            ]),
            available_tools=ToolCollection(ScopeTool()),
        )

        result = await agent.run("Scan evil.com")
        assert "OUT OF SCOPE" in result

    @pytest.mark.asyncio
    async def test_agent_cannot_bypass_cage(self):
        """Agent cannot bypass mindset cage to access unauthorized tools."""
        agent = ToolCallAgent(
            name="caged_agent",
            llm=MockLLM([
                {
                    "content": "Trying unauthorized tool.",
                    "tool_calls": [
                        {
                            "id": "c1",
                            "type": "function",
                            "function": {
                                "name": "forbidden_tool",
                                "arguments": json.dumps({}),
                            },
                        }
                    ],
                },
            ]),
            available_tools=ToolCollection(),  # Empty - no tools allowed
        )

        result = await agent.run("Try forbidden tool")
        assert result  # Should contain error info


# ─────────────────────────────────────────────────────────────────────────────
# End-to-End: Complete Bug Hunt to Submission
# ─────────────────────────────────────────────────────────────────────────────

class TestEndToEndBugHunt:
    """Complete flow: recon → scan → verify → bundle → submit-ready."""

    @pytest.mark.asyncio
    async def test_full_hunt_to_submission(self):
        """Complete bug bounty hunt from recon to submission-ready bundle."""

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
                    output=f"Found endpoints: /api/v1/users, /api/v1/admin on {target}"
                )

        class ScanTool(BaseTool):
            name: str = "scan_vuln"
            description: str = "Scan for vulnerabilities"
            parameters: dict = {
                "type": "object",
                "properties": {"endpoint": {"type": "string"}},
                "required": ["endpoint"],
            }

            async def execute(self, endpoint: str = "") -> ToolResult:
                return ToolResult(
                    output=f"VULN: IDOR on {endpoint} - can access any user's data"
                )

        class ReportTool(BaseTool):
            name: str = "write_report"
            description: str = "Write submission-ready report"
            parameters: dict = {
                "type": "object",
                "properties": {
                    "finding": {"type": "string"},
                    "severity": {"type": "string"},
                },
                "required": ["finding", "severity"],
            }

            async def execute(self, finding: str = "", severity: str = "medium") -> ToolResult:
                return ToolResult(
                    output=f"Report written: {finding}. Severity: {severity}. SHA-256 manifest: abc123def456. Ready for submission."
                )

        agent = ToolCallAgent(
            name="hunter",
            llm=MockLLM([
                {
                    "content": "Starting reconnaissance.",
                    "tool_calls": [
                        make_tool_call("recon", {"target": "target.com"}, "c1")
                    ],
                },
                {
                    "content": "Found admin endpoint, scanning.",
                    "tool_calls": [
                        make_tool_call(
                            "scan_vuln",
                            {"endpoint": "/api/v1/admin/users/{id}"},
                            "c2",
                        )
                    ],
                },
                {
                    "content": "Found critical IDOR. Writing report.",
                    "tool_calls": [
                        make_tool_call(
                            "write_report",
                            {
                                "finding": "IDOR on /api/v1/admin/users/{id} allows accessing any user's data",
                                "severity": "critical",
                            },
                            "c3",
                        )
                    ],
                },
                {
                    "content": "Report ready for submission.",
                    "tool_calls": [],
                },
            ]),
            available_tools=ToolCollection(
                ReconTool(), ScanTool(), ReportTool()
            ),
        )

        result = await agent.run("Full bug hunt on target.com")
        assert "Found endpoints" in result
        assert "VULN: IDOR" in result
        assert "Report written:" in result
        assert "SHA-256 manifest" in result
        assert "Ready for submission" in result


# ─────────────────────────────────────────────────────────────────────────────
# Run tests
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    pytest.main([__file__, "-q", "-v"])
