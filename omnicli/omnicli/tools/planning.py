"""
Planning tool for OmniCLI agents.

Allows agents to create and manage multi-step plans for solving complex tasks.
Provides commands: create, update, list, get, set_active, mark_step, delete.

Modeled after OpenManus's PlanningTool.
"""

from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional

from omnicli.base_tool import BaseTool, ToolResult
from pydantic import Field


_PLANNING_TOOL_DESCRIPTION = """
A planning tool that allows the agent to create and manage plans for solving
complex tasks. Provides functionality for creating plans, updating plan steps,
and tracking progress.
"""


class PlanningTool(BaseTool):
    """Planning tool for managing multi-step task plans."""

    name: str = "planning"
    description: str = _PLANNING_TOOL_DESCRIPTION
    parameters: dict = {
        "type": "object",
        "properties": {
            "command": {
                "description": "The command to execute. Available commands: create, update, list, get, set_active, mark_step, delete.",
                "enum": [
                    "create",
                    "update",
                    "list",
                    "get",
                    "set_active",
                    "mark_step",
                    "delete",
                ],
                "type": "string",
            },
            "plan_id": {
                "description": "Unique identifier for the plan.",
                "type": "string",
            },
            "title": {
                "description": "Title for the plan.",
                "type": "string",
            },
            "steps": {
                "description": "List of plan steps.",
                "type": "array",
                "items": {"type": "string"},
            },
            "step_index": {
                "description": "Index of the step to update (0-based).",
                "type": "integer",
            },
            "step_status": {
                "description": "Status to set for a step.",
                "enum": ["not_started", "in_progress", "completed", "blocked"],
                "type": "string",
            },
            "step_notes": {
                "description": "Additional notes for a step.",
                "type": "string",
            },
        },
        "required": ["command"],
        "additionalProperties": False,
    }

    plans: Dict[str, dict] = Field(default_factory=dict)
    current_plan_id: Optional[str] = Field(default=None)

    async def execute(
        self,
        *,
        command: Literal[
            "create", "update", "list", "get", "set_active", "mark_step", "delete"
        ],
        plan_id: Optional[str] = None,
        title: Optional[str] = None,
        steps: Optional[List[str]] = None,
        step_index: Optional[int] = None,
        step_status: Optional[
            Literal["not_started", "in_progress", "completed", "blocked"]
        ] = None,
        step_notes: Optional[str] = None,
        **kwargs: Any,
    ) -> ToolResult:
        """Execute the planning tool with the given command and parameters."""
        if command == "create":
            return self._create_plan(plan_id, title, steps)
        elif command == "update":
            return self._update_plan(plan_id, title, steps)
        elif command == "list":
            return self._list_plans()
        elif command == "get":
            return self._get_plan(plan_id)
        elif command == "set_active":
            return self._set_active_plan(plan_id)
        elif command == "mark_step":
            return self._mark_step(
                plan_id, step_index, step_status, step_notes
            )
        elif command == "delete":
            return self._delete_plan(plan_id)
        else:
            return ToolResult(
                error=(
                    f"Unrecognized command: {command}. "
                    "Allowed commands are: create, update, list, get, "
                    "set_active, mark_step, delete"
                )
            )

    # ── Plan operations ──────────────────────────────────────────────

    def _create_plan(
        self,
        plan_id: Optional[str],
        title: Optional[str],
        steps: Optional[List[str]],
    ) -> ToolResult:
        if not plan_id:
            return ToolResult(
                error="Parameter `plan_id` is required for command: create"
            )
        if plan_id in self.plans:
            return ToolResult(
                error=(
                    f"A plan with ID '{plan_id}' already exists. "
                    "Use 'update' to modify existing plans."
                )
            )
        if not title:
            return ToolResult(error="Parameter `title` is required for command: create")
        if not steps or not isinstance(steps, list) or not all(
            isinstance(s, str) for s in steps
        ):
            return ToolResult(
                error=(
                    "Parameter `steps` must be a non-empty list of strings "
                    "for command: create"
                )
            )

        plan = {
            "plan_id": plan_id,
            "title": title,
            "steps": steps,
            "step_statuses": ["not_started"] * len(steps),
            "step_notes": [""] * len(steps),
        }
        self.plans[plan_id] = plan
        self.current_plan_id = plan_id

        return ToolResult(
            output=(
                f"Plan created successfully with ID: {plan_id}\n\n"
                f"{self._format_plan(plan)}"
            )
        )

    def _update_plan(
        self,
        plan_id: Optional[str],
        title: Optional[str],
        steps: Optional[List[str]],
    ) -> ToolResult:
        if not plan_id:
            return ToolResult(error="Parameter `plan_id` is required for command: update")
        if plan_id not in self.plans:
            return ToolResult(error=f"No plan found with ID: {plan_id}")

        plan = self.plans[plan_id]
        if title:
            plan["title"] = title

        if steps:
            if not isinstance(steps, list) or not all(
                isinstance(s, str) for s in steps
            ):
                return ToolResult(
                    error=(
                        "Parameter `steps` must be a list of strings "
                        "for command: update"
                    )
                )
            old_steps = plan["steps"]
            old_statuses = plan["step_statuses"]
            old_notes = plan["step_notes"]

            new_statuses = []
            new_notes = []
            for i, step in enumerate(steps):
                if i < len(old_steps) and step == old_steps[i]:
                    new_statuses.append(old_statuses[i])
                    new_notes.append(old_notes[i])
                else:
                    new_statuses.append("not_started")
                    new_notes.append("")

            plan["steps"] = steps
            plan["step_statuses"] = new_statuses
            plan["step_notes"] = new_notes

        return ToolResult(
            output=f"Plan updated successfully: {plan_id}\n\n{self._format_plan(plan)}"
        )

    def _list_plans(self) -> ToolResult:
        if not self.plans:
            return ToolResult(
                output=(
                    "No plans available. Create a plan with the 'create' command."
                )
            )
        output = "Available plans:\n"
        for pid, plan in self.plans.items():
            current_marker = " (active)" if pid == self.current_plan_id else ""
            completed = sum(1 for s in plan["step_statuses"] if s == "completed")
            total = len(plan["steps"])
            progress = f"{completed}/{total} steps completed"
            output += (
                f"• {pid}{current_marker}: {plan['title']} - {progress}\n"
            )
        return ToolResult(output=output)

    def _get_plan(self, plan_id: Optional[str]) -> ToolResult:
        if not plan_id:
            if not self.current_plan_id:
                return ToolResult(
                    error=(
                        "No active plan. Please specify a plan_id or "
                        "set an active plan."
                    )
                )
            plan_id = self.current_plan_id
        if plan_id not in self.plans:
            return ToolResult(error=f"No plan found with ID: {plan_id}")
        return ToolResult(output=self._format_plan(self.plans[plan_id]))

    def _set_active_plan(self, plan_id: Optional[str]) -> ToolResult:
        if not plan_id:
            return ToolResult(error="Parameter `plan_id` is required for command: set_active")
        if plan_id not in self.plans:
            return ToolResult(error=f"No plan found with ID: {plan_id}")
        self.current_plan_id = plan_id
        return ToolResult(
            output=(
                f"Plan '{plan_id}' is now the active plan.\n\n"
                f"{self._format_plan(self.plans[plan_id])}"
            )
        )

    def _mark_step(
        self,
        plan_id: Optional[str],
        step_index: Optional[int],
        step_status: Optional[str],
        step_notes: Optional[str],
    ) -> ToolResult:
        if not plan_id:
            if not self.current_plan_id:
                return ToolResult(
                    error=(
                        "No active plan. Please specify a plan_id or "
                        "set an active plan."
                    )
                )
            plan_id = self.current_plan_id
        if plan_id not in self.plans:
            return ToolResult(error=f"No plan found with ID: {plan_id}")
        if step_index is None:
            return ToolResult(
                error="Parameter `step_index` is required for command: mark_step"
            )
        plan = self.plans[plan_id]
        if step_index < 0 or step_index >= len(plan["steps"]):
            return ToolResult(
                error=(
                    f"Invalid step_index: {step_index}. "
                    f"Valid indices range from 0 to {len(plan['steps'])-1}."
                )
            )
        if step_status and step_status not in [
            "not_started",
            "in_progress",
            "completed",
            "blocked",
        ]:
            return ToolResult(
                error=(
                    f"Invalid step_status: {step_status}. "
                    "Valid statuses are: not_started, in_progress, completed, blocked"
                )
            )
        if step_status:
            plan["step_statuses"][step_index] = step_status
        if step_notes:
            plan["step_notes"][step_index] = step_notes
        return ToolResult(
            output=f"Step {step_index} updated in plan '{plan_id}'.\n\n"
            f"{self._format_plan(plan)}"
        )

    def _delete_plan(self, plan_id: Optional[str]) -> ToolResult:
        if not plan_id:
            return ToolResult(error="Parameter `plan_id` is required for command: delete")
        if plan_id not in self.plans:
            return ToolResult(error=f"No plan found with ID: {plan_id}")
        del self.plans[plan_id]
        if self.current_plan_id == plan_id:
            self.current_plan_id = None
        return ToolResult(output=f"Plan '{plan_id}' has been deleted.")

    def _format_plan(self, plan: dict) -> str:
        output = f"Plan: {plan['title']} (ID: {plan['plan_id']})\n"
        output += "=" * len(output) + "\n\n"

        total_steps = len(plan["steps"])
        completed = sum(1 for s in plan["step_statuses"] if s == "completed")
        in_progress = sum(1 for s in plan["step_statuses"] if s == "in_progress")
        blocked = sum(1 for s in plan["step_statuses"] if s == "blocked")
        not_started = sum(1 for s in plan["step_statuses"] if s == "not_started")

        output += f"Progress: {completed}/{total_steps} steps completed"
        if total_steps > 0:
            percentage = (completed / total_steps) * 100
            output += f" ({percentage:.1f}%)\n"
        else:
            output += "(0%)\n"

        output += (
            f"Status: {completed} completed, {in_progress} in progress, "
            f"{blocked} blocked, {not_started} not started\n\n"
        )
        output += "Steps:\n"

        for i, (step, status, notes) in enumerate(
            zip(plan["steps"], plan["step_statuses"], plan["step_notes"])
        ):
            status_symbol = {
                "not_started": "[ ]",
                "in_progress": "[→]",
                "completed": "[✓]",
                "blocked": "[!]",
            }.get(status, "[ ]")
            output += f"{i}. {status_symbol} {step}\n"
            if notes:
                output += f"   Notes: {notes}\n"

        return output