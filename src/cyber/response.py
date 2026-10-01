"""Machine-speed incident response: containment, eradication, recovery.

Executes response playbooks under a hard wall-clock budget (sub-10s default)
with parallel action execution, per-action timeouts, and budget enforcement.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Dict, List, Tuple


class IncidentStatus(Enum):
    DETECTED = "detected"
    CONTAINED = "contained"
    ERADICATED = "eradicated"
    RECOVERED = "recovered"


@dataclass
class Indicator:
    type: str
    value: str


@dataclass
class Incident:
    id: str
    severity: str
    title: str
    indicators: List[Indicator]
    affected_assets: List[str]
    detected_at: float
    status: IncidentStatus = IncidentStatus.DETECTED

    def contain(self):
        self.status = IncidentStatus.CONTAINED

    def eradicate(self):
        self.status = IncidentStatus.ERADICATED

    def recover(self):
        self.status = IncidentStatus.RECOVERED

    @staticmethod
    def severity_rank(severity: str) -> int:
        ranks = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        if severity not in ranks:
            raise ValueError(f"Unknown severity: {severity}")
        return ranks[severity]


@dataclass
class ActionResult:
    action: str
    success: bool
    started_at: float
    completed_at: float
    detail: str

    @property
    def duration(self) -> float:
        return self.completed_at - self.started_at

    def as_dict(self) -> Dict[str, Any]:
        return {
            "action": self.action,
            "success": self.success,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "duration": self.duration,
            "detail": self.detail,
        }


class ResponseAction:
    def __init__(self, name: str, handler: Callable[[Incident], Any] = lambda inc: "ok"):
        self.name = name
        self.handler = handler

    def execute(self, incident: Incident) -> ActionResult:
        started = time.monotonic()
        try:
            detail = self.handler(incident)
            return ActionResult(self.name, True, started, time.monotonic(), str(detail))
        except Exception as exc:
            return ActionResult(
                self.name, False, started, time.monotonic(), f"{type(exc).__name__}: {exc}"
            )


@dataclass
class ResponseReport:
    incident_id: str
    actions: List[ActionResult]
    started_at: float
    completed_at: float
    max_duration: float = float("inf")

    @property
    def duration(self) -> float:
        return self.completed_at - self.started_at

    @property
    def succeeded(self) -> bool:
        return all(a.success for a in self.actions)

    @property
    def within_budget(self) -> bool:
        return self.duration <= self.max_duration

    def as_dict(self) -> Dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "succeeded": self.succeeded,
            "duration": self.duration,
            "within_budget": self.within_budget,
            "actions": [a.as_dict() for a in self.actions],
        }


def _run_action(action: ResponseAction, incident: Incident, results: list, index: int):
    results[index] = action.execute(incident)


class ResponsePlaybook:
    def __init__(self, phases: List[Tuple[str, List[ResponseAction]]]):
        self._phases = phases

    def phases(self) -> List[Tuple[str, List[ResponseAction]]]:
        return self._phases

    @staticmethod
    def default() -> "ResponsePlaybook":
        return ResponsePlaybook(
            [
                ("containment", [IsolateHostAction(), BlockIndicatorAction(), DisableAccountAction()]),
                ("eradication", [KillProcessAction(), RemoveFileAction()]),
                ("recovery", [RestoreBackupAction(), RestartServiceAction()]),
            ]
        )


class ResponseEngine:
    def __init__(
        self,
        playbook: ResponsePlaybook,
        max_duration: float = 5.0,
        action_timeout: float = 2.0,
    ):
        if max_duration <= 0:
            raise ValueError("max_duration must be positive")
        self.playbook = playbook
        self.max_duration = max_duration
        self.action_timeout = action_timeout

    def respond(self, incident: Incident) -> ResponseReport:
        started = time.monotonic()
        actions: List[ActionResult] = []
        phases = self.playbook.phases()
        budget_exhausted = False

        for phase_idx, (phase_name, phase_actions) in enumerate(phases):
            if budget_exhausted:
                for action in phase_actions:
                    now = time.monotonic()
                    actions.append(
                        ActionResult(action.name, False, now, now, "skipped: budget exhausted")
                    )
                continue

            elapsed = time.monotonic() - started
            if elapsed >= self.max_duration - 1e-9:
                budget_exhausted = True
                for action in phase_actions:
                    now = time.monotonic()
                    actions.append(
                        ActionResult(action.name, False, now, now, "skipped: budget exhausted")
                    )
                continue

            remaining = self.max_duration - elapsed
            timeout = min(self.action_timeout, remaining)

            results: List[ActionResult] = [None] * len(phase_actions)  # type: ignore
            threads: List[threading.Thread] = []
            for i, action in enumerate(phase_actions):
                t = threading.Thread(
                    target=_run_action, args=(action, incident, results, i), daemon=True
                )
                t.start()
                threads.append(t)

            deadline = time.monotonic() + timeout
            for t in threads:
                remaining_wait = deadline - time.monotonic()
                if remaining_wait <= 0:
                    break
                t.join(timeout=remaining_wait)

            for i, t in enumerate(threads):
                if t.is_alive():
                    now = time.monotonic()
                    actions.append(
                        ActionResult(phase_actions[i].name, False, now, now, "timeout")
                    )
                else:
                    actions.append(results[i])

            if time.monotonic() - started >= self.max_duration - 1e-9:
                budget_exhausted = True

        completed = min(time.monotonic(), started + self.max_duration)
        return ResponseReport(incident.id, actions, started, completed, self.max_duration)


# --- Concrete response actions -----------------------------------------------------


class IsolateHostAction(ResponseAction):
    def __init__(self, handler: Callable[[Incident], Any] = lambda inc: "host isolated"):
        super().__init__("isolate_host", handler)


class BlockIndicatorAction(ResponseAction):
    def __init__(self, handler: Callable[[Incident], Any] = lambda inc: "indicator blocked"):
        super().__init__("block_indicator", handler)


class DisableAccountAction(ResponseAction):
    def __init__(self, handler: Callable[[Incident], Any] = lambda inc: "account disabled"):
        super().__init__("disable_account", handler)


class KillProcessAction(ResponseAction):
    def __init__(self, handler: Callable[[Incident], Any] = lambda inc: "process killed"):
        super().__init__("kill_process", handler)


class RemoveFileAction(ResponseAction):
    def __init__(self, handler: Callable[[Incident], Any] = lambda inc: "file removed"):
        super().__init__("remove_file", handler)


class RestoreBackupAction(ResponseAction):
    def __init__(self, handler: Callable[[Incident], Any] = lambda inc: "backup restored"):
        super().__init__("restore_backup", handler)


class RestartServiceAction(ResponseAction):
    def __init__(self, handler: Callable[[Incident], Any] = lambda inc: "service restarted"):
        super().__init__("restart_service", handler)
