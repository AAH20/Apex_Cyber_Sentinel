"""Automated containment, eradication, and recovery playbooks.

Each playbook consists of ordered phases containing response actions.
Playbooks execute against an Incident and transition its status.
The PlaybookOrchestrator chains all three playbooks in sequence.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List

from src.cyber.response import (
    Incident,
    IncidentStatus,
    ResponseAction,
)


@dataclass
class PhaseResult:
    name: str
    actions: List[Dict[str, Any]]
    started_at: float
    completed_at: float

    @property
    def duration(self) -> float:
        return self.completed_at - self.started_at

    @property
    def succeeded(self) -> bool:
        return all(a["success"] for a in self.actions)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "succeeded": self.succeeded,
            "duration": self.duration,
            "actions": self.actions,
        }


@dataclass
class PlaybookResult:
    playbook_name: str
    incident_id: str
    phases: List[PhaseResult]
    started_at: float
    completed_at: float

    @property
    def duration(self) -> float:
        return self.completed_at - self.started_at

    @property
    def succeeded(self) -> bool:
        return all(p.succeeded for p in self.phases)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "playbook": self.playbook_name,
            "incident_id": self.incident_id,
            "succeeded": self.succeeded,
            "duration": self.duration,
            "phases": [p.as_dict() for p in self.phases],
        }


@dataclass
class Phase:
    name: str
    actions: List[ResponseAction] = field(default_factory=list)

    def execute(self, incident: Incident) -> PhaseResult:
        started = time.monotonic()
        action_dicts: List[Dict[str, Any]] = []
        for action in self.actions:
            result = action.execute(incident)
            action_dicts.append(result.as_dict())
        completed = time.monotonic()
        return PhaseResult(self.name, action_dicts, started, completed)


class BasePlaybook:
    playbook_name: str = "base"

    def __init__(self):
        self.phases: List[Phase] = []

    def execute(self, incident: Incident) -> PlaybookResult:
        started = time.monotonic()
        phase_results: List[PhaseResult] = []
        for phase in self.phases:
            phase_results.append(phase.execute(incident))
        completed = time.monotonic()
        return PlaybookResult(
            self.playbook_name, incident.id, phase_results, started, completed
        )


class ContainmentPlaybook(BasePlaybook):
    playbook_name = "containment"

    def __init__(self):
        super().__init__()
        self.phases = [
            Phase("isolate_hosts", [ResponseAction("isolate_host", lambda inc: "host isolated")]),
            Phase("block_indicators", [ResponseAction("block_indicator", lambda inc: "indicator blocked")]),
            Phase("disable_accounts", [ResponseAction("disable_account", lambda inc: "account disabled")]),
        ]

    def execute(self, incident: Incident) -> PlaybookResult:
        result = super().execute(incident)
        incident.contain()
        return result


class EradicationPlaybook(BasePlaybook):
    playbook_name = "eradication"

    def __init__(self):
        super().__init__()
        self.phases = [
            Phase("kill_processes", [ResponseAction("kill_process", lambda inc: "process killed")]),
            Phase("remove_files", [ResponseAction("remove_file", lambda inc: "file removed")]),
            Phase("clean_registry", [ResponseAction("clean_registry", lambda inc: "registry cleaned")]),
        ]

    def execute(self, incident: Incident) -> PlaybookResult:
        result = super().execute(incident)
        incident.eradicate()
        return result


class RecoveryPlaybook(BasePlaybook):
    playbook_name = "recovery"

    def __init__(self):
        super().__init__()
        self.phases = [
            Phase("restore_backups", [ResponseAction("restore_backup", lambda inc: "backup restored")]),
            Phase("restart_services", [ResponseAction("restart_service", lambda inc: "service restarted")]),
            Phase("verify_health", [ResponseAction("verify_health", lambda inc: "health verified")]),
        ]

    def execute(self, incident: Incident) -> PlaybookResult:
        result = super().execute(incident)
        incident.recover()
        return result


@dataclass
class OrchestratorResult:
    playbook_results: List[PlaybookResult]
    started_at: float
    completed_at: float

    @property
    def duration(self) -> float:
        return self.completed_at - self.started_at

    @property
    def succeeded(self) -> bool:
        return all(r.succeeded for r in self.playbook_results)


class PlaybookOrchestrator:
    def __init__(self):
        self.playbooks: List[BasePlaybook] = [
            ContainmentPlaybook(),
            EradicationPlaybook(),
            RecoveryPlaybook(),
        ]

    def run(self, incident: Incident) -> OrchestratorResult:
        started = time.monotonic()
        results: List[PlaybookResult] = []
        for playbook in self.playbooks:
            result = playbook.execute(incident)
            results.append(result)
            if not result.succeeded:
                break
        completed = time.monotonic()
        return OrchestratorResult(results, started, completed)
