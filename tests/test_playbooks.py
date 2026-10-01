"""Unit tests for automated containment, eradication, and recovery playbooks.

Written first (TDD). Covers playbook phase structure, execution, incident
status transitions, result reporting, and orchestrator chaining.
"""

import time

import pytest

from src.cyber.playbooks import (
    ContainmentPlaybook,
    EradicationPlaybook,
    PlaybookOrchestrator,
    RecoveryPlaybook,
)
from src.cyber.response import (
    Incident,
    IncidentStatus,
    Indicator,
    ResponseAction,
)


def make_incident(**overrides):
    data = dict(
        id="INC-001",
        severity="critical",
        title="Ransomware on file server",
        indicators=[Indicator(type="ip", value="203.0.113.10")],
        affected_assets=["fs-01"],
        detected_at=time.time(),
    )
    data.update(overrides)
    return Incident(**data)


# --- ContainmentPlaybook -------------------------------------------------------


def test_containment_playbook_has_three_phases():
    playbook = ContainmentPlaybook()
    names = [phase.name for phase in playbook.phases]
    assert names == ["isolate_hosts", "block_indicators", "disable_accounts"]


def test_containment_playbook_executes_successfully():
    playbook = ContainmentPlaybook()
    result = playbook.execute(make_incident())
    assert result.succeeded is True
    assert len(result.phases) == 3


def test_containment_playbook_marks_incident_contained():
    playbook = ContainmentPlaybook()
    incident = make_incident()
    playbook.execute(incident)
    assert incident.status == IncidentStatus.CONTAINED


# --- EradicationPlaybook -------------------------------------------------------


def test_eradication_playbook_has_three_phases():
    playbook = EradicationPlaybook()
    names = [phase.name for phase in playbook.phases]
    assert names == ["kill_processes", "remove_files", "clean_registry"]


def test_eradication_playbook_executes_successfully():
    playbook = EradicationPlaybook()
    result = playbook.execute(make_incident())
    assert result.succeeded is True
    assert len(result.phases) == 3


def test_eradication_playbook_marks_incident_eradicated():
    playbook = EradicationPlaybook()
    incident = make_incident()
    playbook.execute(incident)
    assert incident.status == IncidentStatus.ERADICATED


# --- RecoveryPlaybook ----------------------------------------------------------


def test_recovery_playbook_has_three_phases():
    playbook = RecoveryPlaybook()
    names = [phase.name for phase in playbook.phases]
    assert names == ["restore_backups", "restart_services", "verify_health"]


def test_recovery_playbook_executes_successfully():
    playbook = RecoveryPlaybook()
    result = playbook.execute(make_incident())
    assert result.succeeded is True
    assert len(result.phases) == 3


def test_recovery_playbook_marks_incident_recovered():
    playbook = RecoveryPlaybook()
    incident = make_incident()
    playbook.execute(incident)
    assert incident.status == IncidentStatus.RECOVERED


# --- PlaybookResult ------------------------------------------------------------


def test_playbook_result_succeeded_true_when_all_phases_succeed():
    playbook = ContainmentPlaybook()
    result = playbook.execute(make_incident())
    assert result.succeeded is True


def test_playbook_result_succeeded_false_when_any_phase_fails():
    def bad_handler(incident):
        raise RuntimeError("boom")

    playbook = ContainmentPlaybook()
    playbook.phases[0].actions[0] = ResponseAction("bad", bad_handler)
    result = playbook.execute(make_incident())
    assert result.succeeded is False


def test_playbook_result_duration():
    playbook = ContainmentPlaybook()
    result = playbook.execute(make_incident())
    assert result.duration > 0
    assert result.duration < 5.0


def test_playbook_result_as_dict():
    playbook = ContainmentPlaybook()
    result = playbook.execute(make_incident())
    data = result.as_dict()
    assert data["playbook"] == "containment"
    assert data["incident_id"] == "INC-001"
    assert data["succeeded"] is True
    assert len(data["phases"]) == 3


# --- PhaseResult ---------------------------------------------------------------


def test_phase_result_succeeded():
    playbook = ContainmentPlaybook()
    result = playbook.execute(make_incident())
    for phase in result.phases:
        assert phase.succeeded is True


def test_phase_result_duration():
    playbook = ContainmentPlaybook()
    result = playbook.execute(make_incident())
    for phase in result.phases:
        assert phase.duration >= 0


# --- PlaybookOrchestrator ------------------------------------------------------


def test_orchestrator_runs_all_three_playbooks_in_order():
    orchestrator = PlaybookOrchestrator()
    incident = make_incident()
    result = orchestrator.run(incident)
    assert len(result.playbook_results) == 3
    assert result.playbook_results[0].playbook_name == "containment"
    assert result.playbook_results[1].playbook_name == "eradication"
    assert result.playbook_results[2].playbook_name == "recovery"
    assert incident.status == IncidentStatus.RECOVERED


def test_orchestrator_stops_on_containment_failure():
    def bad_handler(incident):
        raise RuntimeError("boom")

    orchestrator = PlaybookOrchestrator()
    orchestrator.playbooks[0].phases[0].actions[0] = ResponseAction("bad", bad_handler)
    incident = make_incident()
    result = orchestrator.run(incident)
    assert len(result.playbook_results) == 1
    assert result.playbook_results[0].succeeded is False


def test_orchestrator_result_contains_all_playbook_results():
    orchestrator = PlaybookOrchestrator()
    result = orchestrator.run(make_incident())
    assert result.succeeded is True
    assert result.duration > 0


# --- Custom playbook configuration ---------------------------------------------


def test_containment_playbook_with_custom_actions():
    custom_action = ResponseAction("custom", lambda inc: "custom")
    playbook = ContainmentPlaybook()
    playbook.phases[0].actions.append(custom_action)
    result = playbook.execute(make_incident())
    assert result.succeeded is True
    assert len(result.phases[0].actions) == 2


def test_playbook_empty_phases_succeeds():
    playbook = ContainmentPlaybook()
    playbook.phases = []
    result = playbook.execute(make_incident())
    assert result.succeeded is True
    assert result.phases == []
