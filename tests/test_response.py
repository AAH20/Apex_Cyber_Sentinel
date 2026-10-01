"""Unit tests for machine-speed incident response (written first, TDD).

Covers containment, eradication, recovery playbook execution under a hard
wall-clock budget (sub-10s), parallel action execution, timeout enforcement,
and incident/playbook/report behavior.
"""

import time

import pytest

from src.cyber.response import (
    ActionResult,
    BlockIndicatorAction,
    DisableAccountAction,
    Incident,
    IncidentStatus,
    Indicator,
    IsolateHostAction,
    KillProcessAction,
    RemoveFileAction,
    ResponseAction,
    ResponseEngine,
    ResponsePlaybook,
    ResponseReport,
    RestoreBackupAction,
    RestartServiceAction,
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


def slow_handler(delay):
    def handler(incident):
        time.sleep(delay)
        return "ok"

    return handler


def recording_handler(log, label):
    def handler(incident):
        log.append(label)
        return "ok"

    return handler


# --- ActionResult / ResponseReport -------------------------------------------------


def test_action_result_duration_is_positive():
    result = ActionResult("a", True, 100.0, 100.25, "ok")
    assert result.duration == pytest.approx(0.25)


def test_action_result_as_dict():
    result = ActionResult("a", True, 1.0, 2.0, "ok")
    assert result.as_dict() == {
        "action": "a",
        "success": True,
        "started_at": 1.0,
        "completed_at": 2.0,
        "duration": 1.0,
        "detail": "ok",
    }


def test_report_duration():
    report = ResponseReport("INC-1", [], 100.0, 100.5)
    assert report.duration == pytest.approx(0.5)


def test_report_succeeded_true_when_all_actions_succeed():
    report = ResponseReport("INC-1", [ActionResult("a", True, 0, 1, "ok")], 0, 1)
    assert report.succeeded is True


def test_report_succeeded_false_when_any_action_fails():
    report = ResponseReport(
        "INC-1",
        [ActionResult("a", True, 0, 1, "ok"), ActionResult("b", False, 1, 2, "boom")],
        0,
        2,
    )
    assert report.succeeded is False


def test_report_with_no_actions_succeeds():
    report = ResponseReport("INC-1", [], 0, 0.01)
    assert report.succeeded is True


def test_report_as_dict_contains_actions():
    report = ResponseReport("INC-1", [ActionResult("a", True, 0, 1, "ok")], 0, 1)
    data = report.as_dict()
    assert data["incident_id"] == "INC-1"
    assert data["succeeded"] is True
    assert len(data["actions"]) == 1
    assert data["actions"][0]["action"] == "a"


# --- ResponseEngine ---------------------------------------------------------------


def test_engine_runs_phases_in_order():
    order = []
    playbook = ResponsePlaybook(
        [
            ("containment", [ResponseAction("c1", recording_handler(order, "containment"))]),
            ("eradication", [ResponseAction("e1", recording_handler(order, "eradication"))]),
            ("recovery", [ResponseAction("r1", recording_handler(order, "recovery"))]),
        ]
    )
    report = ResponseEngine(playbook).respond(make_incident())
    assert order == ["containment", "eradication", "recovery"]
    assert report.succeeded is True


def test_engine_runs_actions_within_phase_in_parallel():
    playbook = ResponsePlaybook(
        [
            (
                "containment",
                [
                    ResponseAction("a", slow_handler(0.3)),
                    ResponseAction("b", slow_handler(0.3)),
                    ResponseAction("c", slow_handler(0.3)),
                ],
            ),
        ]
    )
    report = ResponseEngine(playbook).respond(make_incident())
    # Sequential execution would take >= 0.9s; parallel must be well under that.
    assert report.duration < 0.7
    assert report.succeeded is True
    assert len(report.actions) == 3


def test_engine_enforces_action_timeout():
    playbook = ResponsePlaybook(
        [("containment", [ResponseAction("slow", slow_handler(30.0))])]
    )
    engine = ResponseEngine(playbook, max_duration=10.0, action_timeout=0.2)
    report = engine.respond(make_incident())
    assert report.duration < 1.0
    assert report.succeeded is False
    assert "timeout" in report.actions[0].detail.lower()


def test_engine_enforces_total_budget():
    playbook = ResponsePlaybook(
        [
            ("containment", [ResponseAction("slow", slow_handler(30.0))]),
            ("eradication", [ResponseAction("never", slow_handler(30.0))]),
        ]
    )
    engine = ResponseEngine(playbook, max_duration=0.5, action_timeout=30.0)
    report = engine.respond(make_incident())
    assert report.duration < 1.5
    assert report.within_budget is True
    assert report.succeeded is False


def test_engine_marks_actions_skipped_when_budget_exhausted():
    playbook = ResponsePlaybook(
        [
            ("containment", [ResponseAction("slow", slow_handler(30.0))]),
            ("eradication", [ResponseAction("never", recording_handler([], "never"))]),
        ]
    )
    engine = ResponseEngine(playbook, max_duration=0.3, action_timeout=30.0)
    report = engine.respond(make_incident())
    assert len(report.actions) == 2
    assert report.actions[0].success is False
    assert "timeout" in report.actions[0].detail.lower()
    assert report.actions[1].success is False
    assert "skip" in report.actions[1].detail.lower()


def test_engine_handles_action_exception():
    def bad_handler(incident):
        raise RuntimeError("boom")

    playbook = ResponsePlaybook([("containment", [ResponseAction("bad", bad_handler)])])
    report = ResponseEngine(playbook).respond(make_incident())
    assert report.succeeded is False
    assert "boom" in report.actions[0].detail


def test_engine_empty_playbook_succeeds():
    report = ResponseEngine(ResponsePlaybook([])).respond(make_incident())
    assert report.succeeded is True
    assert report.actions == []
    assert report.duration < 1.0


def test_engine_returns_report_with_incident_id():
    report = ResponseEngine(ResponsePlaybook([])).respond(make_incident(id="INC-42"))
    assert report.incident_id == "INC-42"


def test_engine_rejects_non_positive_budget():
    with pytest.raises(ValueError):
        ResponseEngine(ResponsePlaybook([]), max_duration=0)


def test_default_engine_budget_is_under_10_seconds():
    engine = ResponseEngine(ResponsePlaybook.default())
    assert engine.max_duration < 10.0


# --- Concrete response actions -----------------------------------------------------


def test_isolate_host_action_success():
    seen = []
    action = IsolateHostAction(handler=lambda inc: seen.append(inc.affected_assets) or "isolated")
    result = action.execute(make_incident())
    assert result.success is True
    assert result.action == "isolate_host"
    assert seen == [["fs-01"]]


def test_block_indicator_action_success():
    action = BlockIndicatorAction(handler=lambda inc: f"blocked {len(inc.indicators)} indicators")
    result = action.execute(make_incident())
    assert result.success is True
    assert result.action == "block_indicator"
    assert "1 indicators" in result.detail


def test_disable_account_action_success():
    action = DisableAccountAction(handler=lambda inc: "account disabled")
    result = action.execute(make_incident())
    assert result.success is True
    assert result.action == "disable_account"


def test_kill_process_action_success():
    action = KillProcessAction(handler=lambda inc: "process killed")
    result = action.execute(make_incident())
    assert result.success is True
    assert result.action == "kill_process"


def test_remove_file_action_success():
    action = RemoveFileAction(handler=lambda inc: "file removed")
    result = action.execute(make_incident())
    assert result.success is True
    assert result.action == "remove_file"


def test_restore_backup_action_success():
    action = RestoreBackupAction(handler=lambda inc: "backup restored")
    result = action.execute(make_incident())
    assert result.success is True
    assert result.action == "restore_backup"


def test_restart_service_action_success():
    action = RestartServiceAction(handler=lambda inc: "service restarted")
    result = action.execute(make_incident())
    assert result.success is True
    assert result.action == "restart_service"


def test_action_failure_captures_exception():
    action = IsolateHostAction(handler=lambda inc: 1 / 0)
    result = action.execute(make_incident())
    assert result.success is False
    assert "ZeroDivisionError" in result.detail


# --- ResponsePlaybook --------------------------------------------------------------


def test_playbook_phases_returns_configured_order():
    a, b = ResponseAction("a"), ResponseAction("b")
    playbook = ResponsePlaybook([("containment", [a]), ("recovery", [b])])
    assert playbook.phases() == [("containment", [a]), ("recovery", [b])]


def test_default_playbook_has_three_phases():
    playbook = ResponsePlaybook.default()
    names = [name for name, _ in playbook.phases()]
    assert names == ["containment", "eradication", "recovery"]


def test_default_playbook_actions_have_unique_names():
    playbook = ResponsePlaybook.default()
    names = [action.name for _, actions in playbook.phases() for action in actions]
    assert len(names) == len(set(names))
    assert "isolate_host" in names
    assert "restore_backup" in names


# --- Incident ----------------------------------------------------------------------


def test_incident_status_defaults_to_detected():
    assert make_incident().status == IncidentStatus.DETECTED


def test_incident_contain_marks_contained():
    incident = make_incident()
    incident.contain()
    assert incident.status == IncidentStatus.CONTAINED


def test_incident_eradicate_marks_eradicated():
    incident = make_incident()
    incident.eradicate()
    assert incident.status == IncidentStatus.ERADICATED


def test_incident_recover_marks_recovered():
    incident = make_incident()
    incident.recover()
    assert incident.status == IncidentStatus.RECOVERED


def test_incident_with_no_indicators_still_responds():
    incident = make_incident(indicators=[])
    report = ResponseEngine(ResponsePlaybook.default()).respond(incident)
    assert report.succeeded is True


def test_severity_rank_ordering():
    assert Incident.severity_rank("critical") > Incident.severity_rank("high")
    assert Incident.severity_rank("high") > Incident.severity_rank("medium")
    assert Incident.severity_rank("medium") > Incident.severity_rank("low")
    with pytest.raises(ValueError):
        Incident.severity_rank("bogus")
