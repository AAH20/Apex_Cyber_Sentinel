"""Unit tests for advanced threat hunting: hypothesis-driven hunting, anomaly correlation, actor profiling."""
from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from src.cyber.hunt_advanced import (
    Anomaly,
    AnomalyCorrelator,
    CorrelationRule,
    CorrelationResult,
    HuntHypothesis,
    HypothesisEngine,
    HypothesisEvaluation,
    Indicator,
    IOCType,
    Severity,
    ThreatActorProfile,
    ActorProfiler,
    TTP,
    ActorMatch,
)


# ── Hypothesis-driven hunting ─────────────────────────────────────────

class TestHypothesisCreation:
    def test_create_hypothesis(self):
        engine = HypothesisEngine()
        h = engine.create_hypothesis(
            description="APT29 targeting via spearphishing",
            hypothesis_type="apt_targeting",
        )
        assert h.description == "APT29 targeting via spearphishing"
        assert h.hypothesis_type == "apt_targeting"
        assert h.status == "open"
        assert h.confidence == 0.0

    def test_create_hypothesis_with_expected_iocs(self):
        engine = HypothesisEngine()
        iocs = [Indicator("evil.com", IOCType.DOMAIN, Severity.HIGH)]
        h = engine.create_hypothesis(
            description="C2 communication",
            hypothesis_type="c2",
            expected_iocs=iocs,
        )
        assert len(h.expected_iocs) == 1
        assert h.expected_iocs[0].value == "evil.com"

    def test_create_hypothesis_with_expected_ttps(self):
        engine = HypothesisEngine()
        ttps = [TTP("Command and Control", "T1071", "Application Layer Protocol")]
        h = engine.create_hypothesis(
            description="DNS tunneling",
            hypothesis_type="exfiltration",
            expected_ttps=ttps,
        )
        assert len(h.expected_ttps) == 1
        assert h.expected_ttps[0].technique_id == "T1071"


class TestHypothesisEvaluation:
    def test_evaluate_confirmed_with_ioc_match(self):
        engine = HypothesisEngine()
        engine.add_ioc(Indicator("10.0.0.1", IOCType.IP, Severity.CRITICAL))
        h = engine.create_hypothesis(
            description="C2 beacon",
            hypothesis_type="c2",
        )
        events = [{"src_ip": "10.0.0.1", "dst_ip": "192.168.1.1"}]
        result = engine.evaluate(h, events)
        assert result.status == "confirmed"
        assert result.confidence > 0.0
        assert len(result.matched_iocs) == 1

    def test_evaluate_confirmed_with_ttp_match(self):
        engine = HypothesisEngine()
        engine.add_ttp(TTP(
            tactic="Command and Control",
            technique_id="T1071",
            technique_name="Application Layer Protocol",
            event_patterns=["dns tunnel", "beacon"],
        ))
        h = engine.create_hypothesis(
            description="DNS tunneling exfil",
            hypothesis_type="exfiltration",
        )
        events = [{"message": "detected dns tunnel activity"}]
        result = engine.evaluate(h, events)
        assert result.status == "confirmed"
        assert len(result.matched_ttps) == 1

    def test_evaluate_rejected_no_matches(self):
        engine = HypothesisEngine()
        h = engine.create_hypothesis(
            description="Check for C2",
            hypothesis_type="c2",
        )
        events = [{"src_ip": "192.168.1.1", "action": "normal"}]
        result = engine.evaluate(h, events)
        assert result.status == "rejected"
        assert result.confidence == 0.0

    def test_evaluate_confidence_increases_with_more_evidence(self):
        engine = HypothesisEngine()
        engine.add_ioc(Indicator("10.0.0.1", IOCType.IP, Severity.CRITICAL))
        engine.add_ioc(Indicator("10.0.0.2", IOCType.IP, Severity.HIGH))
        h = engine.create_hypothesis(description="Multi-IOC", hypothesis_type="c2")
        events_one = [{"src_ip": "10.0.0.1"}]
        events_both = [{"src_ip": "10.0.0.1"}, {"src_ip": "10.0.0.2"}]
        r1 = engine.evaluate(h, events_one)
        r2 = engine.evaluate(h, events_both)
        assert r2.confidence > r1.confidence

    def test_evaluate_empty_events_rejected(self):
        engine = HypothesisEngine()
        engine.add_ioc(Indicator("10.0.0.1", IOCType.IP))
        h = engine.create_hypothesis(description="Test", hypothesis_type="c2")
        result = engine.evaluate(h, [])
        assert result.status == "rejected"


class TestHypothesisRanking:
    def test_rank_hypotheses_by_confidence(self):
        engine = HypothesisEngine()
        engine.add_ioc(Indicator("10.0.0.1", IOCType.IP, Severity.CRITICAL))
        h1 = engine.create_hypothesis(description="High conf", hypothesis_type="c2")
        h2 = engine.create_hypothesis(description="Low conf", hypothesis_type="c2")
        events = [{"src_ip": "10.0.0.1"}]
        engine.evaluate(h1, events)
        engine.evaluate(h2, [])
        ranked = engine.rank_hypotheses()
        assert ranked[0].hypothesis.description == "High conf"
        assert ranked[0].confidence >= ranked[1].confidence

    def test_rank_empty_hypotheses(self):
        engine = HypothesisEngine()
        assert engine.rank_hypotheses() == []


# ── Anomaly correlation ───────────────────────────────────────────────

class TestAnomalyCorrelation:
    def test_correlate_same_entity_same_type(self):
        correlator = AnomalyCorrelator()
        now = datetime(2024, 1, 1, 12, 0, 0)
        correlator.add_anomaly(Anomaly(
            id="a1", entity="host-1", anomaly_type="cpu_spike",
            severity=Severity.HIGH, timestamp=now,
        ))
        correlator.add_anomaly(Anomaly(
            id="a2", entity="host-1", anomaly_type="cpu_spike",
            severity=Severity.HIGH, timestamp=now + timedelta(minutes=5),
        ))
        rule = CorrelationRule(
            name="repeated_cpu",
            anomaly_types=["cpu_spike"],
            time_window=timedelta(minutes=30),
            min_count=2,
        )
        results = correlator.correlate([rule])
        assert len(results) == 1
        assert results[0].rule_name == "repeated_cpu"
        assert len(results[0].anomalies) == 2

    def test_correlate_different_entities_no_match(self):
        correlator = AnomalyCorrelator()
        now = datetime(2024, 1, 1, 12, 0, 0)
        correlator.add_anomaly(Anomaly(
            id="a1", entity="host-1", anomaly_type="cpu_spike",
            severity=Severity.HIGH, timestamp=now,
        ))
        correlator.add_anomaly(Anomaly(
            id="a2", entity="host-2", anomaly_type="cpu_spike",
            severity=Severity.HIGH, timestamp=now + timedelta(minutes=5),
        ))
        rule = CorrelationRule(
            name="same_host_cpu",
            anomaly_types=["cpu_spike"],
            time_window=timedelta(minutes=30),
            min_count=2,
        )
        results = correlator.correlate([rule])
        assert len(results) == 0

    def test_correlate_outside_time_window(self):
        correlator = AnomalyCorrelator()
        now = datetime(2024, 1, 1, 12, 0, 0)
        correlator.add_anomaly(Anomaly(
            id="a1", entity="host-1", anomaly_type="cpu_spike",
            severity=Severity.HIGH, timestamp=now,
        ))
        correlator.add_anomaly(Anomaly(
            id="a2", entity="host-1", anomaly_type="cpu_spike",
            severity=Severity.HIGH, timestamp=now + timedelta(hours=2),
        ))
        rule = CorrelationRule(
            name="quick_burst",
            anomaly_types=["cpu_spike"],
            time_window=timedelta(minutes=30),
            min_count=2,
        )
        results = correlator.correlate([rule])
        assert len(results) == 0

    def test_correlate_multiple_types(self):
        correlator = AnomalyCorrelator()
        now = datetime(2024, 1, 1, 12, 0, 0)
        correlator.add_anomaly(Anomaly(
            id="a1", entity="host-1", anomaly_type="cpu_spike",
            severity=Severity.HIGH, timestamp=now,
        ))
        correlator.add_anomaly(Anomaly(
            id="a2", entity="host-1", anomaly_type="mem_spike",
            severity=Severity.HIGH, timestamp=now + timedelta(minutes=2),
        ))
        rule = CorrelationRule(
            name="resource_exhaustion",
            anomaly_types=["cpu_spike", "mem_spike"],
            time_window=timedelta(minutes=30),
            min_count=2,
        )
        results = correlator.correlate([rule])
        assert len(results) == 1
        assert len(results[0].anomalies) == 2

    def test_correlate_empty_anomalies(self):
        correlator = AnomalyCorrelator()
        rule = CorrelationRule(
            name="test",
            anomaly_types=["cpu_spike"],
            time_window=timedelta(minutes=30),
            min_count=2,
        )
        results = correlator.correlate([rule])
        assert len(results) == 0

    def test_correlate_below_min_count(self):
        correlator = AnomalyCorrelator()
        now = datetime(2024, 1, 1, 12, 0, 0)
        correlator.add_anomaly(Anomaly(
            id="a1", entity="host-1", anomaly_type="cpu_spike",
            severity=Severity.HIGH, timestamp=now,
        ))
        rule = CorrelationRule(
            name="needs_three",
            anomaly_types=["cpu_spike"],
            time_window=timedelta(minutes=30),
            min_count=3,
        )
        results = correlator.correlate([rule])
        assert len(results) == 0

    def test_temporal_clustering(self):
        correlator = AnomalyCorrelator()
        now = datetime(2024, 1, 1, 12, 0, 0)
        for i in range(5):
            correlator.add_anomaly(Anomaly(
                id=f"a{i}", entity=f"host-{i}", anomaly_type="login_failure",
                severity=Severity.MEDIUM, timestamp=now + timedelta(minutes=i * 3),
            ))
        clusters = correlator.temporal_clusters(
            anomaly_type="login_failure",
            time_window=timedelta(minutes=10),
        )
        assert len(clusters) >= 1
        assert len(clusters[0]) >= 3


# ── Threat actor profiling ────────────────────────────────────────────

class TestActorProfiling:
    def test_build_profile_from_events(self):
        profiler = ActorProfiler()
        events = [
            {"src_ip": "10.0.0.1", "action": "spearphishing", "target": "finance"},
            {"src_ip": "10.0.0.1", "action": "dns tunnel", "target": "finance"},
        ]
        profile = profiler.build_profile(
            actor_id="APT-TEST",
            name="Test Actor",
            events=events,
        )
        assert profile.actor_id == "APT-TEST"
        assert profile.name == "Test Actor"
        assert len(profile.ttps) > 0
        assert profile.confidence > 0.0

    def test_profile_tracks_targeting(self):
        profiler = ActorProfiler()
        events = [
            {"src_ip": "10.0.0.1", "action": "spearphishing", "target": "finance"},
            {"src_ip": "10.0.0.1", "action": "spearphishing", "target": "finance"},
            {"src_ip": "10.0.0.1", "action": "spearphishing", "target": "hr"},
        ]
        profile = profiler.build_profile(
            actor_id="APT-TARGET",
            name="Targeting Actor",
            events=events,
        )
        assert "finance" in profile.targeting
        assert "hr" in profile.targeting
        assert profile.targeting["finance"] == 2

    def test_profile_sophistication_score(self):
        profiler = ActorProfiler()
        events = [
            {"src_ip": "10.0.0.1", "action": "spearphishing"},
            {"src_ip": "10.0.0.1", "action": "dns tunnel"},
            {"src_ip": "10.0.0.1", "action": "privilege escalation"},
            {"src_ip": "10.0.0.1", "action": "lateral movement"},
            {"src_ip": "10.0.0.1", "action": "data exfiltration"},
        ]
        profile = profiler.build_profile(
            actor_id="APT-SOPH",
            name="Sophisticated Actor",
            events=events,
        )
        assert profile.sophistication > 0.0
        assert profile.sophistication <= 1.0

    def test_match_event_to_actor(self):
        profiler = ActorProfiler()
        events = [
            {"src_ip": "10.0.0.1", "action": "spearphishing", "target": "finance"},
        ]
        profile = profiler.build_profile(
            actor_id="APT-MATCH",
            name="Match Actor",
            events=events,
        )
        match = profiler.match_event(
            profile,
            {"src_ip": "10.0.0.1", "action": "spearphishing"},
        )
        assert match is not None
        assert match.actor_id == "APT-MATCH"
        assert match.confidence > 0.0

    def test_match_event_no_match(self):
        profiler = ActorProfiler()
        events = [
            {"src_ip": "10.0.0.1", "action": "spearphishing", "target": "finance"},
        ]
        profile = profiler.build_profile(
            actor_id="APT-NOMATCH",
            name="No Match Actor",
            events=events,
        )
        match = profiler.match_event(
            profile,
            {"src_ip": "192.168.1.1", "action": "normal browsing"},
        )
        assert match is None

    def test_update_profile_with_new_events(self):
        profiler = ActorProfiler()
        events = [
            {"src_ip": "10.0.0.1", "action": "spearphishing", "target": "finance"},
        ]
        profile = profiler.build_profile(
            actor_id="APT-UPDATE",
            name="Update Actor",
            events=events,
        )
        original_ttp_count = len(profile.ttps)
        new_events = [
            {"src_ip": "10.0.0.1", "action": "dns tunnel", "target": "finance"},
        ]
        profiler.update_profile(profile, new_events)
        assert len(profile.ttps) >= original_ttp_count

    def test_profile_first_seen_last_seen(self):
        profiler = ActorProfiler()
        now = datetime(2024, 1, 1, 12, 0, 0)
        events = [
            {"src_ip": "10.0.0.1", "action": "spearphishing", "timestamp": now},
            {"src_ip": "10.0.0.1", "action": "dns tunnel", "timestamp": now + timedelta(hours=2)},
        ]
        profile = profiler.build_profile(
            actor_id="APT-TIME",
            name="Time Actor",
            events=events,
        )
        assert profile.first_seen == now
        assert profile.last_seen == now + timedelta(hours=2)

    def test_profile_with_aliases(self):
        profiler = ActorProfiler()
        events = [
            {"src_ip": "10.0.0.1", "action": "spearphishing"},
        ]
        profile = profiler.build_profile(
            actor_id="APT-ALIAS",
            name="Alias Actor",
            events=events,
            aliases=["Cozy Bear", "APT29"],
        )
        assert "Cozy Bear" in profile.aliases
        assert "APT29" in profile.aliases
