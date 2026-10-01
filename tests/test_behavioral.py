"""Tests for behavioral grammar — pattern learning, anomaly detection, zero-day ID."""

import time
import pytest
from src.cyber.behavioral import (
    EventType,
    Event,
    BehavioralPattern,
    AnomalyScore,
    ZeroDayThreat,
    BehavioralGrammar,
)


class TestEvent:
    def test_event_creation(self):
        event = Event(EventType.PROCESS, "nginx", time.time())
        assert event.event_type == EventType.PROCESS
        assert event.name == "nginx"
        assert event.timestamp > 0

    def test_event_with_metadata(self):
        event = Event(EventType.NETWORK, "192.168.1.1", time.time(), {"port": 443})
        assert event.metadata == {"port": 443}

    def test_event_default_metadata(self):
        event = Event(EventType.FILE, "/etc/passwd", time.time())
        assert event.metadata == {}

    def test_event_type_enum_values(self):
        assert EventType.PROCESS.value == "process"
        assert EventType.NETWORK.value == "network"
        assert EventType.FILE.value == "file"
        assert EventType.REGISTRY.value == "registry"
        assert EventType.MEMORY.value == "memory"


class TestBehavioralPattern:
    def test_pattern_creation(self):
        pattern = BehavioralPattern(
            pattern_id="p1",
            event_sequence=(EventType.PROCESS, EventType.NETWORK),
            frequency=10,
            confidence=0.9,
            first_seen=100.0,
            last_seen=200.0,
        )
        assert pattern.pattern_id == "p1"
        assert pattern.frequency == 10
        assert pattern.confidence == 0.9
        assert pattern.first_seen == 100.0
        assert pattern.last_seen == 200.0


class TestBehavioralGrammarLearning:
    def test_learn_empty_events(self):
        grammar = BehavioralGrammar()
        grammar.learn([])
        assert grammar.get_patterns() == {}

    def test_learn_single_event(self):
        grammar = BehavioralGrammar()
        events = [Event(EventType.PROCESS, "nginx", time.time())]
        grammar.learn(events)
        patterns = grammar.get_patterns()
        assert len(patterns) > 0

    def test_learn_creates_ngram_patterns(self):
        grammar = BehavioralGrammar()
        events = [
            Event(EventType.PROCESS, "nginx", 1.0),
            Event(EventType.NETWORK, "10.0.0.1", 2.0),
            Event(EventType.FILE, "/var/log", 3.0),
        ]
        grammar.learn(events)
        patterns = grammar.get_patterns()
        assert len(patterns) >= 2

    def test_pattern_frequency_increments(self):
        grammar = BehavioralGrammar()
        events = [
            Event(EventType.PROCESS, "nginx", 1.0),
            Event(EventType.NETWORK, "10.0.0.1", 2.0),
        ]
        grammar.learn(events)
        grammar.learn(events)
        patterns = grammar.get_patterns()
        assert any(p.frequency >= 2 for p in patterns.values())

    def test_pattern_confidence_increases_with_frequency(self):
        grammar = BehavioralGrammar()
        events = [
            Event(EventType.PROCESS, "nginx", 1.0),
            Event(EventType.NETWORK, "10.0.0.1", 2.0),
        ]
        grammar.learn(events)
        patterns1 = grammar.get_patterns()
        conf1 = max(p.confidence for p in patterns1.values())

        for _ in range(10):
            grammar.learn(events)
        patterns2 = grammar.get_patterns()
        conf2 = max(p.confidence for p in patterns2.values())
        assert conf2 > conf1

    def test_learn_multiple_distinct_patterns(self):
        grammar = BehavioralGrammar()
        events = [
            Event(EventType.PROCESS, "nginx", 1.0),
            Event(EventType.NETWORK, "10.0.0.1", 2.0),
            Event(EventType.FILE, "/etc/passwd", 3.0),
            Event(EventType.REGISTRY, "HKLM\\Run", 4.0),
        ]
        grammar.learn(events)
        patterns = grammar.get_patterns()
        assert len(patterns) >= 3

    def test_grammar_with_custom_ngram_sizes(self):
        grammar = BehavioralGrammar(ngram_sizes=(2,))
        events = [
            Event(EventType.PROCESS, "nginx", 1.0),
            Event(EventType.NETWORK, "10.0.0.1", 2.0),
        ]
        grammar.learn(events)
        patterns = grammar.get_patterns()
        # With ngram_sizes=(2,), only bigrams are created
        assert all(len(p.event_sequence) == 2 for p in patterns.values())


class TestAnomalyDetection:
    def test_normal_event_low_score(self):
        grammar = BehavioralGrammar()
        events = [Event(EventType.PROCESS, "nginx", float(i)) for i in range(20)]
        grammar.learn(events)
        score = grammar.detect_anomalies([Event(EventType.PROCESS, "nginx", 100.0)])
        assert len(score) == 1
        assert score[0].score < 0.5

    def test_anomalous_event_high_score(self):
        grammar = BehavioralGrammar()
        events = [Event(EventType.PROCESS, "nginx", float(i)) for i in range(20)]
        grammar.learn(events)
        score = grammar.detect_anomalies([Event(EventType.PROCESS, "unknown_malware", 100.0)])
        assert len(score) == 1
        assert score[0].score > 0.5

    def test_unknown_event_type_high_score(self):
        grammar = BehavioralGrammar()
        events = [Event(EventType.PROCESS, "nginx", float(i)) for i in range(20)]
        grammar.learn(events)
        score = grammar.detect_anomalies([Event(EventType.MEMORY, "0xdeadbeef", 100.0)])
        assert score[0].score > 0.5

    def test_anomaly_score_bounds(self):
        grammar = BehavioralGrammar()
        events = [Event(EventType.PROCESS, "nginx", float(i)) for i in range(10)]
        grammar.learn(events)
        scores = grammar.detect_anomalies([
            Event(EventType.PROCESS, "nginx", 100.0),
            Event(EventType.PROCESS, "evil", 101.0),
        ])
        for s in scores:
            assert 0.0 <= s.score <= 1.0

    def test_detect_empty_events(self):
        grammar = BehavioralGrammar()
        grammar.learn([Event(EventType.PROCESS, "nginx", 1.0)])
        scores = grammar.detect_anomalies([])
        assert scores == []

    def test_anomaly_reason_present(self):
        grammar = BehavioralGrammar()
        events = [Event(EventType.PROCESS, "nginx", float(i)) for i in range(10)]
        grammar.learn(events)
        scores = grammar.detect_anomalies([Event(EventType.PROCESS, "evil", 100.0)])
        assert scores[0].reason != ""

    def test_no_training_data_high_score(self):
        grammar = BehavioralGrammar()
        scores = grammar.detect_anomalies([Event(EventType.PROCESS, "nginx", 1.0)])
        assert scores[0].score == 1.0
        assert "no training data" in scores[0].reason


class TestZeroDayThreats:
    def test_no_threats_for_normal_behavior(self):
        grammar = BehavioralGrammar()
        events = [Event(EventType.PROCESS, "nginx", float(i)) for i in range(20)]
        grammar.learn(events)
        threats = grammar.identify_zero_day_threats(events)
        assert threats == []

    def test_threats_for_anomalous_behavior(self):
        grammar = BehavioralGrammar()
        normal_events = [Event(EventType.PROCESS, "nginx", float(i)) for i in range(20)]
        grammar.learn(normal_events)

        anomalous_events = [
            Event(EventType.PROCESS, "evil_proc", 100.0),
            Event(EventType.NETWORK, "10.0.0.99", 101.0),
            Event(EventType.FILE, "/etc/shadow", 102.0),
            Event(EventType.REGISTRY, "HKLM\\Run\\evil", 103.0),
        ]
        threats = grammar.identify_zero_day_threats(anomalous_events)
        assert len(threats) > 0

    def test_threat_has_confidence(self):
        grammar = BehavioralGrammar()
        normal_events = [Event(EventType.PROCESS, "nginx", float(i)) for i in range(20)]
        grammar.learn(normal_events)

        anomalous_events = [
            Event(EventType.PROCESS, "evil_proc", 100.0),
            Event(EventType.NETWORK, "10.0.0.99", 101.0),
            Event(EventType.FILE, "/etc/shadow", 102.0),
        ]
        threats = grammar.identify_zero_day_threats(anomalous_events)
        for t in threats:
            assert 0.0 <= t.confidence <= 1.0

    def test_threat_has_description(self):
        grammar = BehavioralGrammar()
        normal_events = [Event(EventType.PROCESS, "nginx", float(i)) for i in range(20)]
        grammar.learn(normal_events)

        anomalous_events = [
            Event(EventType.PROCESS, "evil_proc", 100.0),
            Event(EventType.NETWORK, "10.0.0.99", 101.0),
        ]
        threats = grammar.identify_zero_day_threats(anomalous_events)
        for t in threats:
            assert t.description != ""

    def test_threat_contains_anomalous_events(self):
        grammar = BehavioralGrammar()
        normal_events = [Event(EventType.PROCESS, "nginx", float(i)) for i in range(20)]
        grammar.learn(normal_events)

        anomalous_events = [
            Event(EventType.PROCESS, "evil_proc", 100.0),
            Event(EventType.NETWORK, "10.0.0.99", 101.0),
        ]
        threats = grammar.identify_zero_day_threats(anomalous_events)
        for t in threats:
            assert len(t.events) > 0

    def test_multiple_threats_identified(self):
        grammar = BehavioralGrammar()
        normal_events = [Event(EventType.PROCESS, "nginx", float(i)) for i in range(20)]
        grammar.learn(normal_events)

        # Two separate clusters of anomalous events
        cluster1 = [
            Event(EventType.PROCESS, "evil1", 100.0),
            Event(EventType.NETWORK, "10.0.0.99", 101.0),
        ]
        cluster2 = [
            Event(EventType.PROCESS, "evil2", 500.0),
            Event(EventType.FILE, "/etc/shadow", 501.0),
        ]
        threats = grammar.identify_zero_day_threats(cluster1 + cluster2)
        assert len(threats) >= 2


class TestGrammarState:
    def test_reset_clears_patterns(self):
        grammar = BehavioralGrammar()
        events = [Event(EventType.PROCESS, "nginx", 1.0)]
        grammar.learn(events)
        assert len(grammar.get_patterns()) > 0
        grammar.reset()
        assert grammar.get_patterns() == {}

    def test_reset_clears_event_history(self):
        grammar = BehavioralGrammar()
        events = [Event(EventType.PROCESS, "nginx", 1.0)]
        grammar.learn(events)
        grammar.reset()
        scores = grammar.detect_anomalies(events)
        assert scores[0].score > 0.5

    def test_get_patterns_returns_copy(self):
        grammar = BehavioralGrammar()
        events = [Event(EventType.PROCESS, "nginx", 1.0)]
        grammar.learn(events)
        patterns = grammar.get_patterns()
        patterns.clear()
        assert len(grammar.get_patterns()) > 0


class TestIntegration:
    def test_full_pipeline(self):
        grammar = BehavioralGrammar()
        normal_events = []
        for i in range(50):
            normal_events.append(Event(EventType.PROCESS, "nginx", float(i)))
            normal_events.append(Event(EventType.NETWORK, "10.0.0.1", float(i) + 0.1))
        grammar.learn(normal_events)

        test_events = [
            Event(EventType.PROCESS, "nginx", 100.0),
            Event(EventType.NETWORK, "10.0.0.1", 100.1),
        ]
        scores = grammar.detect_anomalies(test_events)
        assert all(s.score < 0.5 for s in scores)

        zero_day_events = [
            Event(EventType.PROCESS, "unknown_exploit", 200.0),
            Event(EventType.MEMORY, "0xdeadbeef", 201.0),
            Event(EventType.FILE, "/etc/shadow", 202.0),
        ]
        threats = grammar.identify_zero_day_threats(zero_day_events)
        assert len(threats) > 0

    def test_sequential_learning(self):
        grammar = BehavioralGrammar()
        for batch in range(5):
            events = [
                Event(EventType.PROCESS, "nginx", float(batch * 10 + i))
                for i in range(10)
            ]
            grammar.learn(events)
        patterns = grammar.get_patterns()
        assert len(patterns) > 0
        assert all(p.frequency >= 5 for p in patterns.values())
