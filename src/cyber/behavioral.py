"""Behavioral grammar for zero-day detection.

Learns normal behavioral patterns from event streams, detects anomalies,
and identifies potential zero-day threats based on deviation from learned
baselines.
"""

from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple


class EventType(Enum):
    """Types of observable system events."""

    PROCESS = "process"
    NETWORK = "network"
    FILE = "file"
    REGISTRY = "registry"
    MEMORY = "memory"


@dataclass
class Event:
    """A single observable system event."""

    event_type: EventType
    name: str
    timestamp: float
    metadata: Dict[str, str] = field(default_factory=dict)


@dataclass
class BehavioralPattern:
    """A learned behavioral pattern (n-gram of event types)."""

    pattern_id: str
    event_sequence: Tuple[EventType, ...]
    frequency: int
    confidence: float
    first_seen: float
    last_seen: float


@dataclass
class AnomalyScore:
    """Anomaly score for a single event."""

    event: Event
    score: float
    reason: str


@dataclass
class ZeroDayThreat:
    """A potential zero-day threat identified from anomalous behavior."""

    threat_id: str
    description: str
    confidence: float
    events: List[Event]
    timestamp: float


class BehavioralGrammar:
    """Learns behavioral patterns and detects anomalies / zero-day threats.

    Uses n-gram modeling over event type sequences to build a baseline
    of normal behavior. Events that deviate significantly from learned
    patterns are flagged as anomalous. Clusters of anomalous events are
    classified as potential zero-day threats.
    """

    def __init__(self, ngram_sizes: Tuple[int, ...] = (1, 2, 3), anomaly_threshold: float = 0.6):
        self.ngram_sizes = ngram_sizes
        self.anomaly_threshold = anomaly_threshold
        self._patterns: Dict[str, BehavioralPattern] = {}
        self._event_history: List[Event] = []
        self._event_type_counts: Dict[EventType, int] = defaultdict(int)
        self._event_name_counts: Dict[str, int] = defaultdict(int)
        self._total_events: int = 0

    def learn(self, events: List[Event]) -> None:
        """Learn behavioral patterns from a sequence of events."""
        if not events:
            return

        self._event_history.extend(events)
        for event in events:
            self._event_type_counts[event.event_type] += 1
            self._event_name_counts[event.name] += 1
            self._total_events += 1

        for n in self.ngram_sizes:
            self._learn_ngrams(events, n)

    def _learn_ngrams(self, events: List[Event], n: int) -> None:
        """Learn n-gram patterns from events."""
        if len(events) < n:
            return

        for i in range(len(events) - n + 1):
            seq = tuple(e.event_type for e in events[i : i + n])
            pattern_key = self._pattern_key(seq)

            if pattern_key in self._patterns:
                pattern = self._patterns[pattern_key]
                pattern.frequency += 1
                pattern.last_seen = events[i + n - 1].timestamp
                # Confidence increases with frequency (capped at 1.0)
                pattern.confidence = min(1.0, pattern.confidence + 0.1)
            else:
                self._patterns[pattern_key] = BehavioralPattern(
                    pattern_id=pattern_key,
                    event_sequence=seq,
                    frequency=1,
                    confidence=0.1,
                    first_seen=events[i].timestamp,
                    last_seen=events[i + n - 1].timestamp,
                )

    def detect_anomalies(self, events: List[Event]) -> List[AnomalyScore]:
        """Detect anomalous events based on learned patterns.

        Returns a list of AnomalyScore for each input event.
        """
        if not events:
            return []

        if self._total_events == 0:
            return [
                AnomalyScore(
                    event=e,
                    score=1.0,
                    reason="no training data available",
                )
                for e in events
            ]

        scores = []
        for event in events:
            score, reason = self._score_event(event)
            scores.append(AnomalyScore(event=event, score=score, reason=reason))
        return scores

    def _score_event(self, event: Event) -> Tuple[float, str]:
        """Score a single event for anomaly likelihood.

        Returns (score, reason) where score is in [0, 1].
        Unknown event names/types contribute heavily to the score.
        """
        score = 0.0
        reasons = []

        # Check event type frequency
        type_count = self._event_type_counts.get(event.event_type, 0)
        if type_count == 0:
            score += 0.6
            reasons.append(f"unknown event type: {event.event_type.value}")
        else:
            type_freq = type_count / self._total_events
            score += (1.0 - type_freq) * 0.2

        # Check event name frequency (weighted more heavily)
        name_count = self._event_name_counts.get(event.name, 0)
        if name_count == 0:
            score += 0.6
            reasons.append(f"unknown event name: {event.name}")
        else:
            name_freq = name_count / self._total_events
            score += (1.0 - name_freq) * 0.2

        # Check n-gram pattern match
        ngram_score = self._ngram_anomaly_score(event)
        score += ngram_score * 0.2
        if ngram_score > 0.5:
            reasons.append("event does not match learned n-gram patterns")

        final_score = min(1.0, max(0.0, score))
        reason = "; ".join(reasons) if reasons else "event matches learned patterns"
        return final_score, reason

    def _ngram_anomaly_score(self, event: Event) -> float:
        """Check if event fits any learned n-gram pattern."""
        if not self._patterns:
            return 0.5

        # Check if this event type appears in any pattern
        matching_patterns = [
            p for p in self._patterns.values() if event.event_type in p.event_sequence
        ]
        if not matching_patterns:
            return 1.0

        # Score based on confidence of matching patterns
        avg_confidence = sum(p.confidence for p in matching_patterns) / len(matching_patterns)
        return 1.0 - avg_confidence

    def identify_zero_day_threats(self, events: List[Event]) -> List[ZeroDayThreat]:
        """Identify potential zero-day threats from anomalous events.

        Clusters anomalous events and creates threat objects for
        significant deviations from normal behavior.
        """
        if not events:
            return []

        scores = self.detect_anomalies(events)
        anomalous_events = [
            s.event for s in scores if s.score >= self.anomaly_threshold
        ]

        if not anomalous_events:
            return []

        # Cluster anomalous events by proximity in time
        clusters = self._cluster_events(anomalous_events)

        threats = []
        for i, cluster in enumerate(clusters):
            if len(cluster) < 2:
                continue

            avg_score = sum(
                s.score for s in scores if s.event in cluster
            ) / len(cluster)

            threat = ZeroDayThreat(
                threat_id=f"zd-{i}-{int(cluster[0].timestamp)}",
                description=self._describe_threat(cluster),
                confidence=min(1.0, avg_score),
                events=cluster,
                timestamp=cluster[0].timestamp,
            )
            threats.append(threat)

        return threats

    def _cluster_events(
        self, events: List[Event], time_window: float = 10.0
    ) -> List[List[Event]]:
        """Cluster events that occur within a time window of each other."""
        if not events:
            return []

        sorted_events = sorted(events, key=lambda e: e.timestamp)
        clusters = [[sorted_events[0]]]

        for event in sorted_events[1:]:
            if event.timestamp - clusters[-1][-1].timestamp <= time_window:
                clusters[-1].append(event)
            else:
                clusters.append([event])

        return clusters

    def _describe_threat(self, events: List[Event]) -> str:
        """Generate a human-readable description of a threat cluster."""
        event_types = set(e.event_type.value for e in events)
        event_names = [e.name for e in events]
        return (
            f"Anomalous behavior detected: {len(events)} events "
            f"of types {', '.join(sorted(event_types))}: "
            f"{', '.join(event_names[:5])}"
        )

    def get_patterns(self) -> Dict[str, BehavioralPattern]:
        """Return a copy of learned patterns."""
        return dict(self._patterns)

    def reset(self) -> None:
        """Reset all learned state."""
        self._patterns.clear()
        self._event_history.clear()
        self._event_type_counts.clear()
        self._event_name_counts.clear()
        self._total_events = 0

    @staticmethod
    def _pattern_key(sequence: Tuple[EventType, ...]) -> str:
        """Generate a unique key for an event type sequence."""
        return "-".join(e.value for e in sequence)
