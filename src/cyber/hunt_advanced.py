"""Advanced threat hunting: hypothesis-driven hunting, anomaly correlation, actor profiling."""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set

from src.cyber.hunting import (
    HypothesisStatus,
    IOCType,
    Indicator,
    Severity,
    TTP,
    normalize_ioc,
)


# ── Data classes ─────────────────────────────────────────────────────

@dataclass
class HuntHypothesis:
    description: str
    hypothesis_type: str
    status: str = "open"
    confidence: float = 0.0
    expected_iocs: List[Indicator] = field(default_factory=list)
    expected_ttps: List[TTP] = field(default_factory=list)
    matched_iocs: List[Indicator] = field(default_factory=list)
    matched_ttps: List[TTP] = field(default_factory=list)


@dataclass
class HypothesisEvaluation:
    hypothesis: HuntHypothesis
    status: str
    confidence: float
    matched_iocs: List[Indicator] = field(default_factory=list)
    matched_ttps: List[TTP] = field(default_factory=list)
    findings: List[str] = field(default_factory=list)


@dataclass
class Anomaly:
    id: str
    entity: str
    anomaly_type: str
    severity: Severity
    timestamp: datetime
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CorrelationRule:
    name: str
    anomaly_types: List[str]
    time_window: timedelta
    min_count: int = 2


@dataclass
class CorrelationResult:
    rule_name: str
    anomalies: List[Anomaly]
    entity: str = ""
    confidence: float = 0.0


@dataclass
class ThreatActorProfile:
    actor_id: str
    name: str
    ttps: List[TTP] = field(default_factory=list)
    targeting: Dict[str, int] = field(default_factory=dict)
    iocs: List[Indicator] = field(default_factory=list)
    aliases: List[str] = field(default_factory=list)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    sophistication: float = 0.0
    confidence: float = 0.0


@dataclass
class ActorMatch:
    actor_id: str
    name: str
    confidence: float
    matched_indicators: List[str] = field(default_factory=list)


# ── Hypothesis-driven hunting engine ─────────────────────────────────

class HypothesisEngine:
    def __init__(self) -> None:
        self.iocs: List[Indicator] = []
        self.ttps: List[TTP] = []
        self.hypotheses: List[HuntHypothesis] = []

    def add_ioc(self, indicator: Indicator) -> None:
        self.iocs.append(indicator)

    def add_ttp(self, ttp: TTP) -> None:
        self.ttps.append(ttp)

    def create_hypothesis(
        self,
        description: str,
        hypothesis_type: str,
        expected_iocs: Optional[List[Indicator]] = None,
        expected_ttps: Optional[List[TTP]] = None,
    ) -> HuntHypothesis:
        h = HuntHypothesis(
            description=description,
            hypothesis_type=hypothesis_type,
            expected_iocs=expected_iocs or [],
            expected_ttps=expected_ttps or [],
        )
        self.hypotheses.append(h)
        return h

    def evaluate(
        self,
        hypothesis: HuntHypothesis,
        events: List[Dict[str, Any]],
    ) -> HypothesisEvaluation:
        matched_iocs: List[Indicator] = []
        matched_ttps: List[TTP] = []
        findings: List[str] = []

        for event in events:
            event_text = " ".join(str(v) for v in event.values()).lower()

            for ioc in self.iocs:
                if normalize_ioc(ioc.value, ioc.ioc_type) in event_text:
                    if ioc not in matched_iocs:
                        matched_iocs.append(ioc)
                        findings.append(f"Matched IOC: {ioc.value} ({ioc.ioc_type.value})")

            for ttp in self.ttps:
                for pattern in ttp.event_patterns:
                    if pattern.lower() in event_text:
                        if ttp not in matched_ttps:
                            matched_ttps.append(ttp)
                            findings.append(f"Matched TTP: {ttp.technique_id} - {ttp.technique_name}")
                        break

        if matched_iocs or matched_ttps:
            confidence = min(0.3 + 0.2 * len(matched_iocs) + 0.15 * len(matched_ttps), 1.0)
            status = "confirmed"
        else:
            confidence = 0.0
            status = "rejected"

        hypothesis.status = status
        hypothesis.confidence = confidence
        hypothesis.matched_iocs = matched_iocs
        hypothesis.matched_ttps = matched_ttps

        return HypothesisEvaluation(
            hypothesis=hypothesis,
            status=status,
            confidence=confidence,
            matched_iocs=matched_iocs,
            matched_ttps=matched_ttps,
            findings=findings,
        )

    def rank_hypotheses(self) -> List[HypothesisEvaluation]:
        evaluations = []
        for h in self.hypotheses:
            evaluations.append(HypothesisEvaluation(
                hypothesis=h,
                status=h.status,
                confidence=h.confidence,
                matched_iocs=h.matched_iocs,
                matched_ttps=h.matched_ttps,
            ))
        return sorted(evaluations, key=lambda e: e.confidence, reverse=True)


# ── Anomaly correlation ───────────────────────────────────────────────

class AnomalyCorrelator:
    def __init__(self) -> None:
        self.anomalies: List[Anomaly] = []

    def add_anomaly(self, anomaly: Anomaly) -> None:
        self.anomalies.append(anomaly)

    def correlate(self, rules: List[CorrelationRule]) -> List[CorrelationResult]:
        results: List[CorrelationResult] = []
        for rule in rules:
            # Group anomalies by entity for this rule's types
            by_entity: Dict[str, List[Anomaly]] = defaultdict(list)
            for a in self.anomalies:
                if a.anomaly_type in rule.anomaly_types:
                    by_entity[a.entity].append(a)

            for entity, entity_anomalies in by_entity.items():
                # Sort by timestamp
                entity_anomalies.sort(key=lambda a: a.timestamp)

                # Sliding window: find clusters of >= min_count within time_window
                i = 0
                while i < len(entity_anomalies):
                    window_end = entity_anomalies[i].timestamp + rule.time_window
                    cluster: List[Anomaly] = []
                    j = i
                    while j < len(entity_anomalies) and entity_anomalies[j].timestamp <= window_end:
                        cluster.append(entity_anomalies[j])
                        j += 1

                    if len(cluster) >= rule.min_count:
                        confidence = min(0.3 + 0.15 * len(cluster), 1.0)
                        results.append(CorrelationResult(
                            rule_name=rule.name,
                            anomalies=list(cluster),
                            entity=entity,
                            confidence=confidence,
                        ))
                        i = j  # skip past this cluster
                    else:
                        i += 1

        return results

    def temporal_clusters(
        self,
        anomaly_type: str,
        time_window: timedelta,
    ) -> List[List[Anomaly]]:
        filtered = [a for a in self.anomalies if a.anomaly_type == anomaly_type]
        filtered.sort(key=lambda a: a.timestamp)

        if not filtered:
            return []

        clusters: List[List[Anomaly]] = []
        current: List[Anomaly] = [filtered[0]]

        for a in filtered[1:]:
            if a.timestamp - current[-1].timestamp <= time_window:
                current.append(a)
            else:
                clusters.append(current)
                current = [a]
        clusters.append(current)

        return clusters


# ── Threat actor profiling ────────────────────────────────────────────

# Map event action keywords to TTP technique IDs
_ACTION_TO_TTP: Dict[str, TTP] = {
    "spearphishing": TTP("Initial Access", "T1566", "Phishing", ["spearphishing"]),
    "phishing": TTP("Initial Access", "T1566", "Phishing", ["phishing"]),
    "dns tunnel": TTP("Command and Control", "T1071", "Application Layer Protocol", ["dns tunnel"]),
    "beacon": TTP("Command and Control", "T1071", "Application Layer Protocol", ["beacon"]),
    "privilege escalation": TTP("Privilege Escalation", "T1068", "Exploitation for Privilege Escalation", ["privilege escalation"]),
    "lateral movement": TTP("Lateral Movement", "T1021", "Remote Services", ["lateral movement"]),
    "data exfiltration": TTP("Exfiltration", "T1041", "Exfiltration Over C2 Channel", ["data exfiltration"]),
    "credential dumping": TTP("Credential Access", "T1003", "OS Credential Dumping", ["credential dumping"]),
    "persistence": TTP("Persistence", "T1547", "Boot or Logon Autostart Execution", ["persistence"]),
    "defense evasion": TTP("Defense Evasion", "T1070", "Indicator Removal", ["defense evasion"]),
}

_SOPHISTICATION_WEIGHTS = {
    "T1566": 0.15,   # Phishing
    "T1071": 0.20,   # C2
    "T1068": 0.20,   # Priv esc
    "T1021": 0.15,   # Lateral movement
    "T1041": 0.20,   # Exfiltration
    "T1003": 0.15,   # Credential dumping
    "T1547": 0.10,   # Persistence
    "T1070": 0.15,   # Defense evasion
}


class ActorProfiler:
    def build_profile(
        self,
        actor_id: str,
        name: str,
        events: List[Dict[str, Any]],
        aliases: Optional[List[str]] = None,
    ) -> ThreatActorProfile:
        ttps: List[TTP] = []
        targeting: Dict[str, int] = defaultdict(int)
        iocs: List[Indicator] = []
        timestamps: List[datetime] = []

        for event in events:
            action = event.get("action", "").lower()
            target = event.get("target", "")
            src_ip = event.get("src_ip", "")
            ts = event.get("timestamp")

            if ts and isinstance(ts, datetime):
                timestamps.append(ts)

            # Extract TTPs from action
            for keyword, ttp in _ACTION_TO_TTP.items():
                if keyword in action:
                    if ttp not in ttps:
                        ttps.append(ttp)

            # Track targeting
            if target:
                targeting[target] += 1

            # Extract IOCs
            if src_ip:
                iocs.append(Indicator(src_ip, IOCType.IP, Severity.MEDIUM))

        # Calculate sophistication
        sophistication = self._calculate_sophistication(ttps)

        # Calculate confidence based on evidence volume
        confidence = min(0.2 + 0.1 * len(ttps) + 0.05 * len(events), 1.0)

        first_seen = min(timestamps) if timestamps else None
        last_seen = max(timestamps) if timestamps else None

        return ThreatActorProfile(
            actor_id=actor_id,
            name=name,
            ttps=ttps,
            targeting=dict(targeting),
            iocs=iocs,
            aliases=aliases or [],
            first_seen=first_seen,
            last_seen=last_seen,
            sophistication=sophistication,
            confidence=confidence,
        )

    def update_profile(
        self,
        profile: ThreatActorProfile,
        new_events: List[Dict[str, Any]],
    ) -> None:
        for event in new_events:
            action = event.get("action", "").lower()
            target = event.get("target", "")
            src_ip = event.get("src_ip", "")
            ts = event.get("timestamp")

            if ts and isinstance(ts, datetime):
                if profile.first_seen is None or ts < profile.first_seen:
                    profile.first_seen = ts
                if profile.last_seen is None or ts > profile.last_seen:
                    profile.last_seen = ts

            for keyword, ttp in _ACTION_TO_TTP.items():
                if keyword in action:
                    if ttp not in profile.ttps:
                        profile.ttps.append(ttp)

            if target:
                profile.targeting[target] = profile.targeting.get(target, 0) + 1

            if src_ip:
                existing = [i.value for i in profile.iocs]
                if src_ip not in existing:
                    profile.iocs.append(Indicator(src_ip, IOCType.IP, Severity.MEDIUM))

        profile.sophistication = self._calculate_sophistication(profile.ttps)
        profile.confidence = min(0.2 + 0.1 * len(profile.ttps) + 0.05 * sum(profile.targeting.values()), 1.0)

    def match_event(
        self,
        profile: ThreatActorProfile,
        event: Dict[str, Any],
    ) -> Optional[ActorMatch]:
        action = event.get("action", "").lower()
        src_ip = event.get("src_ip", "")

        matched_indicators: List[str] = []
        match_score = 0.0

        # Check TTP match
        for keyword, ttp in _ACTION_TO_TTP.items():
            if keyword in action and ttp in profile.ttps:
                match_score += 0.4
                matched_indicators.append(f"TTP:{ttp.technique_id}")
                break

        # Check IP match
        if src_ip:
            profile_ips = {i.value for i in profile.iocs if i.ioc_type == IOCType.IP}
            if src_ip in profile_ips:
                match_score += 0.3
                matched_indicators.append(f"IP:{src_ip}")

        # Check targeting match
        target = event.get("target", "")
        if target and target in profile.targeting:
            match_score += 0.3
            matched_indicators.append(f"TARGET:{target}")

        if match_score > 0.0:
            return ActorMatch(
                actor_id=profile.actor_id,
                name=profile.name,
                confidence=min(match_score, 1.0),
                matched_indicators=matched_indicators,
            )
        return None

    def _calculate_sophistication(self, ttps: List[TTP]) -> float:
        if not ttps:
            return 0.0
        total = sum(_SOPHISTICATION_WEIGHTS.get(t.technique_id, 0.05) for t in ttps)
        return min(total, 1.0)
