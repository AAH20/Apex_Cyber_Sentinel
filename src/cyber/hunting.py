"""Autonomous threat hunting: proactive search, IOC matching, TTP detection, hypothesis testing."""

from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


# ── Enums ────────────────────────────────────────────────────────────

class IOCType(Enum):
    IP = "ip"
    DOMAIN = "domain"
    HASH = "hash"
    URL = "url"
    EMAIL = "email"
    UNKNOWN = "unknown"


class Severity(Enum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class HypothesisStatus(Enum):
    OPEN = "open"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"


# ── Data classes ─────────────────────────────────────────────────────

@dataclass
class Indicator:
    value: str
    ioc_type: IOCType
    severity: Severity = Severity.MEDIUM
    description: str = ""
    source: str = ""


@dataclass
class TTP:
    tactic: str
    technique_id: str
    technique_name: str
    event_patterns: List[str] = field(default_factory=list)
    description: str = ""


@dataclass
class Hypothesis:
    description: str
    status: HypothesisStatus = HypothesisStatus.OPEN
    confidence: float = 0.0
    matched_iocs: List[Indicator] = field(default_factory=list)
    matched_ttps: List[TTP] = field(default_factory=list)


@dataclass
class HuntResult:
    hypothesis: Hypothesis
    matched_iocs: List[Indicator]
    matched_ttps: List[TTP]
    findings: List[str] = field(default_factory=list)


# ── IOC classification helpers ──────────────────────────────────────

def is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def is_domain(value: str) -> bool:
    pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    return bool(re.match(pattern, value))


def is_hash(value: str) -> bool:
    return bool(re.match(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$", value))


def is_url(value: str) -> bool:
    return bool(re.match(r"^https?://", value, re.IGNORECASE))


def is_email(value: str) -> bool:
    return bool(re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", value))


def classify_ioc(value: str) -> IOCType:
    if is_ip_address(value):
        return IOCType.IP
    if is_hash(value):
        return IOCType.HASH
    if is_url(value):
        return IOCType.URL
    if is_email(value):
        return IOCType.EMAIL
    if is_domain(value):
        return IOCType.DOMAIN
    return IOCType.UNKNOWN


def normalize_ioc(value: str, ioc_type: IOCType) -> str:
    value = value.strip()
    if ioc_type == IOCType.URL:
        return value.lower().rstrip("/")
    if ioc_type in (IOCType.DOMAIN, IOCType.EMAIL):
        return value.lower()
    if ioc_type == IOCType.HASH:
        return value.lower()
    return value


# ── Risk scoring ─────────────────────────────────────────────────────

def calculate_risk_score(iocs: List[Indicator], ttps: List[TTP]) -> float:
    if not iocs and not ttps:
        return 0.0
    severity_weights = {Severity.LOW: 0.1, Severity.MEDIUM: 0.3, Severity.HIGH: 0.6, Severity.CRITICAL: 1.0}
    ioc_score = sum(severity_weights.get(i.severity, 0.1) for i in iocs)
    ttp_score = len(ttps) * 0.2
    total = ioc_score + ttp_score
    return min(total / 5.0, 1.0)


# ── ThreatHunter ─────────────────────────────────────────────────────

class ThreatHunter:
    def __init__(self) -> None:
        self.iocs: List[Indicator] = []
        self.ttps: List[TTP] = []
        self.hypotheses: List[Hypothesis] = []

    def add_ioc(self, indicator: Indicator) -> None:
        self.iocs.append(indicator)

    def add_ttp(self, ttp: TTP) -> None:
        self.ttps.append(ttp)

    def create_hypothesis(self, description: str) -> Hypothesis:
        h = Hypothesis(description=description)
        self.hypotheses.append(h)
        return h

    def match_ioc(self, value: str, ioc_type: Optional[IOCType] = None) -> List[Indicator]:
        normalized = normalize_ioc(value, ioc_type) if ioc_type else value.strip().lower()
        results = []
        for ioc in self.iocs:
            if ioc_type and ioc.ioc_type != ioc_type:
                continue
            if normalize_ioc(ioc.value, ioc.ioc_type) == normalized:
                results.append(ioc)
        return results

    def detect_ttp(self, event: Dict[str, Any]) -> List[TTP]:
        event_text = " ".join(str(v) for v in event.values()).lower()
        matched = []
        for ttp in self.ttps:
            for pattern in ttp.event_patterns:
                if pattern.lower() in event_text:
                    matched.append(ttp)
                    break
        return matched

    def test_hypothesis(self, hypothesis: Hypothesis, events: List[Dict[str, Any]]) -> HuntResult:
        all_matched_iocs: List[Indicator] = []
        all_matched_ttps: List[TTP] = []
        findings: List[str] = []

        for event in events:
            event_text = " ".join(str(v) for v in event.values())
            for ioc in self.iocs:
                if normalize_ioc(ioc.value, ioc.ioc_type) in event_text.lower():
                    if ioc not in all_matched_iocs:
                        all_matched_iocs.append(ioc)
                        findings.append(f"Matched IOC: {ioc.value} ({ioc.ioc_type.value})")
            for ttp in self.detect_ttp(event):
                if ttp not in all_matched_ttps:
                    all_matched_ttps.append(ttp)
                    findings.append(f"Matched TTP: {ttp.technique_id} - {ttp.technique_name}")

        if all_matched_iocs or all_matched_ttps:
            hypothesis.status = HypothesisStatus.CONFIRMED
            hypothesis.confidence = min(0.3 + 0.2 * len(all_matched_iocs) + 0.15 * len(all_matched_ttps), 1.0)
            hypothesis.matched_iocs = all_matched_iocs
            hypothesis.matched_ttps = all_matched_ttps
        else:
            hypothesis.status = HypothesisStatus.REJECTED
            hypothesis.confidence = 0.0

        return HuntResult(
            hypothesis=hypothesis,
            matched_iocs=all_matched_iocs,
            matched_ttps=all_matched_ttps,
            findings=findings,
        )

    def hunt(self, events: List[Dict[str, Any]]) -> List[HuntResult]:
        if not events:
            return []
        hypotheses = list(self.hypotheses)
        if not hypotheses:
            for ioc in self.iocs:
                hypotheses.append(self.create_hypothesis(f"Investigate IOC: {ioc.value}"))
            for ttp in self.ttps:
                hypotheses.append(self.create_hypothesis(f"Investigate TTP: {ttp.technique_id}"))
        results = []
        for hypothesis in hypotheses:
            result = self.test_hypothesis(hypothesis, events)
            if result.hypothesis.status == HypothesisStatus.CONFIRMED:
                results.append(result)
        return results

    def calculate_risk_score(self, iocs: List[Indicator], ttps: List[TTP]) -> float:
        return calculate_risk_score(iocs, ttps)
