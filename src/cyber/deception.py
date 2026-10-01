"""Deception Grid — honeypots, decoys, attacker engagement, intelligence collection."""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


# ─── Enums ──────────────────────────────────────────────────────────────────

class HoneypotStatus(Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"


class DecoyType(Enum):
    CREDENTIAL = "credential"
    FILE = "file"
    SERVICE = "service"
    DATABASE = "database"


class EngagementLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class IOCType(Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    FILE_HASH = "file_hash"
    EMAIL = "email"


# ─── Honeypot ───────────────────────────────────────────────────────────────

@dataclass
class Honeypot:
    hp_id: str
    hp_type: str
    port: int
    status: HoneypotStatus = HoneypotStatus.INACTIVE
    deployed_at: datetime | None = None

    def deploy(self) -> None:
        if self.status == HoneypotStatus.ACTIVE:
            raise RuntimeError(f"Honeypot {self.hp_id} already deployed")
        self.status = HoneypotStatus.ACTIVE
        self.deployed_at = datetime.now()

    def shutdown(self) -> None:
        if self.status != HoneypotStatus.ACTIVE:
            raise RuntimeError(f"Honeypot {self.hp_id} not deployed")
        self.status = HoneypotStatus.INACTIVE

    def is_listening(self) -> bool:
        return self.status == HoneypotStatus.ACTIVE


# ─── Decoy ──────────────────────────────────────────────────────────────────

@dataclass
class Decoy:
    decoy_id: str
    decoy_type: DecoyType
    content: str
    realism_score: float = 0.5

    def __post_init__(self) -> None:
        if not 0.0 <= self.realism_score <= 1.0:
            raise ValueError(f"realism_score must be between 0.0 and 1.0, got {self.realism_score}")

    def is_credential(self) -> bool:
        return self.decoy_type == DecoyType.CREDENTIAL

    def parse_credential(self) -> tuple[str, str]:
        if ":" not in self.content:
            raise ValueError(f"Invalid credential format: {self.content}")
        username, password = self.content.split(":", 1)
        return username, password


# ─── Attacker Engagement ────────────────────────────────────────────────────

@dataclass
class AttackerEngagement:
    session_id: str
    source_ip: str
    honeypot_id: str
    start_time: datetime
    interactions: list[dict[str, Any]] = field(default_factory=list)
    active: bool = True

    @property
    def interaction_count(self) -> int:
        return len(self.interactions)

    def log_interaction(self, interaction_type: str, data: dict[str, Any]) -> None:
        self.interactions.append({
            "type": interaction_type,
            "data": data,
            "timestamp": datetime.now().isoformat(),
        })

    def get_engagement_level(self) -> EngagementLevel:
        count = self.interaction_count
        if count >= 15:
            return EngagementLevel.HIGH
        if count >= 5:
            return EngagementLevel.MEDIUM
        return EngagementLevel.LOW

    def get_duration(self, end_time: datetime) -> int:
        return int((end_time - self.start_time).total_seconds())

    def is_active(self) -> bool:
        return self.active

    def close(self) -> None:
        self.active = False


# ─── Intelligence Collector ─────────────────────────────────────────────────

@dataclass
class IntelligenceCollector:
    iocs: list[dict[str, Any]] = field(default_factory=list)
    threat_actors: list[dict[str, Any]] = field(default_factory=list)

    def add_ioc(self, ioc_type: IOCType, value: str, session_id: str, context: dict[str, Any] | None = None) -> None:
        self.iocs.append({
            "type": ioc_type,
            "value": value,
            "session_id": session_id,
            "context": context or {},
            "collected_at": datetime.now().isoformat(),
        })

    def get_iocs_by_type(self, ioc_type: IOCType) -> list[dict[str, Any]]:
        return [ioc for ioc in self.iocs if ioc["type"] == ioc_type]

    def get_iocs_by_session(self, session_id: str) -> list[dict[str, Any]]:
        return [ioc for ioc in self.iocs if ioc["session_id"] == session_id]

    def add_threat_actor(self, name: str, iocs: list[str]) -> None:
        self.threat_actors.append({
            "name": name,
            "iocs": iocs,
            "first_seen": datetime.now().isoformat(),
        })

    def generate_report(self) -> dict[str, Any]:
        return {
            "total_iocs": len(self.iocs),
            "total_threat_actors": len(self.threat_actors),
            "generated_at": datetime.now().isoformat(),
        }


# ─── Deception Grid ─────────────────────────────────────────────────────────

@dataclass
class DeceptionGrid:
    honeypots: list[Honeypot] = field(default_factory=list)
    decoys: list[Decoy] = field(default_factory=list)
    engagements: list[AttackerEngagement] = field(default_factory=list)

    def add_honeypot(self, honeypot: Honeypot) -> None:
        self.honeypots.append(honeypot)

    def add_decoy(self, decoy: Decoy) -> None:
        self.decoys.append(decoy)

    def add_engagement(self, engagement: AttackerEngagement) -> None:
        self.engagements.append(engagement)

    def deploy_all(self) -> None:
        for hp in self.honeypots:
            if hp.status != HoneypotStatus.ACTIVE:
                hp.deploy()

    def shutdown_all(self) -> None:
        for hp in self.honeypots:
            if hp.status == HoneypotStatus.ACTIVE:
                hp.shutdown()

    def get_active_honeypots(self) -> list[Honeypot]:
        return [hp for hp in self.honeypots if hp.status == HoneypotStatus.ACTIVE]

    def get_engagement_metrics(self) -> dict[str, Any]:
        unique_ips = len({eng.source_ip for eng in self.engagements})
        total_interactions = sum(eng.interaction_count for eng in self.engagements)
        return {
            "total_engagements": len(self.engagements),
            "total_interactions": total_interactions,
            "unique_ips": unique_ips,
        }

    def generate_alert(self, engagement: AttackerEngagement) -> dict[str, Any]:
        count = engagement.interaction_count
        if count >= 2:
            severity = "HIGH"
        elif count >= 1:
            severity = "MEDIUM"
        else:
            severity = "LOW"
        return {
            "severity": severity,
            "source_ip": engagement.source_ip,
            "session_id": engagement.session_id,
            "honeypot_id": engagement.honeypot_id,
            "interaction_count": count,
            "timestamp": datetime.now().isoformat(),
        }


# ─── Convenience Functions ──────────────────────────────────────────────────

def deploy_honeypot(hp_id: str, hp_type: str, port: int) -> Honeypot:
    hp = Honeypot(hp_id=hp_id, hp_type=hp_type, port=port)
    hp.deploy()
    return hp


def generate_decoy(decoy_id: str, decoy_type: DecoyType, content: str) -> Decoy:
    return Decoy(decoy_id=decoy_id, decoy_type=decoy_type, content=content)


def engage_attacker(session_id: str, source_ip: str, honeypot_id: str) -> AttackerEngagement:
    return AttackerEngagement(
        session_id=session_id,
        source_ip=source_ip,
        honeypot_id=honeypot_id,
        start_time=datetime.now(),
    )


def collect_intelligence(session_id: str, iocs: list[dict[str, Any]]) -> IntelligenceCollector:
    collector = IntelligenceCollector()
    for ioc in iocs:
        collector.add_ioc(ioc["type"], ioc["value"], session_id)
    return collector
