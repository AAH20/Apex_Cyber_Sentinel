"""Adaptive Deception — adaptive honeypots, dynamic decoy generation, engagement analytics."""
from __future__ import annotations

import random
import uuid
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


# ─── Enums ──────────────────────────────────────────────────────────────────

class AdaptationLevel(Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DecoyFormat(Enum):
    CREDENTIAL = "credential"
    FILE = "file"
    SERVICE = "service"
    DATABASE = "database"


class RiskLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# ─── Adaptive Honeypot ─────────────────────────────────────────────────────

@dataclass
class AdaptiveHoneypotConfig:
    adaptation_rate: float = 0.1
    escalation_threshold: int = 5
    de_escalation_threshold: int = 2
    max_adaptation_level: float = 1.0
    history_limit: int = 100


@dataclass
class AdaptiveHoneypot:
    hp_id: str
    hp_type: str
    port: int
    config: AdaptiveHoneypotConfig = field(default_factory=AdaptiveHoneypotConfig)
    status: str = "inactive"
    deployed_at: datetime | None = None
    adaptation_level: float = 0.0
    interaction_count: int = 0
    interaction_history: list[dict[str, Any]] = field(default_factory=list)
    _deployed: bool = False

    def deploy(self) -> None:
        if self._deployed:
            raise RuntimeError(f"Honeypot {self.hp_id} already deployed")
        self.status = "active"
        self.deployed_at = datetime.now()
        self._deployed = True

    def shutdown(self) -> None:
        if not self._deployed:
            raise RuntimeError(f"Honeypot {self.hp_id} not deployed")
        self.status = "inactive"
        self._deployed = False

    def is_listening(self) -> bool:
        return self._deployed

    def record_interaction(self, interaction_type: str, data: dict[str, Any]) -> None:
        if not self._deployed:
            raise RuntimeError(f"Honeypot {self.hp_id} not deployed")
        self.interaction_count += 1
        self.interaction_history.append({
            "type": interaction_type,
            "data": data,
            "timestamp": datetime.now().isoformat(),
        })
        if len(self.interaction_history) > self.config.history_limit:
            self.interaction_history = self.interaction_history[-self.config.history_limit:]
        self._update_adaptation()

    def _update_adaptation(self) -> None:
        self.adaptation_level = min(
            self.adaptation_level + self.config.adaptation_rate,
            self.config.max_adaptation_level,
        )

    def should_escalate(self) -> bool:
        return self.interaction_count >= self.config.escalation_threshold

    def de_escalate(self) -> None:
        self.adaptation_level = max(0.0, self.adaptation_level - self.config.adaptation_rate * 2)

    def get_behavior_profile(self) -> dict[str, Any]:
        types = [i["type"] for i in self.interaction_history]
        users = set()
        for i in self.interaction_history:
            if "user" in i.get("data", {}):
                users.add(i["data"]["user"])
        return {
            "total_interactions": self.interaction_count,
            "unique_users": len(users),
            "interaction_types": dict(Counter(types)),
            "adaptation_level": self.adaptation_level,
        }

    def get_adaptation_score(self) -> float:
        if self.interaction_count == 0:
            return 0.0
        return min(1.0, self.adaptation_level * (self.interaction_count / self.config.escalation_threshold))

    def get_adaptation_level(self) -> AdaptationLevel:
        score = self.get_adaptation_score()
        if score >= 0.8:
            return AdaptationLevel.CRITICAL
        if score >= 0.6:
            return AdaptationLevel.HIGH
        if score >= 0.4:
            return AdaptationLevel.MEDIUM
        if score >= 0.1:
            return AdaptationLevel.LOW
        return AdaptationLevel.NONE


# ─── Dynamic Decoy Generation ──────────────────────────────────────────────

@dataclass
class DecoyTemplate:
    name: str
    decoy_type: str
    format_str: str
    user_pool: list[str] = field(default_factory=list)
    pass_pool: list[str] = field(default_factory=list)


@dataclass
class Decoy:
    decoy_id: str
    decoy_type: DecoyFormat
    content: str
    realism_score: float = 0.5

    def __post_init__(self) -> None:
        if not 0.0 <= self.realism_score <= 1.0:
            raise ValueError(f"realism_score must be between 0.0 and 1.0, got {self.realism_score}")

    def parse_credential(self) -> tuple[str, str]:
        if ":" not in self.content:
            raise ValueError(f"Invalid credential format: {self.content}")
        username, password = self.content.split(":", 1)
        return username, password


class DynamicDecoyGenerator:
    def __init__(self, seed: int | None = None):
        self.rng = random.Random(seed)
        self._decoy_counter = 0
        self._user_pool = ["admin", "root", "guest", "test", "service", "backup", "oracle", "postgres"]
        self._pass_pool = ["password123", "admin", "123456", "P@ssw0rd!", "letmein", "qwerty", "changeme", "secret"]
        self._file_names = ["config.ini", "secrets.txt", "backup.sql", "credentials.json", "id_rsa", "shadow", "passwd", "database.yml"]
        self._service_names = ["ssh", "http", "ftp", "smtp", "mysql", "postgres", "redis", "elasticsearch"]
        self._db_tables = ["users", "customers", "orders", "payments", "sessions", "audit_log", "config", "credentials"]

    def _next_id(self) -> str:
        self._decoy_counter += 1
        return f"decoy-{self._decoy_counter:04d}"

    def _compute_realism(self, content: str) -> float:
        length_factor = min(1.0, len(content) / 50.0)
        variety_factor = len(set(content)) / max(len(content), 1)
        return round(min(1.0, 0.3 + length_factor * 0.4 + variety_factor * 0.3), 2)

    def generate_credential_decoy(self, decoy_id: str | None = None) -> Decoy:
        user = self.rng.choice(self._user_pool)
        password = self.rng.choice(self._pass_pool)
        content = f"{user}:{password}"
        return Decoy(
            decoy_id=decoy_id or self._next_id(),
            decoy_type=DecoyFormat.CREDENTIAL,
            content=content,
            realism_score=self._compute_realism(content),
        )

    def generate_file_decoy(self, decoy_id: str | None = None, filename: str | None = None) -> Decoy:
        fname = filename or self.rng.choice(self._file_names)
        lines = [
            f"# {fname}",
            f"# Generated: {datetime.now().isoformat()}",
            "[database]",
            "host=localhost",
            "port=5432",
            "name=production",
            "user=app_admin",
            "password=Sup3rS3cret!",
            "[api]",
            "key=sk-live-abc123xyz",
            "endpoint=https://api.internal.example.com/v1",
        ]
        content = "\n".join(lines)
        return Decoy(
            decoy_id=decoy_id or self._next_id(),
            decoy_type=DecoyFormat.FILE,
            content=content,
            realism_score=self._compute_realism(content),
        )

    def generate_service_decoy(self, decoy_id: str | None = None, service_name: str | None = None) -> Decoy:
        svc = service_name or self.rng.choice(self._service_names)
        banners = {
            "ssh": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1",
            "http": "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nContent-Type: text/html",
            "ftp": "220 ProFTPD Server (Debian) [::ffff:10.0.0.1]",
            "smtp": "220 mail.example.com ESMTP Postfix",
            "mysql": "5.7.38-log",
            "postgres": "PostgreSQL 14.5 on x86_64-pc-linux-gnu",
            "redis": "-ERR invalid password",
            "elasticsearch": "HTTP/1.1 200 OK\r\nX-Elastic-Product: Elasticsearch",
        }
        content = banners.get(svc, f"220 {svc.upper()} service ready")
        return Decoy(
            decoy_id=decoy_id or self._next_id(),
            decoy_type=DecoyFormat.SERVICE,
            content=content,
            realism_score=self._compute_realism(content),
        )

    def generate_database_decoy(self, decoy_id: str | None = None, table_name: str | None = None) -> Decoy:
        table = table_name or self.rng.choice(self._db_tables)
        rows = []
        for i in range(self.rng.randint(3, 8)):
            uid = self.rng.randint(1000, 9999)
            email = f"user{uid}@example.com"
            password_hash = f"$2b$12${self.rng.getrandbits(128):032x}"
            rows.append(f"({uid}, '{email}', '{password_hash}', NOW())")
        content = f"INSERT INTO {table} (id, email, password_hash, created_at) VALUES\n" + ",\n".join(rows) + ";"
        return Decoy(
            decoy_id=decoy_id or self._next_id(),
            decoy_type=DecoyFormat.DATABASE,
            content=content,
            realism_score=self._compute_realism(content),
        )

    def generate_from_template(self, decoy_id: str, template: DecoyTemplate) -> Decoy:
        user = self.rng.choice(template.user_pool) if template.user_pool else "admin"
        password = self.rng.choice(template.pass_pool) if template.pass_pool else "password123"
        content = template.format_str.format(user=user, **{"pass": password})
        return Decoy(
            decoy_id=decoy_id,
            decoy_type=DecoyFormat(template.decoy_type),
            content=content,
            realism_score=self._compute_realism(content),
        )

    def rotate_decoys(self, old_decoys: list[Decoy], count: int = 5) -> list[Decoy]:
        new_decoys = []
        for _ in range(count):
            decoy_type = self.rng.choice(list(DecoyFormat))
            if decoy_type == DecoyFormat.CREDENTIAL:
                new_decoys.append(self.generate_credential_decoy())
            elif decoy_type == DecoyFormat.FILE:
                new_decoys.append(self.generate_file_decoy())
            elif decoy_type == DecoyFormat.SERVICE:
                new_decoys.append(self.generate_service_decoy())
            else:
                new_decoys.append(self.generate_database_decoy())
        return new_decoys


# ─── Attacker Engagement Analytics ─────────────────────────────────────────

@dataclass
class EngagementRecord:
    session_id: str
    source_ip: str
    honeypot_id: str
    start_time: datetime
    interactions: list[dict[str, Any]] = field(default_factory=list)
    iocs: list[str] = field(default_factory=list)
    end_time: datetime | None = None
    active: bool = True

    @property
    def interaction_count(self) -> int:
        return len(self.interactions)

    @property
    def duration_seconds(self) -> float:
        end = self.end_time or datetime.now()
        return (end - self.start_time).total_seconds()


class EngagementAnalytics:
    def __init__(self):
        self.engagements: list[EngagementRecord] = []

    def record_engagement(self, engagement: EngagementRecord) -> None:
        self.engagements.append(engagement)

    def get_engagement_trends(self) -> dict[str, Any]:
        total = len(self.engagements)
        total_interactions = sum(e.interaction_count for e in self.engagements)
        return {
            "total_engagements": total,
            "total_interactions": total_interactions,
            "avg_interactions_per_session": round(total_interactions / total, 2) if total > 0 else 0.0,
        }

    def get_top_attackers(self, n: int = 5) -> list[dict[str, Any]]:
        ip_stats: dict[str, dict[str, Any]] = {}
        for eng in self.engagements:
            ip = eng.source_ip
            if ip not in ip_stats:
                ip_stats[ip] = {"source_ip": ip, "interaction_count": 0, "session_count": 0}
            ip_stats[ip]["interaction_count"] += eng.interaction_count
            ip_stats[ip]["session_count"] += 1
        sorted_ips = sorted(ip_stats.values(), key=lambda x: x["interaction_count"], reverse=True)
        return sorted_ips[:n]

    def get_honeypot_effectiveness(self) -> dict[str, dict[str, Any]]:
        hp_stats: dict[str, dict[str, Any]] = {}
        for eng in self.engagements:
            hp_id = eng.honeypot_id
            if hp_id not in hp_stats:
                hp_stats[hp_id] = {"engagement_count": 0, "total_interactions": 0, "unique_ips": set()}
            hp_stats[hp_id]["engagement_count"] += 1
            hp_stats[hp_id]["total_interactions"] += eng.interaction_count
            hp_stats[hp_id]["unique_ips"].add(eng.source_ip)
        result = {}
        for hp_id, stats in hp_stats.items():
            result[hp_id] = {
                "engagement_count": stats["engagement_count"],
                "total_interactions": stats["total_interactions"],
                "unique_ips": len(stats["unique_ips"]),
            }
        return result

    def get_temporal_patterns(self) -> dict[str, Any]:
        hourly: dict[int, int] = defaultdict(int)
        for eng in self.engagements:
            hour = eng.start_time.hour
            hourly[hour] += 1
        return {
            "hourly_distribution": dict(sorted(hourly.items())),
            "peak_hour": max(hourly, key=hourly.get) if hourly else None,
        }

    def get_attack_vectors(self) -> dict[str, int]:
        vectors: dict[str, int] = defaultdict(int)
        for eng in self.engagements:
            for interaction in eng.interactions:
                itype = interaction.get("type", "unknown")
                vectors[itype] += 1
        return dict(vectors)

    def get_risk_score(self, session_id: str) -> float:
        eng = next((e for e in self.engagements if e.session_id == session_id), None)
        if eng is None:
            return 0.0
        score = min(1.0, eng.interaction_count / 20.0)
        if eng.iocs:
            score = min(1.0, score + 0.2)
        return round(score, 2)

    def get_risk_level(self, session_id: str) -> RiskLevel:
        score = self.get_risk_score(session_id)
        if score >= 0.8:
            return RiskLevel.CRITICAL
        if score >= 0.5:
            return RiskLevel.HIGH
        if score >= 0.2:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW

    def generate_analytics_report(self) -> dict[str, Any]:
        total = len(self.engagements)
        total_interactions = sum(e.interaction_count for e in self.engagements)
        unique_ips = len({e.source_ip for e in self.engagements})
        return {
            "total_engagements": total,
            "total_interactions": total_interactions,
            "unique_ips": unique_ips,
            "attack_vectors": self.get_attack_vectors(),
            "temporal_patterns": self.get_temporal_patterns(),
            "generated_at": datetime.now().isoformat(),
        }

    def get_retention_rate(self) -> float:
        if not self.engagements:
            return 0.0
        multi_interaction = sum(1 for e in self.engagements if e.interaction_count > 1)
        return round(multi_interaction / len(self.engagements), 2)

    def get_conversion_funnel(self) -> dict[str, int]:
        funnel: dict[str, int] = defaultdict(int)
        for eng in self.engagements:
            for interaction in eng.interactions:
                itype = interaction.get("type", "unknown")
                funnel[itype] += 1
        return dict(funnel)

    def get_all_iocs(self) -> list[str]:
        all_iocs: list[str] = []
        for eng in self.engagements:
            all_iocs.extend(eng.iocs)
        return list(set(all_iocs))

    def get_duration_stats(self) -> dict[str, Any]:
        durations = [e.duration_seconds for e in self.engagements]
        if not durations:
            return {"count": 0, "mean": 0.0, "min": 0.0, "max": 0.0}
        return {
            "count": len(durations),
            "mean": round(sum(durations) / len(durations), 2),
            "min": round(min(durations), 2),
            "max": round(max(durations), 2),
        }
