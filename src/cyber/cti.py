"""Cyber Threat Intelligence (CTI) Module.

Provides IOC ingestion, TTP mapping, threat actor tracking,
and intelligence sharing via STIX/TAXII standards.
"""

import csv
import hashlib
import io
import json
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class IOCType(Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    FILE_HASH_MD5 = "file_hash_md5"
    FILE_HASH_SHA1 = "file_hash_sha1"
    FILE_HASH_SHA256 = "file_hash_sha256"
    EMAIL = "email"
    CVE = "cve"
    MUTEX = "mutex"
    REGISTRY = "registry"
    YARA_RULE = "yara_rule"
    UNKNOWN = "unknown"


class TLP(Enum):
    WHITE = "white"
    GREEN = "green"
    AMBER = "amber"
    RED = "red"


class Confidence(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Severity(Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# ---------------------------------------------------------------------------
# IOC
# ---------------------------------------------------------------------------

@dataclass
class IOC:
    """Indicator of Compromise."""
    value: str
    type: IOCType
    confidence: Confidence = Confidence.MEDIUM
    severity: Severity = Severity.MEDIUM
    source: str = "unknown"
    tags: List[str] = field(default_factory=list)
    description: str = ""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def normalize(self) -> str:
        """Normalize the IOC value (lowercase, strip whitespace)."""
        return self.value.strip().lower()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "value": self.value,
            "type": self.type.value,
            "confidence": self.confidence.value,
            "severity": self.severity.value,
            "source": self.source,
            "tags": self.tags,
            "description": self.description,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "IOC":
        return cls(
            id=data.get("id", str(uuid.uuid4())),
            value=data["value"],
            type=IOCType(data.get("type", "unknown")),
            confidence=Confidence(data.get("confidence", "medium")),
            severity=Severity(data.get("severity", "medium")),
            source=data.get("source", "unknown"),
            tags=data.get("tags", []),
            description=data.get("description", ""),
            created_at=data.get("created_at", datetime.now(timezone.utc).isoformat()),
            updated_at=data.get("updated_at", datetime.now(timezone.utc).isoformat()),
        )


# ---------------------------------------------------------------------------
# IOC Validator
# ---------------------------------------------------------------------------

class IOCValidator:
    """Validates and auto-detects IOC types."""

    _IPV4_RE = re.compile(
        r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
    )
    _IPV6_RE = re.compile(
        r"^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|"
        r"^(?:[0-9a-fA-F]{1,4}:){1,7}:$|"
        r"^(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}$|"
        r"^(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}$|"
        r"^(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}$|"
        r"^(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}$|"
        r"^(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}$|"
        r"^[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}$|"
        r"^::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}$|"
        r"^::$"
    )
    _DOMAIN_RE = re.compile(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    )
    _URL_RE = re.compile(
        r"^https?://[^\s/$.?#].[^\s]*$", re.IGNORECASE
    )
    _MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")
    _SHA1_RE = re.compile(r"^[a-fA-F0-9]{40}$")
    _SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
    _EMAIL_RE = re.compile(
        r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    )
    _CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

    @classmethod
    def validate(cls, value: str, ioc_type: IOCType) -> bool:
        """Validate an IOC value against its type."""
        if not value or not value.strip():
            return False
        v = value.strip()
        if ioc_type == IOCType.IP:
            return bool(cls._IPV4_RE.match(v)) or bool(cls._IPV6_RE.match(v))
        elif ioc_type == IOCType.DOMAIN:
            return bool(cls._DOMAIN_RE.match(v))
        elif ioc_type == IOCType.URL:
            return bool(cls._URL_RE.match(v))
        elif ioc_type == IOCType.FILE_HASH_MD5:
            return bool(cls._MD5_RE.match(v))
        elif ioc_type == IOCType.FILE_HASH_SHA1:
            return bool(cls._SHA1_RE.match(v))
        elif ioc_type == IOCType.FILE_HASH_SHA256:
            return bool(cls._SHA256_RE.match(v))
        elif ioc_type == IOCType.EMAIL:
            return bool(cls._EMAIL_RE.match(v))
        elif ioc_type == IOCType.CVE:
            return bool(cls._CVE_RE.match(v))
        return True

    @classmethod
    def detect_type(cls, value: str) -> Optional[IOCType]:
        """Auto-detect the IOC type from a value."""
        if not value or not value.strip():
            return None
        v = value.strip()
        if cls._IPV4_RE.match(v) or cls._IPV6_RE.match(v):
            return IOCType.IP
        if cls._URL_RE.match(v):
            return IOCType.URL
        if cls._DOMAIN_RE.match(v):
            return IOCType.DOMAIN
        if cls._MD5_RE.match(v):
            return IOCType.FILE_HASH_MD5
        if cls._SHA1_RE.match(v):
            return IOCType.FILE_HASH_SHA1
        if cls._SHA256_RE.match(v):
            return IOCType.FILE_HASH_SHA256
        if cls._EMAIL_RE.match(v):
            return IOCType.EMAIL
        if cls._CVE_RE.match(v):
            return IOCType.CVE
        return None


# ---------------------------------------------------------------------------
# IOC Feed
# ---------------------------------------------------------------------------

class IOCFeed:
    """Ingest and manage IOCs from various sources."""

    def __init__(self):
        self._iocs: Dict[str, IOC] = {}

    def add(self, ioc: IOC) -> bool:
        """Add an IOC. Returns True if new, False if updated existing."""
        key = ioc.normalize()
        if key in self._iocs:
            existing = self._iocs[key]
            existing.source = ioc.source
            existing.updated_at = datetime.now(timezone.utc).isoformat()
            if ioc.tags:
                existing.tags = list(set(existing.tags + ioc.tags))
            return False
        self._iocs[key] = ioc
        return True

    def get(self, value: str) -> Optional[IOC]:
        return self._iocs.get(value.strip().lower())

    def remove(self, value: str) -> bool:
        key = value.strip().lower()
        if key in self._iocs:
            del self._iocs[key]
            return True
        return False

    def all(self) -> List[IOC]:
        return list(self._iocs.values())

    def search(
        self,
        ioc_type: Optional[IOCType] = None,
        tag: Optional[str] = None,
        source: Optional[str] = None,
    ) -> List[IOC]:
        results = list(self._iocs.values())
        if ioc_type:
            results = [i for i in results if i.type == ioc_type]
        if tag:
            results = [i for i in results if tag in i.tags]
        if source:
            results = [i for i in results if i.source == source]
        return results

    def ingest_json(self, data: str) -> int:
        """Ingest IOCs from a JSON array. Returns count of new IOCs."""
        items = json.loads(data)
        count = 0
        for item in items:
            try:
                ioc_type = IOCType(item.get("type", "unknown"))
                value = item.get("value", "")
                if not value:
                    continue
                if ioc_type != IOCType.UNKNOWN and not IOCValidator.validate(value, ioc_type):
                    continue
                ioc = IOC.from_dict({**item, "type": ioc_type.value})
                if self.add(ioc):
                    count += 1
            except (ValueError, KeyError):
                continue
        return count

    def ingest_csv(self, data: str) -> int:
        """Ingest IOCs from CSV. Returns count of new IOCs."""
        reader = csv.DictReader(io.StringIO(data))
        count = 0
        for row in reader:
            try:
                value = row.get("value", "").strip()
                type_str = row.get("type", "unknown").strip()
                if not value:
                    continue
                ioc_type = IOCType(type_str)
                if ioc_type != IOCType.UNKNOWN and not IOCValidator.validate(value, ioc_type):
                    continue
                ioc = IOC(
                    value=value,
                    type=ioc_type,
                    source=row.get("source", "csv"),
                    tags=[t.strip() for t in row.get("tags", "").split(";") if t.strip()],
                )
                if self.add(ioc):
                    count += 1
            except (ValueError, KeyError):
                continue
        return count

    def ingest_text(self, text: str) -> int:
        """Ingest IOCs from plain text (auto-detect types). Returns count."""
        count = 0
        for line in text.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            detected = IOCValidator.detect_type(line)
            if detected is None:
                continue
            ioc = IOC(value=line, type=detected, source="text")
            if self.add(ioc):
                count += 1
        return count

    def __len__(self) -> int:
        return len(self._iocs)


# ---------------------------------------------------------------------------
# TTP
# ---------------------------------------------------------------------------

@dataclass
class TTP:
    """Tactics, Techniques, and Procedures (MITRE ATT&CK)."""
    technique_id: str
    tactic: str
    name: str
    description: str = ""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "technique_id": self.technique_id,
            "tactic": self.tactic,
            "name": self.name,
            "description": self.description,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TTP":
        return cls(
            id=data.get("id", str(uuid.uuid4())),
            technique_id=data["technique_id"],
            tactic=data.get("tactic", ""),
            name=data.get("name", ""),
            description=data.get("description", ""),
            created_at=data.get("created_at", datetime.now(timezone.utc).isoformat()),
        )


class TTPMapper:
    """Maps IOCs and actors to TTPs."""

    def __init__(self):
        self._ttps: Dict[str, TTP] = {}
        self._ioc_to_ttp: Dict[str, Set[str]] = {}
        self._actor_to_ttp: Dict[str, Set[str]] = {}

    def add_ttp(self, ttp: TTP) -> None:
        self._ttps[ttp.technique_id] = ttp

    def get_ttp(self, technique_id: str) -> Optional[TTP]:
        return self._ttps.get(technique_id)

    def all_ttps(self) -> List[TTP]:
        return list(self._ttps.values())

    def map_ioc_to_ttp(self, ioc_value: str, technique_id: str) -> None:
        key = ioc_value.strip().lower()
        if key not in self._ioc_to_ttp:
            self._ioc_to_ttp[key] = set()
        self._ioc_to_ttp[key].add(technique_id)

    def map_actor_to_ttp(self, actor_name: str, technique_id: str) -> None:
        if actor_name not in self._actor_to_ttp:
            self._actor_to_ttp[actor_name] = set()
        self._actor_to_ttp[actor_name].add(technique_id)

    def get_ttps_for_ioc(self, ioc_value: str) -> List[TTP]:
        key = ioc_value.strip().lower()
        ids = self._ioc_to_ttp.get(key, set())
        return [self._ttps[tid] for tid in ids if tid in self._ttps]

    def get_ttps_for_actor(self, actor_name: str) -> List[TTP]:
        ids = self._actor_to_ttp.get(actor_name, set())
        return [self._ttps[tid] for tid in ids if tid in self._ttps]

    def get_actors_for_ttp(self, technique_id: str) -> List[str]:
        return [
            actor for actor, tids in self._actor_to_ttp.items()
            if technique_id in tids
        ]

    def search_by_tactic(self, tactic: str) -> List[TTP]:
        return [t for t in self._ttps.values() if t.tactic.lower() == tactic.lower()]


# ---------------------------------------------------------------------------
# Threat Actor
# ---------------------------------------------------------------------------

@dataclass
class ThreatActor:
    """Threat Actor profile."""
    name: str
    aliases: List[str] = field(default_factory=list)
    motivation: str = ""
    sophistication: str = ""
    iocs: List[str] = field(default_factory=list)
    ttps: List[str] = field(default_factory=list)
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "aliases": self.aliases,
            "motivation": self.motivation,
            "sophistication": self.sophistication,
            "iocs": self.iocs,
            "ttps": self.ttps,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ThreatActor":
        return cls(
            id=data.get("id", str(uuid.uuid4())),
            name=data["name"],
            aliases=data.get("aliases", []),
            motivation=data.get("motivation", ""),
            sophistication=data.get("sophistication", ""),
            iocs=data.get("iocs", []),
            ttps=data.get("ttps", []),
            created_at=data.get("created_at", datetime.now(timezone.utc).isoformat()),
            updated_at=data.get("updated_at", datetime.now(timezone.utc).isoformat()),
        )


class ActorTracker:
    """Track and manage threat actors."""

    def __init__(self):
        self._actors: Dict[str, ThreatActor] = {}

    def add_actor(self, actor: ThreatActor) -> None:
        self._actors[actor.name] = actor

    def get_actor(self, name: str) -> Optional[ThreatActor]:
        return self._actors.get(name)

    def update_actor(self, name: str, **kwargs) -> bool:
        actor = self._actors.get(name)
        if actor is None:
            return False
        for key, value in kwargs.items():
            if hasattr(actor, key):
                setattr(actor, key, value)
        actor.updated_at = datetime.now(timezone.utc).isoformat()
        return True

    def remove_actor(self, name: str) -> bool:
        if name in self._actors:
            del self._actors[name]
            return True
        return False

    def add_ioc_to_actor(self, actor_name: str, ioc_value: str) -> bool:
        actor = self._actors.get(actor_name)
        if actor is None:
            return False
        if ioc_value not in actor.iocs:
            actor.iocs.append(ioc_value)
        return True

    def add_ttp_to_actor(self, actor_name: str, technique_id: str) -> bool:
        actor = self._actors.get(actor_name)
        if actor is None:
            return False
        if technique_id not in actor.ttps:
            actor.ttps.append(technique_id)
        return True

    def find_by_alias(self, alias: str) -> List[ThreatActor]:
        return [a for a in self._actors.values() if alias in a.aliases]

    def find_by_ttp(self, technique_id: str) -> List[ThreatActor]:
        return [a for a in self._actors.values() if technique_id in a.ttps]

    def find_by_ioc(self, ioc_value: str) -> List[ThreatActor]:
        return [a for a in self._actors.values() if ioc_value in a.iocs]

    def all_actors(self) -> List[ThreatActor]:
        return list(self._actors.values())


# ---------------------------------------------------------------------------
# Intelligence Report
# ---------------------------------------------------------------------------

@dataclass
class IntelligenceReport:
    """Aggregated intelligence report."""
    title: str
    tlp: TLP = TLP.AMBER
    description: str = ""
    iocs: List[IOC] = field(default_factory=list)
    ttps: List[TTP] = field(default_factory=list)
    actors: List[ThreatActor] = field(default_factory=list)
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "tlp": self.tlp.value,
            "description": self.description,
            "iocs": [i.to_dict() for i in self.iocs],
            "ttps": [t.to_dict() for t in self.ttps],
            "actors": [a.to_dict() for a in self.actors],
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "IntelligenceReport":
        return cls(
            id=data.get("id", str(uuid.uuid4())),
            title=data["title"],
            tlp=TLP(data.get("tlp", "amber")),
            description=data.get("description", ""),
            iocs=[IOC.from_dict(i) for i in data.get("iocs", [])],
            ttps=[TTP.from_dict(t) for t in data.get("ttps", [])],
            actors=[ThreatActor.from_dict(a) for a in data.get("actors", [])],
            created_at=data.get("created_at", datetime.now(timezone.utc).isoformat()),
        )


# ---------------------------------------------------------------------------
# STIX Exporter
# ---------------------------------------------------------------------------

class STIXExporter:
    """Export CTI objects to STIX 2.1 format."""

    @staticmethod
    def _stix_id(obj_type: str, uuid_val: str) -> str:
        return f"{obj_type}--{uuid_val}"

    @classmethod
    def export_ioc(cls, ioc: IOC) -> Dict[str, Any]:
        type_map = {
            IOCType.IP: "ipv4-addr",
            IOCType.DOMAIN: "domain-name",
            IOCType.URL: "url",
            IOCType.FILE_HASH_MD5: "file",
            IOCType.FILE_HASH_SHA1: "file",
            IOCType.FILE_HASH_SHA256: "file",
            IOCType.EMAIL: "email-addr",
            IOCType.CVE: "vulnerability",
        }
        stix_type = type_map.get(ioc.type, "indicator")
        pattern_map = {
            IOCType.IP: f"[ipv4-addr:value = '{ioc.value}']",
            IOCType.DOMAIN: f"[domain-name:value = '{ioc.value}']",
            IOCType.URL: f"[url:value = '{ioc.value}']",
            IOCType.FILE_HASH_MD5: f"[file:hashes.MD5 = '{ioc.value}']",
            IOCType.FILE_HASH_SHA1: f"[file:hashes.SHA1 = '{ioc.value}']",
            IOCType.FILE_HASH_SHA256: f"[file:hashes.SHA256 = '{ioc.value}']",
            IOCType.EMAIL: f"[email-addr:value = '{ioc.value}']",
            IOCType.CVE: f"[vulnerability:name = '{ioc.value}']",
        }
        pattern = pattern_map.get(ioc.type, f"[indicator:value = '{ioc.value}']")
        return {
            "type": "indicator",
            "id": cls._stix_id("indicator", ioc.id),
            "created": ioc.created_at,
            "modified": ioc.updated_at,
            "name": f"{ioc.type.value}: {ioc.value}",
            "description": ioc.description,
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": ioc.created_at,
            "labels": ioc.tags,
            "confidence": ioc.confidence.value,
        }

    @classmethod
    def export_ttp(cls, ttp: TTP) -> Dict[str, Any]:
        return {
            "type": "attack-pattern",
            "id": cls._stix_id("attack-pattern", ttp.id),
            "created": ttp.created_at,
            "name": ttp.name,
            "description": ttp.description,
            "x_mitre_id": ttp.technique_id,
            "x_mitre_tactic": ttp.tactic,
        }

    @classmethod
    def export_actor(cls, actor: ThreatActor) -> Dict[str, Any]:
        return {
            "type": "threat-actor",
            "id": cls._stix_id("threat-actor", actor.id),
            "created": actor.created_at,
            "modified": actor.updated_at,
            "name": actor.name,
            "aliases": actor.aliases,
            "description": f"Motivation: {actor.motivation}, Sophistication: {actor.sophistication}",
        }

    @classmethod
    def export_report(cls, report: IntelligenceReport) -> Dict[str, Any]:
        objects = []
        for ioc in report.iocs:
            objects.append(cls.export_ioc(ioc))
        for ttp in report.ttps:
            objects.append(cls.export_ttp(ttp))
        for actor in report.actors:
            objects.append(cls.export_actor(actor))
        return {
            "type": "bundle",
            "id": cls._stix_id("bundle", report.id),
            "objects": objects,
        }


# ---------------------------------------------------------------------------
# TAXII Collection
# ---------------------------------------------------------------------------

class TAXIICollection:
    """TAXII 2.1 data collection."""

    def __init__(self, name: str, description: str = ""):
        self.name = name
        self.description = description
        self._objects: List[Dict[str, Any]] = []
        self._tlp: TLP = TLP.AMBER

    def add_object(self, obj: Dict[str, Any]) -> None:
        self._objects.append(obj)

    def get_objects(self) -> List[Dict[str, Any]]:
        return list(self._objects)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "tlp": self._tlp.value,
            "objects": self._objects,
        }


# ---------------------------------------------------------------------------
# Sharing Hub
# ---------------------------------------------------------------------------

class SharingHub:
    """Central hub for intelligence sharing with TLP enforcement."""

    _TLP_HIERARCHY = {
        TLP.WHITE: 0,
        TLP.GREEN: 1,
        TLP.AMBER: 2,
        TLP.RED: 3,
    }

    def __init__(self):
        self._collections: Dict[str, TAXIICollection] = {}

    def create_collection(self, name: str, description: str = "") -> TAXIICollection:
        col = TAXIICollection(name=name, description=description)
        self._collections[name] = col
        return col

    def get_collection(self, name: str) -> Optional[TAXIICollection]:
        return self._collections.get(name)

    def list_collections(self) -> List[str]:
        return list(self._collections.keys())

    def set_tlp(self, collection_name: str, tlp: TLP) -> None:
        col = self._collections.get(collection_name)
        if col:
            col._tlp = tlp

    def get_tlp(self, collection_name: str) -> Optional[TLP]:
        col = self._collections.get(collection_name)
        return col._tlp if col else None

    def share_report(self, report: IntelligenceReport, collection_name: str) -> bool:
        """Share a report to a collection, enforcing TLP rules."""
        col = self._collections.get(collection_name)
        if col is None:
            return False
        col_tlp = col._tlp
        report_tlp = report.tlp
        # Block if report is more restrictive than collection
        if self._TLP_HIERARCHY.get(report_tlp, 0) > self._TLP_HIERARCHY.get(col_tlp, 0):
            return False
        stix_bundle = STIXExporter.export_report(report)
        col.add_object(stix_bundle)
        return True
