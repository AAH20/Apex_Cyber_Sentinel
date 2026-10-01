"""Threat Intelligence Fusion, IOC Lifecycle Management, and Sharing.

Provides:
- FusionEngine: merges IOCs from multiple feeds with deduplication
- LifecycleManager: manages IOC lifecycle stages (active/inactive/revoked/expired)
- SharingGateway: packages and shares intelligence with TLP enforcement
"""

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set

from src.cyber.cti import (
    IOC,
    IOCType,
    IOCFeed,
    TTP,
    ThreatActor,
    IntelligenceReport,
    STIXExporter,
    TLP,
    Confidence,
    Severity,
)


# ---------------------------------------------------------------------------
# Lifecycle Stage
# ---------------------------------------------------------------------------

class LifecycleStage(Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    REVOKED = "revoked"
    EXPIRED = "expired"


# ---------------------------------------------------------------------------
# Fusion Result
# ---------------------------------------------------------------------------

@dataclass
class Correlation:
    """Correlation between two IOCs."""
    ioc_a: IOC
    ioc_b: IOC
    relationship: str
    confidence: Confidence = Confidence.MEDIUM

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ioc_a": self.ioc_a.to_dict(),
            "ioc_b": self.ioc_b.to_dict(),
            "relationship": self.relationship,
            "confidence": self.confidence.value,
        }


@dataclass
class FusionResult:
    """Result of fusing multiple IOC feeds."""
    iocs: List[IOC] = field(default_factory=list)
    sources: List[str] = field(default_factory=list)
    correlations: List[Correlation] = field(default_factory=list)
    fused_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "iocs": [i.to_dict() for i in self.iocs],
            "sources": self.sources,
            "correlations": [c.to_dict() for c in self.correlations],
            "fused_at": self.fused_at,
        }


# ---------------------------------------------------------------------------
# Fusion Engine
# ---------------------------------------------------------------------------

class FusionEngine:
    """Fuses IOCs from multiple feeds with deduplication and correlation."""

    _CONFIDENCE_ORDER = {
        Confidence.LOW: 0,
        Confidence.MEDIUM: 1,
        Confidence.HIGH: 2,
        Confidence.CRITICAL: 3,
    }

    def fuse(self, *feeds: IOCFeed) -> FusionResult:
        """Fuse multiple IOC feeds into a single result with deduplication."""
        merged: Dict[str, IOC] = {}
        sources: Set[str] = set()

        for feed in feeds:
            for ioc in feed.all():
                sources.add(ioc.source)
                key = ioc.normalize()
                if key in merged:
                    existing = merged[key]
                    # Merge tags
                    existing.tags = list(set(existing.tags + ioc.tags))
                    # Keep highest confidence
                    if self._CONFIDENCE_ORDER.get(ioc.confidence, 0) > self._CONFIDENCE_ORDER.get(existing.confidence, 0):
                        existing.confidence = ioc.confidence
                    # Keep highest severity
                    if self._severity_order(ioc.severity) > self._severity_order(existing.severity):
                        existing.severity = ioc.severity
                else:
                    merged[key] = ioc

        result = FusionResult(
            iocs=list(merged.values()),
            sources=sorted(sources),
        )
        return result

    @staticmethod
    def _severity_order(severity: Severity) -> int:
        order = {
            Severity.INFO: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }
        return order.get(severity, 0)

    def correlate(self, iocs: List[IOC]) -> List[Correlation]:
        """Find correlations between IOCs based on shared tags."""
        correlations: List[Correlation] = []
        for i in range(len(iocs)):
            for j in range(i + 1, len(iocs)):
                a, b = iocs[i], iocs[j]
                shared = set(a.tags) & set(b.tags)
                if shared:
                    correlations.append(Correlation(
                        ioc_a=a,
                        ioc_b=b,
                        relationship="shared_tag",
                        confidence=Confidence.MEDIUM,
                    ))
        return correlations


# ---------------------------------------------------------------------------
# Lifecycle Manager
# ---------------------------------------------------------------------------

class LifecycleManager:
    """Manages IOC lifecycle stages."""

    _VALID_TRANSITIONS: Dict[LifecycleStage, Set[LifecycleStage]] = {
        LifecycleStage.ACTIVE: {LifecycleStage.INACTIVE, LifecycleStage.REVOKED, LifecycleStage.EXPIRED},
        LifecycleStage.INACTIVE: {LifecycleStage.ACTIVE, LifecycleStage.REVOKED, LifecycleStage.EXPIRED},
        LifecycleStage.REVOKED: set(),
        LifecycleStage.EXPIRED: set(),
    }

    def __init__(self):
        self._stages: Dict[str, LifecycleStage] = {}

    def get_stage(self, ioc: IOC) -> LifecycleStage:
        key = ioc.normalize()
        return self._stages.get(key, LifecycleStage.ACTIVE)

    def transition(self, ioc: IOC, target: LifecycleStage) -> bool:
        current = self.get_stage(ioc)
        if target not in self._VALID_TRANSITIONS.get(current, set()):
            raise ValueError(f"Invalid transition: {current.value} -> {target.value}")
        self._stages[ioc.normalize()] = target
        return True

    def is_active(self, ioc: IOC) -> bool:
        return self.get_stage(ioc) == LifecycleStage.ACTIVE

    def can_transition(self, current: LifecycleStage, target: LifecycleStage) -> bool:
        return target in self._VALID_TRANSITIONS.get(current, set())

    def expire_old(self, iocs: List[IOC], max_age_days: int) -> List[IOC]:
        """Expire IOCs older than max_age_days. Returns list of expired IOCs."""
        now = datetime.now(timezone.utc)
        expired: List[IOC] = []
        for ioc in iocs:
            try:
                created = datetime.fromisoformat(ioc.created_at.replace("Z", "+00:00"))
                age = (now - created).days
                if age > max_age_days:
                    self._stages[ioc.normalize()] = LifecycleStage.EXPIRED
                    expired.append(ioc)
            except (ValueError, AttributeError):
                continue
        return expired


# ---------------------------------------------------------------------------
# Sharing Policy
# ---------------------------------------------------------------------------

@dataclass
class SharingPolicy:
    """Policy for sharing intelligence."""
    tlp: TLP = TLP.AMBER
    allowed_types: Optional[List[IOCType]] = None

    _TLP_HIERARCHY = {
        TLP.WHITE: 0,
        TLP.GREEN: 1,
        TLP.AMBER: 2,
        TLP.RED: 3,
    }

    def can_share(self, ioc: IOC) -> bool:
        """Check if an IOC can be shared under this policy."""
        if self.allowed_types is not None and ioc.type not in self.allowed_types:
            return False
        # Check lifecycle stage
        stage = getattr(ioc, "_lifecycle_stage", LifecycleStage.ACTIVE)
        if stage != LifecycleStage.ACTIVE:
            return False
        return True

    def can_share_report(self, report: IntelligenceReport) -> bool:
        """Check if a report can be shared under this policy."""
        report_level = self._TLP_HIERARCHY.get(report.tlp, 0)
        policy_level = self._TLP_HIERARCHY.get(self.tlp, 0)
        return report_level <= policy_level


# ---------------------------------------------------------------------------
# Intelligence Package
# ---------------------------------------------------------------------------

@dataclass
class IntelligencePackage:
    """Package of intelligence for sharing."""
    iocs: List[IOC] = field(default_factory=list)
    ttps: List[TTP] = field(default_factory=list)
    actors: List[ThreatActor] = field(default_factory=list)
    tlp: TLP = TLP.AMBER
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_stix(self) -> Dict[str, Any]:
        """Export package as STIX 2.1 bundle."""
        objects: List[Dict[str, Any]] = []
        for ioc in self.iocs:
            objects.append(STIXExporter.export_ioc(ioc))
        for ttp in self.ttps:
            objects.append(STIXExporter.export_ttp(ttp))
        for actor in self.actors:
            objects.append(STIXExporter.export_actor(actor))
        return {
            "type": "bundle",
            "id": f"bundle--{self.id}",
            "objects": objects,
        }

    def to_json(self) -> str:
        """Serialize package to JSON string."""
        return json.dumps({
            "id": self.id,
            "tlp": self.tlp.value,
            "created_at": self.created_at,
            "iocs": [i.to_dict() for i in self.iocs],
            "ttps": [t.to_dict() for t in self.ttps],
            "actors": [a.to_dict() for a in self.actors],
        })

    def filter_by_type(self, ioc_type: IOCType) -> List[IOC]:
        """Filter IOCs by type."""
        return [i for i in self.iocs if i.type == ioc_type]


# ---------------------------------------------------------------------------
# Sharing Gateway
# ---------------------------------------------------------------------------

class SharingGateway:
    """Gateway for sharing intelligence with policy enforcement."""

    def __init__(self, policy: SharingPolicy):
        self.policy = policy
        self._shared: List[Dict[str, Any]] = []

    def package_iocs(self, iocs: List[IOC]) -> IntelligencePackage:
        """Create an intelligence package from IOCs, filtering by policy."""
        shareable = [i for i in iocs if self.policy.can_share(i)]
        return IntelligencePackage(
            iocs=shareable,
            ttps=[],
            actors=[],
            tlp=self.policy.tlp,
        )

    def validate_package(self, pkg: IntelligencePackage) -> List[str]:
        """Validate a package for sharing. Returns list of error strings."""
        errors: List[str] = []
        if not self.policy.can_share_report(IntelligenceReport(title="", tlp=pkg.tlp)):
            errors.append(f"TLP {pkg.tlp.value} exceeds policy TLP {self.policy.tlp.value}")
        for ioc in pkg.iocs:
            if not self.policy.can_share(ioc):
                errors.append(f"IOC {ioc.value} cannot be shared under current policy")
        return errors

    def share(self, pkg: IntelligencePackage, partner: str) -> bool:
        """Share a package with a partner. Returns True if successful."""
        errors = self.validate_package(pkg)
        if errors:
            return False
        self._shared.append({
            "package_id": pkg.id,
            "partner": partner,
            "shared_at": datetime.now(timezone.utc).isoformat(),
            "tlp": pkg.tlp.value,
        })
        return True
