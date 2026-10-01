"""Unit tests for Threat Intelligence Fusion, IOC Lifecycle, and Sharing.

TDD: These tests were written BEFORE the implementation.
Run with: python -m pytest tests/test_fusion.py -v
"""

import json
from datetime import datetime, timedelta, timezone

import pytest

from src.cyber.cti import (
    IOC,
    IOCType,
    IOCFeed,
    TTP,
    ThreatActor,
    IntelligenceReport,
    TLP,
    Confidence,
    Severity,
)
from src.cyber.fusion import (
    FusionEngine,
    FusionResult,
    Correlation,
    LifecycleStage,
    LifecycleManager,
    SharingPolicy,
    IntelligencePackage,
    SharingGateway,
)


# ---------------------------------------------------------------------------
# Fusion Engine
# ---------------------------------------------------------------------------

class TestFusionEngine:
    def test_fuse_single_feed(self):
        feed = IOCFeed()
        feed.add(IOC(value="1.2.3.4", type=IOCType.IP, source="feed_a"))
        engine = FusionEngine()
        result = engine.fuse(feed)
        assert isinstance(result, FusionResult)
        assert len(result.iocs) == 1
        assert "feed_a" in result.sources

    def test_fuse_multiple_feeds_deduplicates(self):
        feed_a = IOCFeed()
        feed_a.add(IOC(value="1.2.3.4", type=IOCType.IP, source="feed_a"))
        feed_b = IOCFeed()
        feed_b.add(IOC(value="1.2.3.4", type=IOCType.IP, source="feed_b"))
        engine = FusionEngine()
        result = engine.fuse(feed_a, feed_b)
        assert len(result.iocs) == 1
        assert "feed_a" in result.sources
        assert "feed_b" in result.sources

    def test_fuse_merges_tags_on_dedup(self):
        feed_a = IOCFeed()
        feed_a.add(IOC(value="evil.com", type=IOCType.DOMAIN, source="a", tags=["c2"]))
        feed_b = IOCFeed()
        feed_b.add(IOC(value="evil.com", type=IOCType.DOMAIN, source="b", tags=["phishing"]))
        engine = FusionEngine()
        result = engine.fuse(feed_a, feed_b)
        assert len(result.iocs) == 1
        merged = result.iocs[0]
        assert "c2" in merged.tags
        assert "phishing" in merged.tags

    def test_fuse_empty_feeds(self):
        engine = FusionEngine()
        result = engine.fuse(IOCFeed(), IOCFeed())
        assert len(result.iocs) == 0
        assert result.sources == []

    def test_fuse_preserves_highest_confidence(self):
        feed_a = IOCFeed()
        feed_a.add(IOC(value="1.2.3.4", type=IOCType.IP, confidence=Confidence.LOW))
        feed_b = IOCFeed()
        feed_b.add(IOC(value="1.2.3.4", type=IOCType.IP, confidence=Confidence.HIGH))
        engine = FusionEngine()
        result = engine.fuse(feed_a, feed_b)
        assert result.iocs[0].confidence == Confidence.HIGH

    def test_fuse_result_to_dict(self):
        feed = IOCFeed()
        feed.add(IOC(value="1.2.3.4", type=IOCType.IP))
        engine = FusionEngine()
        result = engine.fuse(feed)
        d = result.to_dict()
        assert "iocs" in d
        assert "sources" in d
        assert "fused_at" in d
        assert len(d["iocs"]) == 1


class TestCorrelation:
    def test_correlate_same_actor_iocs(self):
        engine = FusionEngine()
        ioc_a = IOC(value="1.2.3.4", type=IOCType.IP, tags=["apt29"])
        ioc_b = IOC(value="evil.com", type=IOCType.DOMAIN, tags=["apt29"])
        correlations = engine.correlate([ioc_a, ioc_b])
        assert len(correlations) >= 1
        assert correlations[0].relationship == "shared_tag"

    def test_correlate_no_match(self):
        engine = FusionEngine()
        ioc_a = IOC(value="1.2.3.4", type=IOCType.IP, tags=["tag_a"])
        ioc_b = IOC(value="evil.com", type=IOCType.DOMAIN, tags=["tag_b"])
        correlations = engine.correlate([ioc_a, ioc_b])
        assert len(correlations) == 0

    def test_correlation_to_dict(self):
        ioc_a = IOC(value="1.2.3.4", type=IOCType.IP)
        ioc_b = IOC(value="5.6.7.8", type=IOCType.IP)
        corr = Correlation(ioc_a=ioc_a, ioc_b=ioc_b, relationship="same_subnet", confidence=Confidence.MEDIUM)
        d = corr.to_dict()
        assert d["relationship"] == "same_subnet"
        assert d["confidence"] == "medium"
        assert "ioc_a" in d
        assert "ioc_b" in d


# ---------------------------------------------------------------------------
# IOC Lifecycle Management
# ---------------------------------------------------------------------------

class TestLifecycleManager:
    def test_new_ioc_is_active(self):
        mgr = LifecycleManager()
        ioc = IOC(value="1.2.3.4", type=IOCType.IP)
        assert mgr.get_stage(ioc) == LifecycleStage.ACTIVE

    def test_transition_to_inactive(self):
        mgr = LifecycleManager()
        ioc = IOC(value="1.2.3.4", type=IOCType.IP)
        assert mgr.transition(ioc, LifecycleStage.INACTIVE) is True
        assert mgr.get_stage(ioc) == LifecycleStage.INACTIVE

    def test_transition_to_revoked(self):
        mgr = LifecycleManager()
        ioc = IOC(value="1.2.3.4", type=IOCType.IP)
        assert mgr.transition(ioc, LifecycleStage.REVOKED) is True
        assert mgr.get_stage(ioc) == LifecycleStage.REVOKED

    def test_invalid_transition_raises(self):
        mgr = LifecycleManager()
        ioc = IOC(value="1.2.3.4", type=IOCType.IP)
        mgr.transition(ioc, LifecycleStage.REVOKED)
        with pytest.raises(ValueError):
            mgr.transition(ioc, LifecycleStage.ACTIVE)

    def test_is_active(self):
        mgr = LifecycleManager()
        ioc = IOC(value="1.2.3.4", type=IOCType.IP)
        assert mgr.is_active(ioc) is True
        mgr.transition(ioc, LifecycleStage.INACTIVE)
        assert mgr.is_active(ioc) is False

    def test_expire_old_iocs(self):
        mgr = LifecycleManager()
        old_ioc = IOC(value="1.2.3.4", type=IOCType.IP)
        old_ioc.created_at = (datetime.now(timezone.utc) - timedelta(days=90)).isoformat()
        new_ioc = IOC(value="5.6.7.8", type=IOCType.IP)
        expired = mgr.expire_old([old_ioc, new_ioc], max_age_days=30)
        assert len(expired) == 1
        assert expired[0].value == "1.2.3.4"
        assert mgr.get_stage(old_ioc) == LifecycleStage.EXPIRED

    def test_can_transition_valid(self):
        mgr = LifecycleManager()
        assert mgr.can_transition(LifecycleStage.ACTIVE, LifecycleStage.INACTIVE) is True

    def test_can_transition_invalid(self):
        mgr = LifecycleManager()
        assert mgr.can_transition(LifecycleStage.REVOKED, LifecycleStage.ACTIVE) is False

    def test_get_stage_for_unknown_ioc(self):
        mgr = LifecycleManager()
        ioc = IOC(value="9.9.9.9", type=IOCType.IP)
        assert mgr.get_stage(ioc) == LifecycleStage.ACTIVE


# ---------------------------------------------------------------------------
# Intelligence Sharing
# ---------------------------------------------------------------------------

class TestSharingPolicy:
    def test_policy_allows_all_types(self):
        policy = SharingPolicy(tlp=TLP.GREEN)
        ioc = IOC(value="1.2.3.4", type=IOCType.IP)
        assert policy.can_share(ioc) is True

    def test_policy_blocks_restricted_types(self):
        policy = SharingPolicy(tlp=TLP.GREEN, allowed_types=[IOCType.IP])
        ioc_domain = IOC(value="evil.com", type=IOCType.DOMAIN)
        ioc_ip = IOC(value="1.2.3.4", type=IOCType.IP)
        assert policy.can_share(ioc_domain) is False
        assert policy.can_share(ioc_ip) is True

    def test_policy_blocks_inactive_iocs(self):
        policy = SharingPolicy(tlp=TLP.GREEN)
        ioc = IOC(value="1.2.3.4", type=IOCType.IP)
        ioc._lifecycle_stage = LifecycleStage.INACTIVE
        assert policy.can_share(ioc) is False

    def test_policy_tlp_enforcement(self):
        policy = SharingPolicy(tlp=TLP.GREEN)
        report = IntelligenceReport(title="Test", tlp=TLP.RED)
        assert policy.can_share_report(report) is False


class TestIntelligencePackage:
    def test_create_package(self):
        ioc = IOC(value="1.2.3.4", type=IOCType.IP)
        pkg = IntelligencePackage(
            iocs=[ioc],
            ttps=[],
            actors=[],
            tlp=TLP.AMBER,
        )
        assert len(pkg.iocs) == 1
        assert pkg.tlp == TLP.AMBER

    def test_package_to_stix(self):
        ioc = IOC(value="1.2.3.4", type=IOCType.IP)
        pkg = IntelligencePackage(iocs=[ioc], ttps=[], actors=[], tlp=TLP.GREEN)
        stix = pkg.to_stix()
        assert stix["type"] == "bundle"
        assert len(stix["objects"]) == 1

    def test_package_to_json(self):
        ioc = IOC(value="1.2.3.4", type=IOCType.IP)
        pkg = IntelligencePackage(iocs=[ioc], ttps=[], actors=[], tlp=TLP.GREEN)
        data = json.loads(pkg.to_json())
        assert "iocs" in data
        assert data["tlp"] == "green"

    def test_package_filter_by_type(self):
        ioc_ip = IOC(value="1.2.3.4", type=IOCType.IP)
        ioc_domain = IOC(value="evil.com", type=IOCType.DOMAIN)
        pkg = IntelligencePackage(iocs=[ioc_ip, ioc_domain], ttps=[], actors=[], tlp=TLP.GREEN)
        filtered = pkg.filter_by_type(IOCType.IP)
        assert len(filtered) == 1
        assert filtered[0].type == IOCType.IP


class TestSharingGateway:
    def test_package_iocs(self):
        gateway = SharingGateway(SharingPolicy(tlp=TLP.GREEN))
        ioc = IOC(value="1.2.3.4", type=IOCType.IP)
        pkg = gateway.package_iocs([ioc])
        assert len(pkg.iocs) == 1
        assert pkg.tlp == TLP.GREEN

    def test_package_filters_inactive(self):
        gateway = SharingGateway(SharingPolicy(tlp=TLP.GREEN))
        active = IOC(value="1.2.3.4", type=IOCType.IP)
        inactive = IOC(value="5.6.7.8", type=IOCType.IP)
        inactive._lifecycle_stage = LifecycleStage.INACTIVE
        pkg = gateway.package_iocs([active, inactive])
        assert len(pkg.iocs) == 1

    def test_validate_package_valid(self):
        gateway = SharingGateway(SharingPolicy(tlp=TLP.GREEN))
        ioc = IOC(value="1.2.3.4", type=IOCType.IP)
        pkg = IntelligencePackage(iocs=[ioc], ttps=[], actors=[], tlp=TLP.GREEN)
        errors = gateway.validate_package(pkg)
        assert errors == []

    def test_validate_package_tlp_mismatch(self):
        gateway = SharingGateway(SharingPolicy(tlp=TLP.GREEN))
        ioc = IOC(value="1.2.3.4", type=IOCType.IP)
        pkg = IntelligencePackage(iocs=[ioc], ttps=[], actors=[], tlp=TLP.RED)
        errors = gateway.validate_package(pkg)
        assert len(errors) > 0

    def test_share_package(self):
        gateway = SharingGateway(SharingPolicy(tlp=TLP.GREEN))
        ioc = IOC(value="1.2.3.4", type=IOCType.IP)
        pkg = gateway.package_iocs([ioc])
        assert gateway.share(pkg, "partner_a") is True

    def test_share_package_invalid_tlp(self):
        gateway = SharingGateway(SharingPolicy(tlp=TLP.GREEN))
        ioc = IOC(value="1.2.3.4", type=IOCType.IP)
        pkg = IntelligencePackage(iocs=[ioc], ttps=[], actors=[], tlp=TLP.RED)
        assert gateway.share(pkg, "partner_a") is False
