"""Unit tests for Cyber Threat Intelligence module.

TDD: These tests were written BEFORE the implementation.
Run with: python -m pytest tests/test_cti.py -v
"""

import json
import pytest
from datetime import datetime, timezone

from src.cyber.cti import (
    IOC,
    IOCType,
    IOCValidator,
    IOCFeed,
    TTP,
    TTPMapper,
    ThreatActor,
    ActorTracker,
    IntelligenceReport,
    STIXExporter,
    TAXIICollection,
    SharingHub,
    TLP,
    Confidence,
    Severity,
)


# ---------------------------------------------------------------------------
# IOC Creation & Validation
# ---------------------------------------------------------------------------

class TestIOC:
    def test_create_ioc_with_defaults(self):
        ioc = IOC(value="192.168.1.1", type=IOCType.IP)
        assert ioc.value == "192.168.1.1"
        assert ioc.type == IOCType.IP
        assert ioc.confidence == Confidence.MEDIUM
        assert ioc.severity == Severity.MEDIUM
        assert ioc.source == "unknown"
        assert ioc.id is not None

    def test_create_ioc_with_custom_fields(self):
        ioc = IOC(
            value="evil.com",
            type=IOCType.DOMAIN,
            confidence=Confidence.HIGH,
            severity=Severity.CRITICAL,
            source="feed_alpha",
            tags=["c2", "phishing"],
            description="Known C2 server",
        )
        assert ioc.confidence == Confidence.HIGH
        assert ioc.severity == Severity.CRITICAL
        assert ioc.source == "feed_alpha"
        assert "c2" in ioc.tags
        assert "phishing" in ioc.tags

    def test_ioc_to_dict(self):
        ioc = IOC(value="10.0.0.1", type=IOCType.IP, tags=["test"])
        d = ioc.to_dict()
        assert d["value"] == "10.0.0.1"
        assert d["type"] == "ip"
        assert "test" in d["tags"]
        assert "id" in d

    def test_ioc_from_dict(self):
        data = {
            "value": "10.0.0.1",
            "type": "ip",
            "confidence": "high",
            "severity": "critical",
            "source": "test",
            "tags": ["malware"],
            "description": "test ioc",
            "id": "test-id-123",
        }
        ioc = IOC.from_dict(data)
        assert ioc.value == "10.0.0.1"
        assert ioc.type == IOCType.IP
        assert ioc.confidence == Confidence.HIGH
        assert ioc.severity == Severity.CRITICAL
        assert ioc.id == "test-id-123"

    def test_ioc_normalize_lowercase(self):
        ioc = IOC(value="EVIL.COM", type=IOCType.DOMAIN)
        assert ioc.normalize() == "evil.com"

    def test_ioc_normalize_strips_whitespace(self):
        ioc = IOC(value="  192.168.1.1  ", type=IOCType.IP)
        assert ioc.normalize() == "192.168.1.1"


class TestIOCValidator:
    def test_validate_ipv4(self):
        assert IOCValidator.validate("192.168.1.1", IOCType.IP) is True

    def test_validate_ipv6(self):
        assert IOCValidator.validate("2001:db8::1", IOCType.IP) is True

    def test_validate_invalid_ip(self):
        assert IOCValidator.validate("not-an-ip", IOCType.IP) is False

    def test_validate_domain(self):
        assert IOCValidator.validate("evil.com", IOCType.DOMAIN) is True

    def test_validate_invalid_domain(self):
        assert IOCValidator.validate("not a domain!", IOCType.DOMAIN) is False

    def test_validate_url(self):
        assert IOCValidator.validate("https://evil.com/path", IOCType.URL) is True

    def test_validate_invalid_url(self):
        assert IOCValidator.validate("not-a-url", IOCType.URL) is False

    def test_validate_md5(self):
        assert IOCValidator.validate("d41d8cd98f00b204e9800998ecf8427e", IOCType.FILE_HASH_MD5) is True

    def test_validate_sha1(self):
        assert IOCValidator.validate("da39a3ee5e6b4b0d3255bfef95601890afd80709", IOCType.FILE_HASH_SHA1) is True

    def test_validate_sha256(self):
        assert IOCValidator.validate(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            IOCType.FILE_HASH_SHA256,
        ) is True

    def test_validate_invalid_hash(self):
        assert IOCValidator.validate("xyz123", IOCType.FILE_HASH_SHA256) is False

    def test_validate_email(self):
        assert IOCValidator.validate("attacker@evil.com", IOCType.EMAIL) is True

    def test_validate_invalid_email(self):
        assert IOCValidator.validate("not-an-email", IOCType.EMAIL) is False

    def test_validate_cve(self):
        assert IOCValidator.validate("CVE-2021-44228", IOCType.CVE) is True

    def test_validate_invalid_cve(self):
        assert IOCValidator.validate("CVE-2021", IOCType.CVE) is False

    def test_detect_type_ip(self):
        assert IOCValidator.detect_type("192.168.1.1") == IOCType.IP

    def test_detect_type_domain(self):
        assert IOCValidator.detect_type("evil.com") == IOCType.DOMAIN

    def test_detect_type_url(self):
        assert IOCValidator.detect_type("https://evil.com") == IOCType.URL

    def test_detect_type_md5(self):
        assert IOCValidator.detect_type("d41d8cd98f00b204e9800998ecf8427e") == IOCType.FILE_HASH_MD5

    def test_detect_type_sha256(self):
        assert IOCValidator.detect_type(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ) == IOCType.FILE_HASH_SHA256

    def test_detect_type_email(self):
        assert IOCValidator.detect_type("user@domain.com") == IOCType.EMAIL

    def test_detect_type_cve(self):
        assert IOCValidator.detect_type("CVE-2021-44228") == IOCType.CVE

    def test_detect_type_unknown(self):
        assert IOCValidator.detect_type("random-garbage-value") is None


# ---------------------------------------------------------------------------
# IOC Feed Ingestion
# ---------------------------------------------------------------------------

class TestIOCFeed:
    def test_add_ioc(self):
        feed = IOCFeed()
        ioc = IOC(value="1.2.3.4", type=IOCType.IP)
        assert feed.add(ioc) is True
        assert len(feed) == 1

    def test_add_duplicate_ioc_updates(self):
        feed = IOCFeed()
        ioc1 = IOC(value="1.2.3.4", type=IOCType.IP, source="feed_a")
        ioc2 = IOC(value="1.2.3.4", type=IOCType.IP, source="feed_b")
        feed.add(ioc1)
        feed.add(ioc2)
        assert len(feed) == 1
        stored = feed.get("1.2.3.4")
        assert stored.source == "feed_b"

    def test_ingest_json(self):
        feed = IOCFeed()
        data = json.dumps([
            {"value": "1.2.3.4", "type": "ip", "source": "test"},
            {"value": "evil.com", "type": "domain", "source": "test"},
        ])
        count = feed.ingest_json(data)
        assert count == 2
        assert len(feed) == 2

    def test_ingest_json_with_invalid_ioc(self):
        feed = IOCFeed()
        data = json.dumps([
            {"value": "1.2.3.4", "type": "ip"},
            {"value": "not-valid", "type": "ip"},
        ])
        count = feed.ingest_json(data)
        assert count == 1

    def test_ingest_csv(self):
        feed = IOCFeed()
        csv_data = "value,type,source\n1.2.3.4,ip,feed_a\nevil.com,domain,feed_b\n"
        count = feed.ingest_csv(csv_data)
        assert count == 2

    def test_ingest_text_auto_detect(self):
        feed = IOCFeed()
        text = "1.2.3.4\nevil.com\nhttps://bad.com/path\n"
        count = feed.ingest_text(text)
        assert count == 3

    def test_get_ioc(self):
        feed = IOCFeed()
        ioc = IOC(value="5.6.7.8", type=IOCType.IP, tags=["test"])
        feed.add(ioc)
        result = feed.get("5.6.7.8")
        assert result is not None
        assert result.value == "5.6.7.8"

    def test_get_nonexistent_ioc(self):
        feed = IOCFeed()
        assert feed.get("9.9.9.9") is None

    def test_search_by_type(self):
        feed = IOCFeed()
        feed.add(IOC(value="1.1.1.1", type=IOCType.IP))
        feed.add(IOC(value="2.2.2.2", type=IOCType.IP))
        feed.add(IOC(value="evil.com", type=IOCType.DOMAIN))
        results = feed.search(ioc_type=IOCType.IP)
        assert len(results) == 2

    def test_search_by_tag(self):
        feed = IOCFeed()
        feed.add(IOC(value="1.1.1.1", type=IOCType.IP, tags=["c2"]))
        feed.add(IOC(value="2.2.2.2", type=IOCType.IP, tags=["phishing"]))
        results = feed.search(tag="c2")
        assert len(results) == 1
        assert results[0].value == "1.1.1.1"

    def test_search_by_source(self):
        feed = IOCFeed()
        feed.add(IOC(value="1.1.1.1", type=IOCType.IP, source="feed_a"))
        feed.add(IOC(value="2.2.2.2", type=IOCType.IP, source="feed_b"))
        results = feed.search(source="feed_a")
        assert len(results) == 1

    def test_remove_ioc(self):
        feed = IOCFeed()
        feed.add(IOC(value="1.1.1.1", type=IOCType.IP))
        assert feed.remove("1.1.1.1") is True
        assert len(feed) == 0

    def test_remove_nonexistent_ioc(self):
        feed = IOCFeed()
        assert feed.remove("9.9.9.9") is False

    def test_all_iocs(self):
        feed = IOCFeed()
        feed.add(IOC(value="1.1.1.1", type=IOCType.IP))
        feed.add(IOC(value="2.2.2.2", type=IOCType.IP))
        assert len(feed.all()) == 2


# ---------------------------------------------------------------------------
# TTP Mapping
# ---------------------------------------------------------------------------

class TestTTP:
    def test_create_ttp(self):
        ttp = TTP(
            technique_id="T1059",
            tactic="Execution",
            name="Command and Scripting Interpreter",
            description="Adversaries may abuse command and script interpreters.",
        )
        assert ttp.technique_id == "T1059"
        assert ttp.tactic == "Execution"
        assert ttp.name == "Command and Scripting Interpreter"

    def test_ttp_to_dict(self):
        ttp = TTP(technique_id="T1059", tactic="Execution", name="Test")
        d = ttp.to_dict()
        assert d["technique_id"] == "T1059"
        assert d["tactic"] == "Execution"
        assert "id" in d

    def test_ttp_from_dict(self):
        data = {
            "technique_id": "T1059",
            "tactic": "Execution",
            "name": "Command and Scripting Interpreter",
            "description": "Test",
            "id": "ttp-123",
        }
        ttp = TTP.from_dict(data)
        assert ttp.technique_id == "T1059"
        assert ttp.id == "ttp-123"


class TestTTPMapper:
    def test_add_and_get_ttp(self):
        mapper = TTPMapper()
        ttp = TTP(technique_id="T1059", tactic="Execution", name="Test")
        mapper.add_ttp(ttp)
        result = mapper.get_ttp("T1059")
        assert result is not None
        assert result.name == "Test"

    def test_get_nonexistent_ttp(self):
        mapper = TTPMapper()
        assert mapper.get_ttp("T9999") is None

    def test_map_ioc_to_ttp(self):
        mapper = TTPMapper()
        mapper.add_ttp(TTP(technique_id="T1059", tactic="Execution", name="Test"))
        mapper.map_ioc_to_ttp("1.2.3.4", "T1059")
        ttps = mapper.get_ttps_for_ioc("1.2.3.4")
        assert len(ttps) == 1
        assert ttps[0].technique_id == "T1059"

    def test_map_actor_to_ttp(self):
        mapper = TTPMapper()
        mapper.add_ttp(TTP(technique_id="T1059", tactic="Execution", name="Test"))
        mapper.map_actor_to_ttp("APT29", "T1059")
        ttps = mapper.get_ttps_for_actor("APT29")
        assert len(ttps) == 1

    def test_get_actors_for_ttp(self):
        mapper = TTPMapper()
        mapper.add_ttp(TTP(technique_id="T1059", tactic="Execution", name="Test"))
        mapper.map_actor_to_ttp("APT29", "T1059")
        mapper.map_actor_to_ttp("APT28", "T1059")
        actors = mapper.get_actors_for_ttp("T1059")
        assert len(actors) == 2
        assert "APT29" in actors
        assert "APT28" in actors

    def test_search_by_tactic(self):
        mapper = TTPMapper()
        mapper.add_ttp(TTP(technique_id="T1059", tactic="Execution", name="Cmd"))
        mapper.add_ttp(TTP(technique_id="T1078", tactic="Persistence", name="Accounts"))
        mapper.add_ttp(TTP(technique_id="T1053", tactic="Execution", name="Scheduled Task"))
        results = mapper.search_by_tactic("Execution")
        assert len(results) == 2

    def test_all_ttps(self):
        mapper = TTPMapper()
        mapper.add_ttp(TTP(technique_id="T1059", tactic="Execution", name="A"))
        mapper.add_ttp(TTP(technique_id="T1078", tactic="Persistence", name="B"))
        assert len(mapper.all_ttps()) == 2


# ---------------------------------------------------------------------------
# Threat Actor Tracking
# ---------------------------------------------------------------------------

class TestThreatActor:
    def test_create_actor(self):
        actor = ThreatActor(
            name="APT29",
            aliases=["Cozy Bear", "Midnight Blizzard"],
            motivation="Espionage",
            sophistication="high",
        )
        assert actor.name == "APT29"
        assert "Cozy Bear" in actor.aliases
        assert actor.motivation == "Espionage"

    def test_actor_to_dict(self):
        actor = ThreatActor(name="APT29", aliases=["Cozy Bear"])
        d = actor.to_dict()
        assert d["name"] == "APT29"
        assert "Cozy Bear" in d["aliases"]
        assert "id" in d

    def test_actor_from_dict(self):
        data = {
            "name": "APT29",
            "aliases": ["Cozy Bear"],
            "motivation": "Espionage",
            "sophistication": "high",
            "id": "actor-123",
        }
        actor = ThreatActor.from_dict(data)
        assert actor.name == "APT29"
        assert actor.id == "actor-123"


class TestActorTracker:
    def test_add_and_get_actor(self):
        tracker = ActorTracker()
        actor = ThreatActor(name="APT29")
        tracker.add_actor(actor)
        result = tracker.get_actor("APT29")
        assert result is not None
        assert result.name == "APT29"

    def test_get_nonexistent_actor(self):
        tracker = ActorTracker()
        assert tracker.get_actor("NONEXISTENT") is None

    def test_update_actor(self):
        tracker = ActorTracker()
        tracker.add_actor(ThreatActor(name="APT29"))
        tracker.update_actor("APT29", motivation="Espionage", sophistication="high")
        actor = tracker.get_actor("APT29")
        assert actor.motivation == "Espionage"
        assert actor.sophistication == "high"

    def test_update_nonexistent_actor(self):
        tracker = ActorTracker()
        assert tracker.update_actor("NONEXISTENT", motivation="test") is False

    def test_add_ioc_to_actor(self):
        tracker = ActorTracker()
        tracker.add_actor(ThreatActor(name="APT29"))
        assert tracker.add_ioc_to_actor("APT29", "1.2.3.4") is True
        actor = tracker.get_actor("APT29")
        assert "1.2.3.4" in actor.iocs

    def test_add_ioc_to_nonexistent_actor(self):
        tracker = ActorTracker()
        assert tracker.add_ioc_to_actor("NONEXISTENT", "1.2.3.4") is False

    def test_add_ttp_to_actor(self):
        tracker = ActorTracker()
        tracker.add_actor(ThreatActor(name="APT29"))
        assert tracker.add_ttp_to_actor("APT29", "T1059") is True
        actor = tracker.get_actor("APT29")
        assert "T1059" in actor.ttps

    def test_add_ttp_to_nonexistent_actor(self):
        tracker = ActorTracker()
        assert tracker.add_ttp_to_actor("NONEXISTENT", "T1059") is False

    def test_find_by_alias(self):
        tracker = ActorTracker()
        tracker.add_actor(ThreatActor(name="APT29", aliases=["Cozy Bear"]))
        tracker.add_actor(ThreatActor(name="APT28", aliases=["Fancy Bear"]))
        results = tracker.find_by_alias("Cozy Bear")
        assert len(results) == 1
        assert results[0].name == "APT29"

    def test_find_by_ttp(self):
        tracker = ActorTracker()
        tracker.add_actor(ThreatActor(name="APT29", ttps=["T1059", "T1078"]))
        tracker.add_actor(ThreatActor(name="APT28", ttps=["T1059"]))
        results = tracker.find_by_ttp("T1059")
        assert len(results) == 2

    def test_find_by_ioc(self):
        tracker = ActorTracker()
        tracker.add_actor(ThreatActor(name="APT29", iocs=["1.2.3.4", "evil.com"]))
        tracker.add_actor(ThreatActor(name="APT28", iocs=["5.6.7.8"]))
        results = tracker.find_by_ioc("1.2.3.4")
        assert len(results) == 1
        assert results[0].name == "APT29"

    def test_all_actors(self):
        tracker = ActorTracker()
        tracker.add_actor(ThreatActor(name="APT29"))
        tracker.add_actor(ThreatActor(name="APT28"))
        assert len(tracker.all_actors()) == 2

    def test_remove_actor(self):
        tracker = ActorTracker()
        tracker.add_actor(ThreatActor(name="APT29"))
        assert tracker.remove_actor("APT29") is True
        assert len(tracker.all_actors()) == 0

    def test_remove_nonexistent_actor(self):
        tracker = ActorTracker()
        assert tracker.remove_actor("NONEXISTENT") is False


# ---------------------------------------------------------------------------
# Intelligence Report & STIX Export
# ---------------------------------------------------------------------------

class TestIntelligenceReport:
    def test_create_report(self):
        report = IntelligenceReport(title="Test Report", tlp=TLP.AMBER)
        assert report.title == "Test Report"
        assert report.tlp == TLP.AMBER
        assert report.id is not None

    def test_report_to_dict(self):
        report = IntelligenceReport(title="Test", tlp=TLP.RED)
        d = report.to_dict()
        assert d["title"] == "Test"
        assert d["tlp"] == "red"
        assert "id" in d

    def test_report_from_dict(self):
        data = {
            "title": "Test Report",
            "tlp": "amber",
            "id": "report-123",
        }
        report = IntelligenceReport.from_dict(data)
        assert report.title == "Test Report"
        assert report.tlp == TLP.AMBER
        assert report.id == "report-123"


class TestSTIXExporter:
    def test_export_ioc(self):
        ioc = IOC(value="1.2.3.4", type=IOCType.IP, tags=["c2"])
        result = STIXExporter.export_ioc(ioc)
        assert result["type"] == "indicator"
        assert "pattern" in result
        assert "1.2.3.4" in result["pattern"]

    def test_export_ttp(self):
        ttp = TTP(technique_id="T1059", tactic="Execution", name="Test")
        result = STIXExporter.export_ttp(ttp)
        assert result["type"] == "attack-pattern"
        assert result["x_mitre_id"] == "T1059"

    def test_export_actor(self):
        actor = ThreatActor(name="APT29", aliases=["Cozy Bear"])
        result = STIXExporter.export_actor(actor)
        assert result["type"] == "threat-actor"
        assert result["name"] == "APT29"

    def test_export_report(self):
        report = IntelligenceReport(
            title="Test Report",
            iocs=[IOC(value="1.2.3.4", type=IOCType.IP)],
            ttps=[TTP(technique_id="T1059", tactic="Execution", name="Test")],
            actors=[ThreatActor(name="APT29")],
        )
        result = STIXExporter.export_report(report)
        assert result["type"] == "bundle"
        assert "objects" in result
        assert len(result["objects"]) == 3


# ---------------------------------------------------------------------------
# TAXII & Sharing
# ---------------------------------------------------------------------------

class TestTAXIICollection:
    def test_create_collection(self):
        col = TAXIICollection(name="test-collection", description="Test")
        assert col.name == "test-collection"
        assert col.description == "Test"

    def test_add_and_get_objects(self):
        col = TAXIICollection(name="test")
        col.add_object({"type": "indicator", "id": "ind-1"})
        col.add_object({"type": "malware", "id": "mal-1"})
        objects = col.get_objects()
        assert len(objects) == 2

    def test_collection_to_dict(self):
        col = TAXIICollection(name="test", description="Desc")
        col.add_object({"type": "indicator"})
        d = col.to_dict()
        assert d["name"] == "test"
        assert len(d["objects"]) == 1


class TestSharingHub:
    def test_create_collection(self):
        hub = SharingHub()
        col = hub.create_collection("test-collection")
        assert col.name == "test-collection"
        assert "test-collection" in hub.list_collections()

    def test_get_collection(self):
        hub = SharingHub()
        hub.create_collection("test")
        col = hub.get_collection("test")
        assert col is not None
        assert col.name == "test"

    def test_get_nonexistent_collection(self):
        hub = SharingHub()
        assert hub.get_collection("nonexistent") is None

    def test_share_report(self):
        hub = SharingHub()
        hub.create_collection("test")
        report = IntelligenceReport(
            title="Test",
            iocs=[IOC(value="1.2.3.4", type=IOCType.IP)],
        )
        assert hub.share_report(report, "test") is True
        col = hub.get_collection("test")
        assert len(col.get_objects()) == 1

    def test_share_report_nonexistent_collection(self):
        hub = SharingHub()
        report = IntelligenceReport(title="Test")
        assert hub.share_report(report, "nonexistent") is False

    def test_set_and_get_tlp(self):
        hub = SharingHub()
        hub.create_collection("test")
        hub.set_tlp("test", TLP.RED)
        assert hub.get_tlp("test") == TLP.RED

    def test_get_tlp_nonexistent_collection(self):
        hub = SharingHub()
        assert hub.get_tlp("nonexistent") is None

    def test_tlp_enforcement(self):
        hub = SharingHub()
        hub.create_collection("secret")
        hub.set_tlp("secret", TLP.RED)
        report = IntelligenceReport(title="Secret", tlp=TLP.RED)
        assert hub.share_report(report, "secret") is True

    def test_tlp_blocks_higher_classification(self):
        hub = SharingHub()
        hub.create_collection("public")
        hub.set_tlp("public", TLP.GREEN)
        report = IntelligenceReport(title="Secret", tlp=TLP.RED)
        assert hub.share_report(report, "public") is False
