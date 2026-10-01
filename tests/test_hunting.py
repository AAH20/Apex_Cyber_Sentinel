"""Unit tests for autonomous threat hunting module."""

import pytest

from src.cyber.hunting import (
    HypothesisStatus,
    IOCType,
    Indicator,
    Severity,
    ThreatHunter,
    TTP,
    calculate_risk_score,
    classify_ioc,
    is_domain,
    is_email,
    is_hash,
    is_ip_address,
    is_url,
    normalize_ioc,
)


# ── IOC classification ──────────────────────────────────────────────

class TestClassifyIOC:
    def test_classify_ioc_ip(self):
        assert classify_ioc("192.168.1.1") == IOCType.IP

    def test_classify_ioc_ip_public(self):
        assert classify_ioc("8.8.8.8") == IOCType.IP

    def test_classify_ioc_domain(self):
        assert classify_ioc("evil.example.com") == IOCType.DOMAIN

    def test_classify_ioc_hash_md5(self):
        assert classify_ioc("d41d8cd98f00b204e9800998ecf8427e") == IOCType.HASH

    def test_classify_ioc_hash_sha256(self):
        h = "a" * 64
        assert classify_ioc(h) == IOCType.HASH

    def test_classify_ioc_url(self):
        assert classify_ioc("http://evil.com/payload") == IOCType.URL

    def test_classify_ioc_email(self):
        assert classify_ioc("attacker@evil.com") == IOCType.EMAIL

    def test_classify_ioc_unknown(self):
        assert classify_ioc("not-an-ioc") == IOCType.UNKNOWN


# ── IOC validation helpers ───────────────────────────────────────────

class TestIOCValidators:
    def test_is_ip_address_valid(self):
        assert is_ip_address("10.0.0.1") is True

    def test_is_ip_address_invalid(self):
        assert is_ip_address("999.999.999.999") is False

    def test_is_domain_valid(self):
        assert is_domain("sub.example.com") is True

    def test_is_domain_invalid(self):
        assert is_domain("not_a_domain") is False

    def test_is_hash_valid(self):
        assert is_hash("d41d8cd98f00b204e9800998ecf8427e") is True

    def test_is_hash_invalid(self):
        assert is_hash("abc123") is False

    def test_is_url_valid(self):
        assert is_url("https://example.com") is True

    def test_is_url_invalid(self):
        assert is_url("example.com") is False

    def test_is_email_valid(self):
        assert is_email("user@example.com") is True

    def test_is_email_invalid(self):
        assert is_email("not-an-email") is False


# ── IOC normalization ────────────────────────────────────────────────

class TestNormalizeIOC:
    def test_normalize_ioc_domain(self):
        assert normalize_ioc("  Evil.COM  ", IOCType.DOMAIN) == "evil.com"

    def test_normalize_ioc_url(self):
        assert normalize_ioc("http://evil.com/path/", IOCType.URL) == "http://evil.com/path"

    def test_normalize_ioc_hash(self):
        assert normalize_ioc("D41D8CD98F00B204E9800998ECF8427E", IOCType.HASH) == "d41d8cd98f00b204e9800998ecf8427e"


# ── ThreatHunter IOC matching ────────────────────────────────────────

class TestThreatHunterIOC:
    def test_add_and_match_ioc(self):
        hunter = ThreatHunter()
        hunter.add_ioc(Indicator("1.2.3.4", IOCType.IP, Severity.HIGH))
        matches = hunter.match_ioc("1.2.3.4")
        assert len(matches) == 1
        assert matches[0].value == "1.2.3.4"

    def test_match_ioc_case_insensitive(self):
        hunter = ThreatHunter()
        hunter.add_ioc(Indicator("evil.com", IOCType.DOMAIN))
        matches = hunter.match_ioc("EVIL.COM")
        assert len(matches) == 1

    def test_match_ioc_by_type_filter(self):
        hunter = ThreatHunter()
        hunter.add_ioc(Indicator("1.2.3.4", IOCType.IP))
        hunter.add_ioc(Indicator("evil.com", IOCType.DOMAIN))
        matches = hunter.match_ioc("1.2.3.4", IOCType.IP)
        assert len(matches) == 1
        assert matches[0].ioc_type == IOCType.IP

    def test_match_ioc_no_match(self):
        hunter = ThreatHunter()
        hunter.add_ioc(Indicator("1.2.3.4", IOCType.IP))
        matches = hunter.match_ioc("5.6.7.8")
        assert len(matches) == 0

    def test_empty_ioc_list(self):
        hunter = ThreatHunter()
        matches = hunter.match_ioc("1.2.3.4")
        assert len(matches) == 0


# ── TTP detection ────────────────────────────────────────────────────

class TestTTPDetection:
    def test_detect_ttp(self):
        hunter = ThreatHunter()
        hunter.add_ttp(TTP(
            tactic="Initial Access",
            technique_id="T1566",
            technique_name="Phishing",
            event_patterns=["phishing", "suspicious email"],
        ))
        event = {"message": "received a phishing email from unknown sender"}
        matched = hunter.detect_ttp(event)
        assert len(matched) == 1
        assert matched[0].technique_id == "T1566"

    def test_detect_ttp_no_match(self):
        hunter = ThreatHunter()
        hunter.add_ttp(TTP(
            tactic="Initial Access",
            technique_id="T1566",
            technique_name="Phishing",
            event_patterns=["phishing"],
        ))
        event = {"message": "normal system boot"}
        matched = hunter.detect_ttp(event)
        assert len(matched) == 0


# ── Hypothesis testing ───────────────────────────────────────────────

class TestHypothesisTesting:
    def test_create_hypothesis(self):
        hunter = ThreatHunter()
        h = hunter.create_hypothesis("Test hypothesis")
        assert h.description == "Test hypothesis"
        assert h.status == HypothesisStatus.OPEN
        assert h.confidence == 0.0

    def test_test_hypothesis_confirmed(self):
        hunter = ThreatHunter()
        hunter.add_ioc(Indicator("10.0.0.1", IOCType.IP, Severity.CRITICAL))
        h = hunter.create_hypothesis("Check for C2 communication")
        events = [{"src_ip": "10.0.0.1", "dst_ip": "192.168.1.1"}]
        result = hunter.test_hypothesis(h, events)
        assert result.hypothesis.status == HypothesisStatus.CONFIRMED
        assert result.hypothesis.confidence > 0.0
        assert len(result.matched_iocs) == 1
        assert len(result.findings) > 0

    def test_test_hypothesis_rejected(self):
        hunter = ThreatHunter()
        h = hunter.create_hypothesis("Check for C2 communication")
        events = [{"src_ip": "192.168.1.1", "dst_ip": "10.0.0.1"}]
        result = hunter.test_hypothesis(h, events)
        assert result.hypothesis.status == HypothesisStatus.REJECTED
        assert result.hypothesis.confidence == 0.0


# ── Proactive hunt ───────────────────────────────────────────────────

class TestProactiveHunt:
    def test_hunt_proactive(self):
        hunter = ThreatHunter()
        hunter.add_ioc(Indicator("bad.com", IOCType.DOMAIN, Severity.HIGH))
        hunter.add_ttp(TTP(
            tactic="Command and Control",
            technique_id="T1071",
            technique_name="Application Layer Protocol",
            event_patterns=["dns tunnel", "beacon"],
        ))
        events = [
            {"domain": "bad.com", "action": "dns query"},
            {"message": "detected dns tunnel activity"},
        ]
        results = hunter.hunt(events)
        assert len(results) > 0
        confirmed = [r for r in results if r.hypothesis.status == HypothesisStatus.CONFIRMED]
        assert len(confirmed) > 0

    def test_hunt_no_events(self):
        hunter = ThreatHunter()
        results = hunter.hunt([])
        assert len(results) == 0


# ── Risk scoring ─────────────────────────────────────────────────────

class TestRiskScoring:
    def test_calculate_risk_score_empty(self):
        assert calculate_risk_score([], []) == 0.0

    def test_calculate_risk_score_with_iocs(self):
        hunter = ThreatHunter()
        iocs = [
            Indicator("1.2.3.4", IOCType.IP, Severity.LOW),
            Indicator("5.6.7.8", IOCType.IP, Severity.CRITICAL),
        ]
        score = hunter.calculate_risk_score(iocs, [])
        assert 0.0 < score <= 1.0

    def test_calculate_risk_score_capped(self):
        hunter = ThreatHunter()
        iocs = [Indicator(f"10.0.0.{i}", IOCType.IP, Severity.CRITICAL) for i in range(10)]
        score = hunter.calculate_risk_score(iocs, [])
        assert score == 1.0


# ── Multi-IOC events ─────────────────────────────────────────────────

class TestMultiIOCEvents:
    def test_multiple_ioc_types_in_event(self):
        hunter = ThreatHunter()
        hunter.add_ioc(Indicator("evil.com", IOCType.DOMAIN, Severity.HIGH))
        hunter.add_ioc(Indicator("d41d8cd98f00b204e9800998ecf8427e", IOCType.HASH, Severity.CRITICAL))
        event = {
            "domain": "evil.com",
            "file_hash": "d41d8cd98f00b204e9800998ecf8427e",
            "src_ip": "192.168.1.1",
        }
        h = hunter.create_hypothesis("Multi-IOC investigation")
        result = hunter.test_hypothesis(h, [event])
        assert result.hypothesis.status == HypothesisStatus.CONFIRMED
        assert len(result.matched_iocs) == 2
