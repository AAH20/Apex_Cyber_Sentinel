"""Tests for Adaptive Deception — adaptive honeypots, dynamic decoys, engagement analytics."""
import pytest
from datetime import datetime, timedelta
from src.cyber.adaptive_deception import (
    AdaptiveHoneypot,
    AdaptiveHoneypotConfig,
    DynamicDecoyGenerator,
    DecoyTemplate,
    EngagementAnalytics,
    EngagementRecord,
    AdaptationLevel,
    DecoyFormat,
    RiskLevel,
)


# ─── Fixtures ───────────────────────────────────────────────────────────────

@pytest.fixture
def adaptive_hp():
    return AdaptiveHoneypot(
        hp_id="ahp-001",
        hp_type="ssh",
        port=2222,
        config=AdaptiveHoneypotConfig(
            adaptation_rate=0.1,
            escalation_threshold=5,
            de_escalation_threshold=2,
            max_adaptation_level=1.0,
        ),
    )


@pytest.fixture
def decoy_gen():
    return DynamicDecoyGenerator(seed=42)


@pytest.fixture
def analytics():
    return EngagementAnalytics()


@pytest.fixture
def sample_engagement():
    return EngagementRecord(
        session_id="sess-001",
        source_ip="192.168.1.100",
        honeypot_id="ahp-001",
        start_time=datetime(2026, 1, 1, 12, 0),
        interactions=[
            {"type": "login", "timestamp": "2026-01-01T12:00:01"},
            {"type": "command", "timestamp": "2026-01-01T12:00:05"},
            {"type": "file_access", "timestamp": "2026-01-01T12:01:00"},
        ],
        iocs=["10.0.0.1", "evil.com"],
    )


# ─── Adaptive Honeypot ─────────────────────────────────────────────────────

class TestAdaptiveHoneypot:
    """Tests for adaptive honeypot behavior."""

    def test_adaptive_honeypot_creation(self, adaptive_hp):
        assert adaptive_hp.hp_id == "ahp-001"
        assert adaptive_hp.hp_type == "ssh"
        assert adaptive_hp.port == 2222
        assert adaptive_hp.adaptation_level == 0.0
        assert adaptive_hp.interaction_count == 0

    def test_adaptive_honeypot_deploy(self, adaptive_hp):
        adaptive_hp.deploy()
        assert adaptive_hp.status == "active"
        assert adaptive_hp.is_listening() is True

    def test_adaptation_level_increase(self, adaptive_hp):
        adaptive_hp.deploy()
        for i in range(3):
            adaptive_hp.record_interaction("login", {"user": "admin"})
        assert adaptive_hp.adaptation_level > 0.0
        assert adaptive_hp.interaction_count == 3

    def test_adaptation_level_capped(self, adaptive_hp):
        adaptive_hp.deploy()
        for i in range(20):
            adaptive_hp.record_interaction("cmd", {"cmd": "ls"})
        assert adaptive_hp.adaptation_level <= 1.0

    def test_escalation_triggered(self, adaptive_hp):
        adaptive_hp.deploy()
        for i in range(6):
            adaptive_hp.record_interaction("login", {"user": "admin"})
        assert adaptive_hp.should_escalate() is True

    def test_no_escalation_below_threshold(self, adaptive_hp):
        adaptive_hp.deploy()
        for i in range(2):
            adaptive_hp.record_interaction("login", {"user": "admin"})
        assert adaptive_hp.should_escalate() is False

    def test_de_escalation(self, adaptive_hp):
        adaptive_hp.deploy()
        for i in range(6):
            adaptive_hp.record_interaction("login", {"user": "admin"})
        assert adaptive_hp.should_escalate() is True
        adaptive_hp.de_escalate()
        assert adaptive_hp.adaptation_level < 1.0

    def test_behavior_profile(self, adaptive_hp):
        adaptive_hp.deploy()
        adaptive_hp.record_interaction("login", {"user": "admin"})
        adaptive_hp.record_interaction("login", {"user": "root"})
        adaptive_hp.record_interaction("command", {"cmd": "ls"})
        profile = adaptive_hp.get_behavior_profile()
        assert profile["total_interactions"] == 3
        assert profile["unique_users"] == 2
        assert "login" in profile["interaction_types"]
        assert "command" in profile["interaction_types"]

    def test_adaptation_score_calculation(self, adaptive_hp):
        adaptive_hp.deploy()
        adaptive_hp.record_interaction("login", {"user": "admin"})
        score = adaptive_hp.get_adaptation_score()
        assert 0.0 <= score <= 1.0

    def test_interaction_history_limit(self, adaptive_hp):
        adaptive_hp.deploy()
        for i in range(150):
            adaptive_hp.record_interaction("cmd", {"cmd": f"cmd{i}"})
        assert len(adaptive_hp.interaction_history) <= 100

    def test_honeypot_without_deploy_raises(self, adaptive_hp):
        with pytest.raises(RuntimeError, match="not deployed"):
            adaptive_hp.record_interaction("login", {"user": "admin"})

    def test_get_adaptation_level_enum(self, adaptive_hp):
        adaptive_hp.deploy()
        for i in range(10):
            adaptive_hp.record_interaction("cmd", {"cmd": "ls"})
        level = adaptive_hp.get_adaptation_level()
        assert isinstance(level, AdaptationLevel)


# ─── Dynamic Decoy Generation ──────────────────────────────────────────────

class TestDynamicDecoyGenerator:
    """Tests for dynamic decoy generation."""

    def test_generate_credential_decoy(self, decoy_gen):
        decoy = decoy_gen.generate_credential_decoy("dec-001")
        assert decoy.decoy_id == "dec-001"
        assert decoy.decoy_type.value == "credential"
        assert ":" in decoy.content
        assert decoy.realism_score > 0.0

    def test_generate_file_decoy(self, decoy_gen):
        decoy = decoy_gen.generate_file_decoy("dec-002", "config.ini")
        assert decoy.decoy_id == "dec-002"
        assert decoy.decoy_type.value == "file"
        assert len(decoy.content) > 0

    def test_generate_service_decoy(self, decoy_gen):
        decoy = decoy_gen.generate_service_decoy("dec-003", "ssh")
        assert decoy.decoy_id == "dec-003"
        assert decoy.decoy_type.value == "service"
        assert "ssh" in decoy.content.lower() or "SSH" in decoy.content

    def test_generate_database_decoy(self, decoy_gen):
        decoy = decoy_gen.generate_database_decoy("dec-004", "users")
        assert decoy.decoy_id == "dec-004"
        assert decoy.decoy_type.value == "database"
        assert len(decoy.content) > 0

    def test_decoy_diversity(self, decoy_gen):
        decoys = [decoy_gen.generate_credential_decoy(f"dec-{i}") for i in range(10)]
        contents = [d.content for d in decoys]
        assert len(set(contents)) > 1  # Not all identical

    def test_generate_from_template(self, decoy_gen):
        template = DecoyTemplate(
            name="web_login",
            decoy_type="credential",
            format_str="{user}:{pass}",
            user_pool=["admin", "root", "guest"],
            pass_pool=["password123", "admin", "123456"],
        )
        decoy = decoy_gen.generate_from_template("dec-005", template)
        assert decoy.decoy_id == "dec-005"
        assert ":" in decoy.content

    def test_realism_score_distribution(self, decoy_gen):
        decoys = [decoy_gen.generate_credential_decoy(f"dec-{i}") for i in range(20)]
        scores = [d.realism_score for d in decoys]
        assert all(0.0 <= s <= 1.0 for s in scores)
        assert len(set(scores)) > 1  # Varied realism

    def test_rotate_decoys(self, decoy_gen):
        old_decoys = [decoy_gen.generate_credential_decoy(f"old-{i}") for i in range(3)]
        new_decoys = decoy_gen.rotate_decoys(old_decoys, count=5)
        assert len(new_decoys) == 5
        old_ids = {d.decoy_id for d in old_decoys}
        new_ids = {d.decoy_id for d in new_decoys}
        assert old_ids.isdisjoint(new_ids)

    def test_decoy_format_validation(self, decoy_gen):
        decoy = decoy_gen.generate_credential_decoy("dec-006")
        username, password = decoy.parse_credential()
        assert len(username) > 0
        assert len(password) > 0

    def test_generate_multiple_types(self, decoy_gen):
        cred = decoy_gen.generate_credential_decoy("d1")
        file_d = decoy_gen.generate_file_decoy("d2", "secret.txt")
        svc = decoy_gen.generate_service_decoy("d3", "http")
        db = decoy_gen.generate_database_decoy("d4", "customers")
        all_decoys = [cred, file_d, svc, db]
        types = {d.decoy_type for d in all_decoys}
        assert len(types) == 4


# ─── Attacker Engagement Analytics ─────────────────────────────────────────

class TestEngagementAnalytics:
    """Tests for engagement analytics engine."""

    def test_record_engagement(self, analytics, sample_engagement):
        analytics.record_engagement(sample_engagement)
        assert len(analytics.engagements) == 1
        assert analytics.engagements[0].session_id == "sess-001"

    def test_get_engagement_trends(self, analytics):
        for i in range(5):
            eng = EngagementRecord(
                session_id=f"sess-{i}",
                source_ip=f"10.0.0.{i}",
                honeypot_id="ahp-001",
                start_time=datetime(2026, 1, 1, 12, 0) + timedelta(hours=i),
                interactions=[{"type": "login", "timestamp": "2026-01-01T12:00:00"}],
            )
            analytics.record_engagement(eng)
        trends = analytics.get_engagement_trends()
        assert trends["total_engagements"] == 5
        assert trends["total_interactions"] == 5

    def test_get_top_attackers(self, analytics):
        for i in range(3):
            eng = EngagementRecord(
                session_id=f"sess-{i}",
                source_ip=f"10.0.0.{i}",
                honeypot_id="ahp-001",
                start_time=datetime(2026, 1, 1, 12, 0),
                interactions=[{"type": "cmd", "timestamp": "2026-01-01T12:00:00"}] * (i + 1),
            )
            analytics.record_engagement(eng)
        top = analytics.get_top_attackers(n=2)
        assert len(top) == 2
        assert top[0]["interaction_count"] >= top[1]["interaction_count"]

    def test_get_honeypot_effectiveness(self, analytics):
        for i in range(4):
            eng = EngagementRecord(
                session_id=f"sess-{i}",
                source_ip=f"10.0.0.{i}",
                honeypot_id=f"ahp-{i % 2}",
                start_time=datetime(2026, 1, 1, 12, 0),
                interactions=[{"type": "login", "timestamp": "2026-01-01T12:00:00"}],
            )
            analytics.record_engagement(eng)
        effectiveness = analytics.get_honeypot_effectiveness()
        assert "ahp-0" in effectiveness
        assert "ahp-1" in effectiveness
        assert effectiveness["ahp-0"]["engagement_count"] == 2

    def test_get_temporal_patterns(self, analytics):
        for i in range(6):
            eng = EngagementRecord(
                session_id=f"sess-{i}",
                source_ip=f"10.0.0.{i}",
                honeypot_id="ahp-001",
                start_time=datetime(2026, 1, 1, 12, 0) + timedelta(hours=i),
                interactions=[{"type": "login", "timestamp": "2026-01-01T12:00:00"}],
            )
            analytics.record_engagement(eng)
        patterns = analytics.get_temporal_patterns()
        assert "hourly_distribution" in patterns
        assert len(patterns["hourly_distribution"]) > 0

    def test_get_attack_vectors(self, analytics):
        eng = EngagementRecord(
            session_id="sess-001",
            source_ip="10.0.0.1",
            honeypot_id="ahp-001",
            start_time=datetime(2026, 1, 1, 12, 0),
            interactions=[
                {"type": "login", "timestamp": "2026-01-01T12:00:00"},
                {"type": "command", "timestamp": "2026-01-01T12:00:05"},
                {"type": "login", "timestamp": "2026-01-01T12:00:10"},
            ],
        )
        analytics.record_engagement(eng)
        vectors = analytics.get_attack_vectors()
        assert vectors["login"] == 2
        assert vectors["command"] == 1

    def test_get_risk_score(self, analytics, sample_engagement):
        analytics.record_engagement(sample_engagement)
        risk = analytics.get_risk_score("sess-001")
        assert 0.0 <= risk <= 1.0

    def test_risk_level_classification(self, analytics, sample_engagement):
        analytics.record_engagement(sample_engagement)
        level = analytics.get_risk_level("sess-001")
        assert isinstance(level, RiskLevel)

    def test_generate_analytics_report(self, analytics):
        for i in range(3):
            eng = EngagementRecord(
                session_id=f"sess-{i}",
                source_ip=f"10.0.0.{i}",
                honeypot_id="ahp-001",
                start_time=datetime(2026, 1, 1, 12, 0),
                interactions=[{"type": "login", "timestamp": "2026-01-01T12:00:00"}],
                iocs=["10.0.0.1"],
            )
            analytics.record_engagement(eng)
        report = analytics.generate_analytics_report()
        assert report["total_engagements"] == 3
        assert report["total_interactions"] == 3
        assert report["unique_ips"] == 3
        assert "generated_at" in report

    def test_get_retention_rate(self, analytics):
        for i in range(4):
            eng = EngagementRecord(
                session_id=f"sess-{i}",
                source_ip=f"10.0.0.{i}",
                honeypot_id="ahp-001",
                start_time=datetime(2026, 1, 1, 12, 0),
                interactions=[{"type": "login", "timestamp": "2026-01-01T12:00:00"}] * (i + 1),
            )
            analytics.record_engagement(eng)
        retention = analytics.get_retention_rate()
        assert 0.0 <= retention <= 1.0

    def test_get_conversion_funnel(self, analytics):
        eng = EngagementRecord(
            session_id="sess-001",
            source_ip="10.0.0.1",
            honeypot_id="ahp-001",
            start_time=datetime(2026, 1, 1, 12, 0),
            interactions=[
                {"type": "login", "timestamp": "2026-01-01T12:00:00"},
                {"type": "command", "timestamp": "2026-01-01T12:00:05"},
                {"type": "file_access", "timestamp": "2026-01-01T12:01:00"},
            ],
        )
        analytics.record_engagement(eng)
        funnel = analytics.get_conversion_funnel()
        assert "login" in funnel
        assert "command" in funnel
        assert "file_access" in funnel

    def test_empty_analytics_report(self, analytics):
        report = analytics.generate_analytics_report()
        assert report["total_engagements"] == 0
        assert report["total_interactions"] == 0

    def test_ioc_extraction(self, analytics, sample_engagement):
        analytics.record_engagement(sample_engagement)
        iocs = analytics.get_all_iocs()
        assert "10.0.0.1" in iocs
        assert "evil.com" in iocs

    def test_engagement_duration_stats(self, analytics):
        for i in range(3):
            eng = EngagementRecord(
                session_id=f"sess-{i}",
                source_ip=f"10.0.0.{i}",
                honeypot_id="ahp-001",
                start_time=datetime(2026, 1, 1, 12, 0),
                end_time=datetime(2026, 1, 1, 12, 0) + timedelta(minutes=i * 5),
                interactions=[{"type": "login", "timestamp": "2026-01-01T12:00:00"}],
            )
            analytics.record_engagement(eng)
        stats = analytics.get_duration_stats()
        assert stats["count"] == 3
        assert stats["mean"] > 0
