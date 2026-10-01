"""Tests for Deception Grid — honeypots, decoys, attacker engagement, intel collection."""
import pytest
from datetime import datetime, timedelta
from src.cyber.deception import (
    Honeypot,
    Decoy,
    AttackerEngagement,
    IntelligenceCollector,
    DeceptionGrid,
    HoneypotStatus,
    DecoyType,
    EngagementLevel,
    IOCType,
    deploy_honeypot,
    generate_decoy,
    engage_attacker,
    collect_intelligence,
)


# ─── Fixtures ───────────────────────────────────────────────────────────────

@pytest.fixture
def honeypot():
    return Honeypot(
        hp_id="hp-001",
        hp_type="ssh",
        port=2222,
    )


@pytest.fixture
def decoy():
    return Decoy(
        decoy_id="dec-001",
        decoy_type=DecoyType.CREDENTIAL,
        content="admin:SuperSecret123!",
        realism_score=0.85,
    )


@pytest.fixture
def engagement():
    return AttackerEngagement(
        session_id="sess-001",
        source_ip="192.168.1.100",
        honeypot_id="hp-001",
        start_time=datetime(2026, 1, 1, 12, 0),
    )


@pytest.fixture
def intel_collector():
    return IntelligenceCollector()


@pytest.fixture
def grid():
    return DeceptionGrid()


# ─── Honeypot Deployment ───────────────────────────────────────────────────

class TestHoneypotDeployment:
    """Tests for honeypot creation and deployment."""

    def test_honeypot_creation(self, honeypot):
        assert honeypot.hp_id == "hp-001"
        assert honeypot.hp_type == "ssh"
        assert honeypot.port == 2222
        assert honeypot.status == HoneypotStatus.INACTIVE

    def test_honeypot_default_status(self):
        hp = Honeypot(hp_id="hp-002", hp_type="http", port=8080)
        assert hp.status == HoneypotStatus.INACTIVE

    def test_honeypot_deploy(self, honeypot):
        honeypot.deploy()
        assert honeypot.status == HoneypotStatus.ACTIVE
        assert honeypot.deployed_at is not None

    def test_honeypot_already_deployed(self, honeypot):
        honeypot.deploy()
        with pytest.raises(RuntimeError, match="already deployed"):
            honeypot.deploy()

    def test_honeypot_shutdown(self, honeypot):
        honeypot.deploy()
        honeypot.shutdown()
        assert honeypot.status == HoneypotStatus.INACTIVE

    def test_honeypot_shutdown_not_deployed(self, honeypot):
        with pytest.raises(RuntimeError, match="not deployed"):
            honeypot.shutdown()

    def test_honeypot_is_listening(self, honeypot):
        honeypot.deploy()
        assert honeypot.is_listening() is True

    def test_honeypot_not_listening_when_inactive(self, honeypot):
        assert honeypot.is_listening() is False

    def test_deploy_honeypot_function(self):
        hp = deploy_honeypot("hp-003", "ftp", 2121)
        assert hp.hp_id == "hp-003"
        assert hp.hp_type == "ftp"
        assert hp.port == 2121
        assert hp.status == HoneypotStatus.ACTIVE


# ─── Decoy Generation ──────────────────────────────────────────────────────

class TestDecoyGeneration:
    """Tests for decoy creation and generation."""

    def test_decoy_creation(self, decoy):
        assert decoy.decoy_id == "dec-001"
        assert decoy.decoy_type == DecoyType.CREDENTIAL
        assert decoy.content == "admin:SuperSecret123!"
        assert decoy.realism_score == 0.85

    def test_decoy_default_realism(self):
        d = Decoy(decoy_id="dec-002", decoy_type=DecoyType.FILE, content="secret.txt")
        assert d.realism_score == 0.5

    def test_generate_decoy_function(self):
        d = generate_decoy("dec-003", DecoyType.FILE, "config.ini")
        assert d.decoy_id == "dec-003"
        assert d.decoy_type == DecoyType.FILE
        assert d.content == "config.ini"

    def test_decoy_realism_score_validation(self):
        with pytest.raises(ValueError, match="realism_score"):
            Decoy(decoy_id="dec-004", decoy_type=DecoyType.FILE, content="x", realism_score=1.5)

    def test_decoy_realism_score_negative(self):
        with pytest.raises(ValueError, match="realism_score"):
            Decoy(decoy_id="dec-005", decoy_type=DecoyType.FILE, content="x", realism_score=-0.1)

    def test_decoy_is_credential(self, decoy):
        assert decoy.is_credential() is True

    def test_decoy_is_not_credential(self):
        d = Decoy(decoy_id="dec-006", decoy_type=DecoyType.FILE, content="readme.txt")
        assert d.is_credential() is False

    def test_decoy_credential_parsing(self, decoy):
        username, password = decoy.parse_credential()
        assert username == "admin"
        assert password == "SuperSecret123!"

    def test_decoy_credential_parsing_invalid(self):
        d = Decoy(decoy_id="dec-007", decoy_type=DecoyType.CREDENTIAL, content="no-colon-here")
        with pytest.raises(ValueError, match="Invalid credential format"):
            d.parse_credential()


# ─── Attacker Engagement ───────────────────────────────────────────────────

class TestAttackerEngagement:
    """Tests for attacker engagement tracking."""

    def test_engagement_creation(self, engagement):
        assert engagement.session_id == "sess-001"
        assert engagement.source_ip == "192.168.1.100"
        assert engagement.honeypot_id == "hp-001"
        assert engagement.interaction_count == 0

    def test_engagement_log_interaction(self, engagement):
        engagement.log_interaction("login attempt", {"user": "admin", "pass": "123"})
        assert engagement.interaction_count == 1
        assert len(engagement.interactions) == 1

    def test_engagement_interaction_details(self, engagement):
        engagement.log_interaction("command", {"cmd": "ls -la"})
        interaction = engagement.interactions[0]
        assert interaction["type"] == "command"
        assert interaction["data"]["cmd"] == "ls -la"
        assert "timestamp" in interaction

    def test_engagement_level_calculation(self, engagement):
        assert engagement.get_engagement_level() == EngagementLevel.LOW
        for i in range(5):
            engagement.log_interaction("cmd", {"cmd": f"cmd{i}"})
        assert engagement.get_engagement_level() == EngagementLevel.MEDIUM
        for i in range(10):
            engagement.log_interaction("cmd", {"cmd": f"cmd{i}"})
        assert engagement.get_engagement_level() == EngagementLevel.HIGH

    def test_engagement_duration(self, engagement):
        end = datetime(2026, 1, 1, 12, 30)
        duration = engagement.get_duration(end)
        assert duration == 1800  # seconds

    def test_engagement_is_active(self, engagement):
        assert engagement.is_active() is True

    def test_engagement_close(self, engagement):
        engagement.close()
        assert engagement.is_active() is False

    def test_engage_attacker_function(self):
        eng = engage_attacker("sess-002", "10.0.0.50", "hp-001")
        assert eng.session_id == "sess-002"
        assert eng.source_ip == "10.0.0.50"
        assert eng.honeypot_id == "hp-001"
        assert eng.is_active() is True


# ─── Intelligence Collection ───────────────────────────────────────────────

class TestIntelligenceCollection:
    """Tests for intelligence collection and IOC management."""

    def test_collector_creation(self, intel_collector):
        assert intel_collector.iocs == []
        assert intel_collector.threat_actors == []

    def test_add_ioc(self, intel_collector):
        intel_collector.add_ioc(IOCType.IP, "192.168.1.100", "sess-001")
        assert len(intel_collector.iocs) == 1
        assert intel_collector.iocs[0]["type"] == IOCType.IP
        assert intel_collector.iocs[0]["value"] == "192.168.1.100"

    def test_add_ioc_with_context(self, intel_collector):
        intel_collector.add_ioc(IOCType.DOMAIN, "evil.com", "sess-001", {"confidence": 0.9})
        assert intel_collector.iocs[0]["context"]["confidence"] == 0.9

    def test_get_iocs_by_type(self, intel_collector):
        intel_collector.add_ioc(IOCType.IP, "1.2.3.4", "sess-001")
        intel_collector.add_ioc(IOCType.DOMAIN, "bad.com", "sess-001")
        intel_collector.add_ioc(IOCType.IP, "5.6.7.8", "sess-002")
        ip_iocs = intel_collector.get_iocs_by_type(IOCType.IP)
        assert len(ip_iocs) == 2

    def test_get_iocs_by_session(self, intel_collector):
        intel_collector.add_ioc(IOCType.IP, "1.2.3.4", "sess-001")
        intel_collector.add_ioc(IOCType.DOMAIN, "bad.com", "sess-002")
        sess_iocs = intel_collector.get_iocs_by_session("sess-001")
        assert len(sess_iocs) == 1
        assert sess_iocs[0]["value"] == "1.2.3.4"

    def test_add_threat_actor(self, intel_collector):
        intel_collector.add_threat_actor("APT-29", ["1.2.3.4", "evil.com"])
        assert len(intel_collector.threat_actors) == 1
        assert intel_collector.threat_actors[0]["name"] == "APT-29"

    def test_threat_actor_has_iocs(self, intel_collector):
        intel_collector.add_threat_actor("APT-29", ["1.2.3.4", "evil.com"])
        assert "1.2.3.4" in intel_collector.threat_actors[0]["iocs"]

    def test_generate_report(self, intel_collector):
        intel_collector.add_ioc(IOCType.IP, "1.2.3.4", "sess-001")
        intel_collector.add_ioc(IOCType.DOMAIN, "bad.com", "sess-001")
        intel_collector.add_threat_actor("APT-29", ["1.2.3.4"])
        report = intel_collector.generate_report()
        assert report["total_iocs"] == 2
        assert report["total_threat_actors"] == 1
        assert "generated_at" in report

    def test_report_empty(self, intel_collector):
        report = intel_collector.generate_report()
        assert report["total_iocs"] == 0
        assert report["total_threat_actors"] == 0

    def test_collect_intelligence_function(self):
        collector = collect_intelligence("sess-001", [
            {"type": IOCType.IP, "value": "1.2.3.4"},
            {"type": IOCType.DOMAIN, "value": "evil.com"},
        ])
        assert len(collector.iocs) == 2


# ─── Deception Grid Orchestration ──────────────────────────────────────────

class TestDeceptionGrid:
    """Tests for the DeceptionGrid orchestrator."""

    def test_grid_creation(self, grid):
        assert grid.honeypots == []
        assert grid.decoys == []
        assert grid.engagements == []

    def test_grid_add_honeypot(self, grid, honeypot):
        grid.add_honeypot(honeypot)
        assert len(grid.honeypots) == 1
        assert grid.honeypots[0].hp_id == "hp-001"

    def test_grid_add_decoy(self, grid, decoy):
        grid.add_decoy(decoy)
        assert len(grid.decoys) == 1
        assert grid.decoys[0].decoy_id == "dec-001"

    def test_grid_add_engagement(self, grid, engagement):
        grid.add_engagement(engagement)
        assert len(grid.engagements) == 1
        assert grid.engagements[0].session_id == "sess-001"

    def test_grid_deploy_all_honeypots(self, grid):
        hp1 = Honeypot(hp_id="hp-001", hp_type="ssh", port=2222)
        hp2 = Honeypot(hp_id="hp-002", hp_type="http", port=8080)
        grid.add_honeypot(hp1)
        grid.add_honeypot(hp2)
        grid.deploy_all()
        assert all(hp.status == HoneypotStatus.ACTIVE for hp in grid.honeypots)

    def test_grid_shutdown_all_honeypots(self, grid):
        hp1 = Honeypot(hp_id="hp-001", hp_type="ssh", port=2222, status=HoneypotStatus.ACTIVE)
        hp1.deployed_at = datetime.now()
        grid.add_honeypot(hp1)
        grid.shutdown_all()
        assert hp1.status == HoneypotStatus.INACTIVE

    def test_grid_get_active_honeypots(self, grid):
        hp1 = Honeypot(hp_id="hp-001", hp_type="ssh", port=2222, status=HoneypotStatus.ACTIVE)
        hp1.deployed_at = datetime.now()
        hp2 = Honeypot(hp_id="hp-002", hp_type="http", port=8080)
        grid.add_honeypot(hp1)
        grid.add_honeypot(hp2)
        active = grid.get_active_honeypots()
        assert len(active) == 1
        assert active[0].hp_id == "hp-001"

    def test_grid_get_engagement_metrics(self, grid):
        eng1 = AttackerEngagement(
            session_id="sess-001", source_ip="10.0.0.1", honeypot_id="hp-001",
            start_time=datetime(2026, 1, 1, 12, 0),
        )
        eng1.log_interaction("cmd", {"cmd": "ls"})
        eng2 = AttackerEngagement(
            session_id="sess-002", source_ip="10.0.0.2", honeypot_id="hp-001",
            start_time=datetime(2026, 1, 1, 12, 0),
        )
        grid.add_engagement(eng1)
        grid.add_engagement(eng2)
        metrics = grid.get_engagement_metrics()
        assert metrics["total_engagements"] == 2
        assert metrics["total_interactions"] == 1
        assert metrics["unique_ips"] == 2

    def test_grid_generate_alert(self, grid, engagement):
        engagement.log_interaction("login", {"user": "admin"})
        engagement.log_interaction("cmd", {"cmd": "cat /etc/passwd"})
        alert = grid.generate_alert(engagement)
        assert alert["severity"] == "HIGH"
        assert alert["source_ip"] == "192.168.1.100"
        assert alert["session_id"] == "sess-001"

    def test_grid_generate_alert_low_severity(self, grid):
        eng = AttackerEngagement(
            session_id="sess-003", source_ip="10.0.0.99", honeypot_id="hp-001",
            start_time=datetime(2026, 1, 1, 12, 0),
        )
        alert = grid.generate_alert(eng)
        assert alert["severity"] == "LOW"

    def test_grid_full_pipeline(self, grid):
        hp = deploy_honeypot("hp-001", "ssh", 2222)
        grid.add_honeypot(hp)
        d = generate_decoy("dec-001", DecoyType.CREDENTIAL, "admin:pass123")
        grid.add_decoy(d)
        eng = engage_attacker("sess-001", "10.0.0.50", "hp-001")
        eng.log_interaction("login", {"user": "admin"})
        grid.add_engagement(eng)
        assert len(grid.honeypots) == 1
        assert len(grid.decoys) == 1
        assert len(grid.engagements) == 1
        assert grid.honeypots[0].status == HoneypotStatus.ACTIVE
