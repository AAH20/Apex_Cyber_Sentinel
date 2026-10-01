"""Tests for attack graph generation, vulnerability scanning, and exploit chain detection."""
import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from cyber.attack_gen import (
    Vulnerability,
    Host,
    ExploitStep,
    ExploitChain,
    VulnerabilityScanner,
    AttackGraphGenerator,
    ExploitChainDetector,
)
from cyber.attack_graph import AttackGraph


# ─── Fixtures ───────────────────────────────────────────────────────────────

@pytest.fixture
def sample_vulns():
    return [
        Vulnerability("CVE-2024-6387", 9.8, 0.95, "ssh", 22),
        Vulnerability("CVE-2023-48795", 5.9, 0.7, "ssh", 22),
    ]


@pytest.fixture
def sample_hosts():
    return [
        Host("web1", "10.0.0.1", "linux", {"http": 80, "ssh": 22}, is_entry_point=True),
        Host("db1", "10.0.0.2", "linux", {"mysql": 3306, "ssh": 22}, is_critical=True),
        Host("app1", "10.0.0.3", "linux", {"http": 80, "redis": 6379}),
    ]


@pytest.fixture
def sample_connections():
    return [("web1", "app1"), ("app1", "db1")]


@pytest.fixture
def scanner():
    return VulnerabilityScanner()


@pytest.fixture
def populated_hosts(sample_hosts, scanner):
    hosts = [Host(h.host_id, h.ip, h.os, dict(h.services), is_critical=h.is_critical, is_entry_point=h.is_entry_point) for h in sample_hosts]
    scanner.scan_network(hosts)
    return hosts


# ─── Vulnerability Tests ────────────────────────────────────────────────────

class TestVulnerability:
    def test_create_vulnerability(self):
        v = Vulnerability("CVE-2024-6387", 9.8, 0.95, "ssh", 22)
        assert v.cve_id == "CVE-2024-6387"
        assert v.cvss_score == 9.8
        assert v.exploitability == 0.95
        assert v.service == "ssh"
        assert v.port == 22

    def test_severity_critical(self):
        v = Vulnerability("CVE-2024-6387", 9.8, 0.95, "ssh", 22)
        assert v.severity == "critical"

    def test_severity_high(self):
        v = Vulnerability("CVE-2023-48795", 7.5, 0.7, "ssh", 22)
        assert v.severity == "high"

    def test_severity_medium(self):
        v = Vulnerability("CVE-2023-48795", 5.9, 0.7, "ssh", 22)
        assert v.severity == "medium"

    def test_severity_low(self):
        v = Vulnerability("CVE-2023-48795", 3.0, 0.3, "ssh", 22)
        assert v.severity == "low"

    def test_invalid_cvss_score(self):
        with pytest.raises(ValueError):
            Vulnerability("CVE-2024-6387", 11.0, 0.5, "ssh", 22)

    def test_invalid_exploitability(self):
        with pytest.raises(ValueError):
            Vulnerability("CVE-2024-6387", 5.0, 1.5, "ssh", 22)

    def test_to_dict(self):
        v = Vulnerability("CVE-2024-6387", 9.8, 0.95, "ssh", 22, "Test vuln")
        d = v.to_dict()
        assert d["cve_id"] == "CVE-2024-6387"
        assert d["cvss_score"] == 9.8
        assert d["description"] == "Test vuln"

    def test_from_dict(self):
        d = {"cve_id": "CVE-2024-6387", "cvss_score": 9.8, "exploitability": 0.95, "service": "ssh", "port": 22}
        v = Vulnerability.from_dict(d)
        assert v.cve_id == "CVE-2024-6387"
        assert v.cvss_score == 9.8


# ─── Host Tests ─────────────────────────────────────────────────────────────

class TestHost:
    def test_create_host(self):
        h = Host("web1", "10.0.0.1", "linux", {"http": 80})
        assert h.host_id == "web1"
        assert h.ip == "10.0.0.1"
        assert h.os == "linux"
        assert h.services == {"http": 80}

    def test_add_vulnerability(self):
        h = Host("web1", "10.0.0.1")
        v = Vulnerability("CVE-2024-6387", 9.8, 0.95, "ssh", 22)
        h.add_vulnerability(v)
        assert len(h.vulnerabilities) == 1
        assert h.vulnerabilities[0].cve_id == "CVE-2024-6387"

    def test_get_vulnerabilities_by_severity(self):
        h = Host("web1", "10.0.0.1")
        h.add_vulnerability(Vulnerability("CVE-2024-6387", 9.8, 0.95, "ssh", 22))
        h.add_vulnerability(Vulnerability("CVE-2023-48795", 5.9, 0.7, "ssh", 22))
        critical = h.get_vulnerabilities_by_severity("critical")
        assert len(critical) == 1
        assert critical[0].cvss_score == 9.8

    def test_get_max_cvss(self):
        h = Host("web1", "10.0.0.1")
        h.add_vulnerability(Vulnerability("CVE-2024-6387", 9.8, 0.95, "ssh", 22))
        h.add_vulnerability(Vulnerability("CVE-2023-48795", 5.9, 0.7, "ssh", 22))
        assert h.get_max_cvss() == 9.8

    def test_get_max_cvss_empty(self):
        h = Host("web1", "10.0.0.1")
        assert h.get_max_cvss() == 0.0

    def test_to_dict(self):
        h = Host("web1", "10.0.0.1", "linux", {"http": 80}, is_critical=True)
        d = h.to_dict()
        assert d["host_id"] == "web1"
        assert d["is_critical"] is True
        assert d["services"] == {"http": 80}

    def test_from_dict(self):
        d = {"host_id": "web1", "ip": "10.0.0.1", "os": "linux", "services": {"http": 80}, "is_critical": True}
        h = Host.from_dict(d)
        assert h.host_id == "web1"
        assert h.is_critical is True


# ─── VulnerabilityScanner Tests ─────────────────────────────────────────────

class TestVulnerabilityScanner:
    def test_scan_host_with_vulns(self, scanner):
        h = Host("web1", "10.0.0.1", "linux", {"ssh": 22})
        vulns = scanner.scan_host(h)
        assert len(vulns) > 0
        assert all(v.service == "ssh" for v in vulns)

    def test_scan_host_no_vulns(self, scanner):
        h = Host("web1", "10.0.0.1", "linux", {"unknown_service": 9999})
        vulns = scanner.scan_host(h)
        assert len(vulns) == 0

    def test_scan_network(self, scanner, sample_hosts):
        hosts = [Host(h.host_id, h.ip, h.os, dict(h.services)) for h in sample_hosts]
        results = scanner.scan_network(hosts)
        assert len(results) == 3
        assert len(results["web1"]) > 0
        assert len(results["db1"]) > 0

    def test_get_critical_vulnerabilities(self, scanner, populated_hosts):
        critical = scanner.get_critical_vulnerabilities(populated_hosts)
        assert len(critical) > 0
        for host_id, vulns in critical.items():
            assert all(v.severity == "critical" for v in vulns)

    def test_get_high_vulnerabilities(self, scanner, populated_hosts):
        high = scanner.get_high_vulnerabilities(populated_hosts)
        for host_id, vulns in high.items():
            assert all(v.severity == "high" for v in vulns)

    def test_custom_vuln_db(self):
        custom_db = {
            "custom_service": [("CVE-2024-0001", 8.5, 0.8, 8080)],
        }
        scanner = VulnerabilityScanner(vuln_db=custom_db)
        h = Host("test", "10.0.0.1", "linux", {"custom_service": 8080})
        vulns = scanner.scan_host(h)
        assert len(vulns) == 1
        assert vulns[0].cve_id == "CVE-2024-0001"


# ─── AttackGraphGenerator Tests ─────────────────────────────────────────────

class TestAttackGraphGenerator:
    def test_generate_from_topology(self, scanner, populated_hosts, sample_connections):
        gen = AttackGraphGenerator(scanner)
        graph = gen.generate_from_topology(populated_hosts, sample_connections)
        assert graph.node_count() == 3
        assert graph.edge_count() == 2
        assert "web1" in graph.get_nodes()
        assert "db1" in graph.get_nodes()

    def test_node_types(self, scanner, populated_hosts, sample_connections):
        gen = AttackGraphGenerator(scanner)
        graph = gen.generate_from_topology(populated_hosts, sample_connections)
        assert graph.get_node("web1").node_type == "entry"
        assert graph.get_node("db1").node_type == "critical"
        assert graph.get_node("app1").node_type == "host"

    def test_edge_probabilities(self, scanner, populated_hosts, sample_connections):
        gen = AttackGraphGenerator(scanner)
        graph = gen.generate_from_topology(populated_hosts, sample_connections)
        edge = graph.get_edge("web1", "app1")
        assert 0 < edge.probability <= 1.0

    def test_empty_topology(self, scanner):
        gen = AttackGraphGenerator(scanner)
        graph = gen.generate_from_topology([], [])
        assert graph.node_count() == 0
        assert graph.edge_count() == 0

    def test_disconnected_hosts(self, scanner, populated_hosts):
        gen = AttackGraphGenerator(scanner)
        graph = gen.generate_from_topology(populated_hosts, [])
        assert graph.node_count() == 3
        assert graph.edge_count() == 0


# ─── ExploitChainDetector Tests ─────────────────────────────────────────────

class TestExploitChainDetector:
    def test_find_chains(self, scanner, populated_hosts, sample_connections):
        gen = AttackGraphGenerator(scanner)
        graph = gen.generate_from_topology(populated_hosts, sample_connections)
        hosts_dict = {h.host_id: h for h in populated_hosts}
        detector = ExploitChainDetector(graph, hosts_dict)
        chains = detector.find_chains()
        assert len(chains) > 0

    def test_chain_length(self, scanner, populated_hosts, sample_connections):
        gen = AttackGraphGenerator(scanner)
        graph = gen.generate_from_topology(populated_hosts, sample_connections)
        hosts_dict = {h.host_id: h for h in populated_hosts}
        detector = ExploitChainDetector(graph, hosts_dict)
        chains = detector.find_chains()
        for chain in chains:
            assert chain.length >= 1

    def test_chain_probability(self, scanner, populated_hosts, sample_connections):
        gen = AttackGraphGenerator(scanner)
        graph = graph = gen.generate_from_topology(populated_hosts, sample_connections)
        hosts_dict = {h.host_id: h for h in populated_hosts}
        detector = ExploitChainDetector(graph, hosts_dict)
        chains = detector.find_chains()
        for chain in chains:
            assert 0 < chain.total_probability <= 1.0

    def test_get_most_dangerous_chain(self, scanner, populated_hosts, sample_connections):
        gen = AttackGraphGenerator(scanner)
        graph = gen.generate_from_topology(populated_hosts, sample_connections)
        hosts_dict = {h.host_id: h for h in populated_hosts}
        detector = ExploitChainDetector(graph, hosts_dict)
        chains = detector.find_chains()
        dangerous = detector.get_most_dangerous_chain(chains)
        assert dangerous is not None

    def test_get_chains_by_target(self, scanner, populated_hosts, sample_connections):
        gen = AttackGraphGenerator(scanner)
        graph = gen.generate_from_topology(populated_hosts, sample_connections)
        hosts_dict = {h.host_id: h for h in populated_hosts}
        detector = ExploitChainDetector(graph, hosts_dict)
        chains = detector.find_chains()
        db_chains = detector.get_chains_by_target(chains, "db1")
        assert len(db_chains) > 0
        assert all(c.target_host == "db1" for c in db_chains)

    def test_get_chain_statistics(self, scanner, populated_hosts, sample_connections):
        gen = AttackGraphGenerator(scanner)
        graph = gen.generate_from_topology(populated_hosts, sample_connections)
        hosts_dict = {h.host_id: h for h in populated_hosts}
        detector = ExploitChainDetector(graph, hosts_dict)
        chains = detector.find_chains()
        stats = detector.get_chain_statistics(chains)
        assert stats["total_chains"] > 0
        assert stats["avg_length"] > 0
        assert stats["max_probability"] > 0

    def test_no_chains_empty_graph(self):
        graph = AttackGraph()
        detector = ExploitChainDetector(graph, {})
        chains = detector.find_chains()
        assert len(chains) == 0

    def test_chain_with_max_length(self, scanner, populated_hosts, sample_connections):
        gen = AttackGraphGenerator(scanner)
        graph = gen.generate_from_topology(populated_hosts, sample_connections)
        hosts_dict = {h.host_id: h for h in populated_hosts}
        detector = ExploitChainDetector(graph, hosts_dict)
        chains = detector.find_chains(max_length=2)
        for chain in chains:
            assert chain.length <= 2


# ─── ExploitChain Tests ─────────────────────────────────────────────────────

class TestExploitChain:
    def test_chain_length(self):
        steps = [
            ExploitStep("a", "b", Vulnerability("CVE-2024-6387", 9.8, 0.95, "ssh", 22), 0.9),
            ExploitStep("b", "c", Vulnerability("CVE-2023-48795", 5.9, 0.7, "ssh", 22), 0.6),
        ]
        chain = ExploitChain(steps, "c")
        assert chain.length == 2

    def test_total_probability(self):
        steps = [
            ExploitStep("a", "b", Vulnerability("CVE-2024-6387", 9.8, 0.95, "ssh", 22), 0.9),
            ExploitStep("b", "c", Vulnerability("CVE-2023-48795", 5.9, 0.7, "ssh", 22), 0.6),
        ]
        chain = ExploitChain(steps, "c")
        assert abs(chain.total_probability - 0.54) < 0.001

    def test_max_cvss(self):
        steps = [
            ExploitStep("a", "b", Vulnerability("CVE-2024-6387", 9.8, 0.95, "ssh", 22), 0.9),
            ExploitStep("b", "c", Vulnerability("CVE-2023-48795", 5.9, 0.7, "ssh", 22), 0.6),
        ]
        chain = ExploitChain(steps, "c")
        assert chain.max_cvss == 9.8

    def test_empty_chain(self):
        chain = ExploitChain([], "target")
        assert chain.length == 0
        assert chain.total_probability == 1.0
        assert chain.max_cvss == 0.0

    def test_to_dict(self):
        steps = [
            ExploitStep("a", "b", Vulnerability("CVE-2024-6387", 9.8, 0.95, "ssh", 22), 0.9),
        ]
        chain = ExploitChain(steps, "b")
        d = chain.to_dict()
        assert d["target_host"] == "b"
        assert d["length"] == 1
        assert len(d["steps"]) == 1


# ─── Integration Tests ────────────────────────────────────────────────────

class TestIntegration:
    def test_full_pipeline(self, scanner, populated_hosts, sample_connections):
        """Test the full pipeline: scan -> generate graph -> detect chains."""
        gen = AttackGraphGenerator(scanner)
        graph = gen.generate_from_topology(populated_hosts, sample_connections)
        hosts_dict = {h.host_id: h for h in populated_hosts}
        detector = ExploitChainDetector(graph, hosts_dict)
        chains = detector.find_chains()
        assert len(chains) > 0
        stats = detector.get_chain_statistics(chains)
        assert stats["total_chains"] > 0

    def test_scan_updates_hosts(self, scanner, sample_hosts):
        hosts = [Host(h.host_id, h.ip, h.os, dict(h.services)) for h in sample_hosts]
        scanner.scan_network(hosts)
        assert len(hosts[0].vulnerabilities) > 0
        assert len(hosts[1].vulnerabilities) > 0

    def test_chain_detection_with_custom_entry_points(self, scanner, populated_hosts, sample_connections):
        gen = AttackGraphGenerator(scanner)
        graph = gen.generate_from_topology(populated_hosts, sample_connections)
        hosts_dict = {h.host_id: h for h in populated_hosts}
        detector = ExploitChainDetector(graph, hosts_dict)
        chains = detector.find_chains(entry_points=["web1"], targets=["db1"])
        assert len(chains) > 0
        assert all(c.target_host == "db1" for c in chains)
