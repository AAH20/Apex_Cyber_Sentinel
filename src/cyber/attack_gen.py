"""Attack graph generation, vulnerability scanning, and exploit chain detection.

Deepens adversarial co-evolution by providing:
- Vulnerability scanning for network hosts
- Attack graph generation from topology and vulnerabilities
- Exploit chain detection for multi-step attacks
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from .attack_graph import AttackGraph


# ─── Data Models ───────────────────────────────────────────────────────────

@dataclass
class Vulnerability:
    """A vulnerability found on a host."""
    cve_id: str
    cvss_score: float
    exploitability: float
    service: str
    port: int
    description: str = ""

    def __post_init__(self) -> None:
        if not 0.0 <= self.cvss_score <= 10.0:
            raise ValueError("cvss_score must be between 0 and 10")
        if not 0.0 <= self.exploitability <= 1.0:
            raise ValueError("exploitability must be between 0 and 1")

    @property
    def severity(self) -> str:
        if self.cvss_score >= 9.0:
            return "critical"
        if self.cvss_score >= 7.0:
            return "high"
        if self.cvss_score >= 4.0:
            return "medium"
        return "low"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "cvss_score": self.cvss_score,
            "exploitability": self.exploitability,
            "service": self.service,
            "port": self.port,
            "description": self.description,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Vulnerability":
        return cls(
            cve_id=d["cve_id"],
            cvss_score=d["cvss_score"],
            exploitability=d["exploitability"],
            service=d["service"],
            port=d["port"],
            description=d.get("description", ""),
        )


@dataclass
class Host:
    """A network host with services and vulnerabilities."""
    host_id: str
    ip: str
    os: str = "unknown"
    services: Dict[str, int] = field(default_factory=dict)
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    is_critical: bool = False
    is_entry_point: bool = False

    def add_vulnerability(self, vuln: Vulnerability) -> None:
        self.vulnerabilities.append(vuln)

    def get_vulnerabilities_by_severity(self, severity: str) -> List[Vulnerability]:
        return [v for v in self.vulnerabilities if v.severity == severity]

    def get_max_cvss(self) -> float:
        if not self.vulnerabilities:
            return 0.0
        return max(v.cvss_score for v in self.vulnerabilities)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "host_id": self.host_id,
            "ip": self.ip,
            "os": self.os,
            "services": dict(self.services),
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "is_critical": self.is_critical,
            "is_entry_point": self.is_entry_point,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Host":
        return cls(
            host_id=d["host_id"],
            ip=d["ip"],
            os=d.get("os", "unknown"),
            services=dict(d.get("services", {})),
            vulnerabilities=[Vulnerability.from_dict(v) for v in d.get("vulnerabilities", [])],
            is_critical=d.get("is_critical", False),
            is_entry_point=d.get("is_entry_point", False),
        )


@dataclass
class ExploitStep:
    """A single step in an exploit chain."""
    source_host: str
    target_host: str
    vulnerability: Vulnerability
    success_probability: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_host": self.source_host,
            "target_host": self.target_host,
            "vulnerability": self.vulnerability.to_dict(),
            "success_probability": self.success_probability,
        }


@dataclass
class ExploitChain:
    """A chain of exploit steps leading to a target."""
    steps: List[ExploitStep]
    target_host: str

    @property
    def length(self) -> int:
        return len(self.steps)

    @property
    def total_probability(self) -> float:
        prob = 1.0
        for step in self.steps:
            prob *= step.success_probability
        return prob

    @property
    def max_cvss(self) -> float:
        if not self.steps:
            return 0.0
        return max(s.vulnerability.cvss_score for s in self.steps)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "steps": [s.to_dict() for s in self.steps],
            "target_host": self.target_host,
            "length": self.length,
            "total_probability": self.total_probability,
            "max_cvss": self.max_cvss,
        }


# ─── Vulnerability Scanner ─────────────────────────────────────────────────

class VulnerabilityScanner:
    """Scans hosts for vulnerabilities based on service signatures."""

    VULN_DB: Dict[str, List[Tuple[str, float, float, int]]] = {
        "ssh": [
            ("CVE-2024-6387", 9.8, 0.95, 22),
            ("CVE-2023-48795", 5.9, 0.7, 22),
        ],
        "http": [
            ("CVE-2024-27198", 9.8, 0.9, 80),
            ("CVE-2023-44487", 7.5, 0.8, 80),
        ],
        "https": [
            ("CVE-2024-27198", 9.8, 0.9, 443),
            ("CVE-2023-44487", 7.5, 0.8, 443),
        ],
        "ftp": [
            ("CVE-2023-48795", 5.9, 0.6, 21),
        ],
        "smb": [
            ("CVE-2023-48795", 8.1, 0.85, 445),
        ],
        "rdp": [
            ("CVE-2024-6387", 9.8, 0.9, 3389),
        ],
        "mysql": [
            ("CVE-2024-27198", 7.5, 0.75, 3306),
        ],
        "postgresql": [
            ("CVE-2024-27198", 7.5, 0.75, 5432),
        ],
        "redis": [
            ("CVE-2024-6387", 9.8, 0.95, 6379),
        ],
        "docker": [
            ("CVE-2024-27198", 9.8, 0.9, 2375),
        ],
    }

    def __init__(self, vuln_db: Optional[Dict[str, List[Tuple[str, float, float, int]]]] = None) -> None:
        self._vuln_db = vuln_db if vuln_db is not None else self.VULN_DB.copy()

    def scan_host(self, host: Host) -> List[Vulnerability]:
        """Scan a single host for vulnerabilities based on its services."""
        vulns: List[Vulnerability] = []
        for service, _port in host.services.items():
            service_lower = service.lower()
            if service_lower in self._vuln_db:
                for cve_id, cvss, exploitability, vuln_port in self._vuln_db[service_lower]:
                    vulns.append(Vulnerability(
                        cve_id=cve_id,
                        cvss_score=cvss,
                        exploitability=exploitability,
                        service=service_lower,
                        port=vuln_port,
                    ))
        return vulns

    def scan_network(self, hosts: List[Host]) -> Dict[str, List[Vulnerability]]:
        """Scan all hosts in a network."""
        results: Dict[str, List[Vulnerability]] = {}
        for host in hosts:
            vulns = self.scan_host(host)
            host.vulnerabilities = vulns
            results[host.host_id] = vulns
        return results

    def get_vulnerabilities_by_severity(
        self, hosts: List[Host], severity: str
    ) -> Dict[str, List[Vulnerability]]:
        """Get vulnerabilities of a specific severity across all hosts."""
        result: Dict[str, List[Vulnerability]] = {}
        for host in hosts:
            vulns = host.get_vulnerabilities_by_severity(severity)
            if vulns:
                result[host.host_id] = vulns
        return result

    def get_critical_vulnerabilities(self, hosts: List[Host]) -> Dict[str, List[Vulnerability]]:
        """Get all critical vulnerabilities across hosts."""
        return self.get_vulnerabilities_by_severity(hosts, "critical")

    def get_high_vulnerabilities(self, hosts: List[Host]) -> Dict[str, List[Vulnerability]]:
        """Get all high vulnerabilities across hosts."""
        return self.get_vulnerabilities_by_severity(hosts, "high")


# ─── Attack Graph Generator ────────────────────────────────────────────────

class AttackGraphGenerator:
    """Generates attack graphs from network topology and vulnerabilities."""

    def __init__(self, scanner: Optional[VulnerabilityScanner] = None) -> None:
        self.scanner = scanner if scanner is not None else VulnerabilityScanner()

    def generate_from_topology(
        self,
        hosts: List[Host],
        connections: List[Tuple[str, str]],
    ) -> AttackGraph:
        """Generate an attack graph from network topology."""
        graph = AttackGraph()

        for host in hosts:
            risk = min(1.0, host.get_max_cvss() / 10.0)
            node_type = "critical" if host.is_critical else ("entry" if host.is_entry_point else "host")
            graph.add_node(
                host.host_id,
                node_type=node_type,
                risk=risk,
                ip=host.ip,
                os=host.os,
                vuln_count=len(host.vulnerabilities),
            )

        for src, dst in connections:
            if src not in graph.get_nodes() or dst not in graph.get_nodes():
                continue
            dst_host = next((h for h in hosts if h.host_id == dst), None)
            if dst_host and dst_host.vulnerabilities:
                max_exploit = max(v.exploitability for v in dst_host.vulnerabilities)
            else:
                max_exploit = 0.5
            graph.add_edge(src, dst, probability=max_exploit)

        return graph


# ─── Exploit Chain Detector ────────────────────────────────────────────────

class ExploitChainDetector:
    """Detects exploit chains in an attack graph."""

    def __init__(self, graph: AttackGraph, hosts: Dict[str, Host]) -> None:
        self.graph = graph
        self.hosts = hosts

    def find_chains(
        self,
        entry_points: Optional[List[str]] = None,
        targets: Optional[List[str]] = None,
        max_length: int = 5,
    ) -> List[ExploitChain]:
        """Find all exploit chains from entry points to targets."""
        if entry_points is None:
            entry_points = [nid for nid, n in self.graph.get_nodes().items() if n.node_type == "entry"]
        if targets is None:
            targets = [nid for nid, n in self.graph.get_nodes().items() if n.node_type == "critical"]

        chains: List[ExploitChain] = []
        for entry in entry_points:
            for target in targets:
                paths = self._find_paths(entry, target, max_length)
                for path in paths:
                    chain = self._build_chain(path)
                    if chain:
                        chains.append(chain)
        return chains

    def _find_paths(self, source: str, target: str, max_length: int) -> List[List[str]]:
        """Find all simple paths from source to target."""
        paths: List[List[str]] = []
        self._dfs(source, target, [source], {source}, paths, max_length)
        return paths

    def _dfs(self, current: str, target: str, path: List[str],
             visited: Set[str], paths: List[List[str]], max_length: int) -> None:
        if current == target:
            paths.append(list(path))
            return
        if len(path) >= max_length:
            return
        for neighbor in sorted(self.graph.get_neighbors(current)):
            if neighbor not in visited:
                visited.add(neighbor)
                path.append(neighbor)
                self._dfs(neighbor, target, path, visited, paths, max_length)
                path.pop()
                visited.discard(neighbor)

    def _build_chain(self, path: List[str]) -> Optional[ExploitChain]:
        """Build an ExploitChain from a path."""
        if len(path) < 2:
            return None

        steps: List[ExploitStep] = []
        for i in range(len(path) - 1):
            src = path[i]
            dst = path[i + 1]
            dst_host = self.hosts.get(dst)
            if not dst_host or not dst_host.vulnerabilities:
                return None

            best_vuln = max(dst_host.vulnerabilities, key=lambda v: v.exploitability)
            edge = self.graph.get_edges().get((src, dst))
            edge_prob = edge.probability if edge else 0.5
            success_prob = best_vuln.exploitability * edge_prob

            steps.append(ExploitStep(
                source_host=src,
                target_host=dst,
                vulnerability=best_vuln,
                success_probability=success_prob,
            ))

        return ExploitChain(steps=steps, target_host=path[-1])

    def get_most_dangerous_chain(self, chains: List[ExploitChain]) -> Optional[ExploitChain]:
        """Get the most dangerous chain (highest probability * max_cvss)."""
        if not chains:
            return None
        return max(chains, key=lambda c: c.total_probability * c.max_cvss)

    def get_chains_by_target(self, chains: List[ExploitChain], target: str) -> List[ExploitChain]:
        """Get all chains targeting a specific host."""
        return [c for c in chains if c.target_host == target]

    def get_chain_statistics(self, chains: List[ExploitChain]) -> Dict[str, Any]:
        """Compute statistics over exploit chains."""
        if not chains:
            return {
                "total_chains": 0,
                "avg_length": 0.0,
                "max_probability": 0.0,
                "max_cvss": 0.0,
            }
        lengths = [c.length for c in chains]
        probs = [c.total_probability for c in chains]
        cvss_scores = [c.max_cvss for c in chains]
        return {
            "total_chains": len(chains),
            "avg_length": sum(lengths) / len(lengths),
            "max_probability": max(probs),
            "max_cvss": max(cvss_scores),
        }
