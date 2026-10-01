#!/usr/bin/env python3
"""
Apex_Cyber_Sentinel — Attack Path Mapping Demo
==============================================

Demonstrates attack path mapping by modeling a sample network topology,
identifying critical assets, and computing plausible attack paths an
adversary could take to reach them.

The demo builds a directed graph of network segments, hosts, and services,
then performs a breadth-first search (BFS) from an external entry point
to each critical asset, printing the shortest attack path and the total
number of distinct paths.

Usage:
    python demo_attack_path.py
"""

from collections import defaultdict, deque
from typing import Dict, List, Set, Tuple


# ---------------------------------------------------------------------------
# Sample network topology
# ---------------------------------------------------------------------------
# Each edge represents a reachable connection (source -> target).
# Hosts are tagged with a type and a risk score (1-10).

HOSTS: Dict[str, Dict[str, object]] = {
    "internet":        {"type": "external",  "risk": 10},
    "dmz_web":         {"type": "server",    "risk": 7},
    "dmz_mail":        {"type": "server",    "risk": 6},
    "fw_internal":     {"type": "firewall",  "risk": 5},
    "workstation_01":  {"type": "workstation", "risk": 4},
    "workstation_02":  {"type": "workstation", "risk": 4},
    "ad_server":       {"type": "server",    "risk": 9},
    "db_server":       {"type": "server",    "risk": 10},
    "backup_server":   {"type": "server",    "risk": 8},
    "siem":            {"type": "server",    "risk": 6},
}

EDGES: List[Tuple[str, str]] = [
    ("internet",       "dmz_web"),
    ("internet",       "dmz_mail"),
    ("dmz_web",        "fw_internal"),
    ("dmz_mail",       "fw_internal"),
    ("fw_internal",    "workstation_01"),
    ("fw_internal",    "workstation_02"),
    ("workstation_01", "ad_server"),
    ("workstation_02", "ad_server"),
    ("ad_server",      "db_server"),
    ("ad_server",      "backup_server"),
    ("workstation_01", "siem"),
    ("workstation_02", "siem"),
]

CRITICAL_ASSETS = {"db_server", "ad_server", "backup_server"}


# ---------------------------------------------------------------------------
# Graph helpers
# ---------------------------------------------------------------------------

def build_adjacency(edges: List[Tuple[str, str]]) -> Dict[str, List[str]]:
    """Build an adjacency list from a list of directed edges."""
    graph: Dict[str, List[str]] = defaultdict(list)
    for src, dst in edges:
        graph[src].append(dst)
    return graph


def bfs_shortest_path(
    graph: Dict[str, List[str]],
    start: str,
    goal: str,
) -> List[str]:
    """Return the shortest path from *start* to *goal* using BFS."""
    if start == goal:
        return [start]

    visited: Set[str] = {start}
    queue: deque = deque([(start, [start])])

    while queue:
        node, path = queue.popleft()
        for neighbor in graph.get(node, []):
            if neighbor == goal:
                return path + [neighbor]
            if neighbor not in visited:
                visited.add(neighbor)
                queue.append((neighbor, path + [neighbor]))
    return []  # no path found


def count_all_paths(
    graph: Dict[str, List[str]],
    start: str,
    goal: str,
    max_depth: int = 10,
) -> int:
    """Count all simple paths from *start* to *goal* up to *max_depth* hops."""
    count = 0

    def dfs(node: str, depth: int, visited: Set[str]) -> None:
        nonlocal count
        if depth > max_depth:
            return
        if node == goal:
            count += 1
            return
        for neighbor in graph.get(node, []):
            if neighbor not in visited:
                visited.add(neighbor)
                dfs(neighbor, depth + 1, visited)
                visited.discard(neighbor)

    dfs(start, 0, {start})
    return count


def path_risk_score(path: List[str]) -> int:
    """Sum the risk scores of all hosts along a path."""
    return sum(HOSTS.get(h, {}).get("risk", 0) for h in path)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Demo output
# ---------------------------------------------------------------------------

def print_header(title: str) -> None:
    print(f"\n{'=' * 60}")
    print(f"  {title}")
    print(f"{'=' * 60}")


def print_network_summary() -> None:
    print_header("Network Topology Summary")
    print(f"  Total hosts : {len(HOSTS)}")
    print(f"  Total edges : {len(EDGES)}")
    print(f"  Entry point : internet")
    print(f"  Critical assets: {', '.join(sorted(CRITICAL_ASSETS))}")
    print()
    print("  Host inventory:")
    print(f"    {'Host':<20} {'Type':<15} {'Risk'}")
    print(f"    {'-'*20} {'-'*15} {'-'*4}")
    for host, meta in sorted(HOSTS.items()):
        print(f"    {host:<20} {meta['type']:<15} {meta['risk']}")


def print_attack_paths(graph: Dict[str, List[str]]) -> None:
    print_header("Attack Path Analysis")
    print(f"  Source: internet (external adversary)\n")

    for asset in sorted(CRITICAL_ASSETS):
        path = bfs_shortest_path(graph, "internet", asset)
        if not path:
            print(f"  [!] No path found to {asset}")
            continue

        total_paths = count_all_paths(graph, "internet", asset)
        risk = path_risk_score(path)

        print(f"  Target: {asset}  (risk score: {HOSTS[asset]['risk']})")
        print(f"    Shortest path ({len(path)} hops, cumulative risk {risk}):")
        print(f"      {' -> '.join(path)}")
        print(f"    Total distinct paths (depth ≤ 10): {total_paths}")
        print()


def print_recommendations() -> None:
    print_header("Recommendations")
    recs = [
        "Segment the DMZ from the internal network with a dedicated firewall.",
        "Enforce multi-factor authentication on all administrative accounts.",
        "Deploy EDR agents on all workstations and servers.",
        "Implement least-privilege access between network segments.",
        "Monitor SIEM alerts for lateral movement indicators.",
    ]
    for i, rec in enumerate(recs, 1):
        print(f"  {i}. {rec}")
    print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    print("\n" + "#" * 60)
    print("#  Apex_Cyber_Sentinel — Attack Path Mapping Demo")
    print("#" * 60)

    graph = build_adjacency(EDGES)

    print_network_summary()
    print_attack_paths(graph)
    print_recommendations()

    print("=" * 60)
    print("  Demo complete.")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    main()
