"""Graph-based attack path mapping for Apex Cyber Sentinel.

Provides attack graph generation, path analysis, critical node
identification, and mitigation recommendation.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


# ─── Data Models ───────────────────────────────────────────────────────────

@dataclass
class Node:
    """A node in the attack graph (host, firewall, entry point, etc.)."""
    node_id: str
    node_type: str = "host"
    risk: float = 0.5
    attributes: Dict[str, Any] = field(default_factory=dict)

    def __getattr__(self, name: str) -> Any:
        try:
            return self.__dict__["attributes"][name]
        except KeyError:
            raise AttributeError(f"'{type(self).__name__}' has no attribute '{name}'")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_id": self.node_id,
            "node_type": self.node_type,
            "risk": self.risk,
            "attributes": dict(self.attributes),
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Node":
        return cls(
            node_id=d["node_id"],
            node_type=d.get("node_type", "host"),
            risk=d.get("risk", 0.5),
            attributes=dict(d.get("attributes", {})),
        )


@dataclass
class Edge:
    """A directed edge representing an attack step."""
    source: str
    target: str
    probability: float = 1.0
    attributes: Dict[str, Any] = field(default_factory=dict)

    def __getattr__(self, name: str) -> Any:
        try:
            return self.__dict__["attributes"][name]
        except KeyError:
            raise AttributeError(f"'{type(self).__name__}' has no attribute '{name}'")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "probability": self.probability,
            "attributes": dict(self.attributes),
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Edge":
        return cls(
            source=d["source"],
            target=d["target"],
            probability=d.get("probability", 1.0),
            attributes=dict(d.get("attributes", {})),
        )


# ─── Attack Graph ──────────────────────────────────────────────────────────

class AttackGraph:
    """Directed graph modeling attack paths through a network."""

    def __init__(self) -> None:
        self._nodes: Dict[str, Node] = {}
        self._edges: Dict[Tuple[str, str], Edge] = {}
        self._adj: Dict[str, Set[str]] = {}
        self._pred: Dict[str, Set[str]] = {}

    # ── Node operations ────────────────────────────────────────────────

    def add_node(self, node_id: str, node_type: str = "host",
                 risk: float = 0.5, **attributes: Any) -> None:
        self._nodes[node_id] = Node(
            node_id=node_id, node_type=node_type, risk=risk,
            attributes=attributes,
        )
        self._adj.setdefault(node_id, set())
        self._pred.setdefault(node_id, set())

    def remove_node(self, node_id: str) -> None:
        if node_id not in self._nodes:
            raise KeyError(f"Node '{node_id}' not found")
        # Remove all edges connected to this node
        for succ in list(self._adj.get(node_id, set())):
            self._remove_edge_internal(node_id, succ)
        for pred in list(self._pred.get(node_id, set())):
            self._remove_edge_internal(pred, node_id)
        del self._nodes[node_id]
        self._adj.pop(node_id, None)
        self._pred.pop(node_id, None)

    def get_nodes(self) -> Dict[str, Node]:
        return dict(self._nodes)

    def get_node(self, node_id: str) -> Node:
        if node_id not in self._nodes:
            raise KeyError(f"Node '{node_id}' not found")
        return self._nodes[node_id]

    def get_nodes_by_type(self, node_type: str) -> Dict[str, Node]:
        return {nid: n for nid, n in self._nodes.items()
                if n.node_type == node_type}

    def get_entry_points(self) -> Dict[str, Node]:
        return self.get_nodes_by_type("entry")

    def get_critical_assets(self) -> Dict[str, Node]:
        return self.get_nodes_by_type("critical")

    # ── Edge operations ────────────────────────────────────────────────

    def add_edge(self, source: str, target: str,
                 probability: float = 1.0, **attributes: Any) -> None:
        # Auto-create nodes if they don't exist
        if source not in self._nodes:
            self.add_node(source)
        if target not in self._nodes:
            self.add_node(target)
        self._edges[(source, target)] = Edge(
            source=source, target=target, probability=probability,
            attributes=attributes,
        )
        self._adj[source].add(target)
        self._pred[target].add(source)

    def remove_edge(self, source: str, target: str) -> None:
        if (source, target) not in self._edges:
            raise KeyError(f"Edge '{source}' -> '{target}' not found")
        self._remove_edge_internal(source, target)

    def _remove_edge_internal(self, source: str, target: str) -> None:
        self._edges.pop((source, target), None)
        self._adj.get(source, set()).discard(target)
        self._pred.get(target, set()).discard(source)

    def get_edges(self) -> Dict[Tuple[str, str], Edge]:
        return dict(self._edges)

    def get_edge(self, source: str, target: str) -> Edge:
        if (source, target) not in self._edges:
            raise KeyError(f"Edge '{source}' -> '{target}' not found")
        return self._edges[(source, target)]

    # ── Graph queries ──────────────────────────────────────────────────

    def get_neighbors(self, node_id: str) -> Set[str]:
        return set(self._adj.get(node_id, set()))

    def get_predecessors(self, node_id: str) -> Set[str]:
        return set(self._pred.get(node_id, set()))

    def node_count(self) -> int:
        return len(self._nodes)

    def edge_count(self) -> int:
        return len(self._edges)

    def has_path(self, source: str, target: str) -> bool:
        if source not in self._nodes or target not in self._nodes:
            return False
        if source == target:
            return True
        visited: Set[str] = set()
        queue = deque([source])
        while queue:
            current = queue.popleft()
            if current == target:
                return True
            if current in visited:
                continue
            visited.add(current)
            for neighbor in self._adj.get(current, set()):
                if neighbor not in visited:
                    queue.append(neighbor)
        return False

    # ── Serialization ──────────────────────────────────────────────────

    def to_dict(self) -> Dict[str, Any]:
        return {
            "nodes": [n.to_dict() for n in self._nodes.values()],
            "edges": [e.to_dict() for e in self._edges.values()],
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "AttackGraph":
        g = cls()
        for nd in d.get("nodes", []):
            n = Node.from_dict(nd)
            g.add_node(n.node_id, node_type=n.node_type, risk=n.risk,
                       **n.attributes)
        for ed in d.get("edges", []):
            e = Edge.from_dict(ed)
            g.add_edge(e.source, e.target, probability=e.probability,
                       **e.attributes)
        return g


# ─── Path Analyzer ─────────────────────────────────────────────────────────

class PathAnalyzer:
    """Analyzes attack paths through the graph."""

    def __init__(self, graph: AttackGraph) -> None:
        self.graph = graph

    def find_all_paths(self, source: str, target: str,
                       max_depth: Optional[int] = None) -> List[List[str]]:
        """Find all simple paths from source to target using DFS."""
        if source not in self.graph.get_nodes():
            return []
        if target not in self.graph.get_nodes():
            return []

        paths: List[List[str]] = []
        self._dfs(source, target, [source], {source}, paths, max_depth)
        return paths

    def _dfs(self, current: str, target: str, path: List[str],
             visited: Set[str], paths: List[List[str]],
             max_depth: Optional[int]) -> None:
        if current == target:
            paths.append(list(path))
            return
        if max_depth is not None and len(path) >= max_depth:
            return
        for neighbor in sorted(self.graph.get_neighbors(current)):
            if neighbor not in visited:
                visited.add(neighbor)
                path.append(neighbor)
                self._dfs(neighbor, target, path, visited, paths, max_depth)
                path.pop()
                visited.discard(neighbor)

    def find_shortest_path(self, source: str, target: str) -> Optional[List[str]]:
        """Find the shortest path from source to target using BFS."""
        if source not in self.graph.get_nodes():
            return None
        if target not in self.graph.get_nodes():
            return None
        if source == target:
            return [source]

        visited: Set[str] = {source}
        queue: deque[Tuple[str, List[str]]] = deque([(source, [source])])

        while queue:
            current, path = queue.popleft()
            for neighbor in sorted(self.graph.get_neighbors(current)):
                if neighbor == target:
                    return path + [neighbor]
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append((neighbor, path + [neighbor]))
        return None

    def find_paths_from_entry_points(
        self, entry_points: List[str], targets: List[str]
    ) -> List[List[str]]:
        """Find all paths from any entry point to any target."""
        all_paths: List[List[str]] = []
        for entry in entry_points:
            for target in targets:
                paths = self.find_all_paths(entry, target)
                all_paths.extend(paths)
        return all_paths

    def calculate_path_risk(self, path: List[str]) -> float:
        """Calculate the cumulative risk of a path.

        Risk = product of edge probabilities * product of node risks.
        For a single-node path, returns the node's risk.
        """
        if not path:
            return 0.0
        if len(path) == 1:
            node = self.graph.get_nodes().get(path[0])
            return node.risk if node else 0.0

        risk = 1.0
        # Multiply node risks
        for node_id in path:
            node = self.graph.get_nodes().get(node_id)
            if node:
                risk *= node.risk
        # Multiply edge probabilities
        for i in range(len(path) - 1):
            edge = self.graph.get_edges().get((path[i], path[i + 1]))
            if edge:
                risk *= edge.probability
        return risk

    def get_path_statistics(
        self, entry_points: List[str], targets: List[str]
    ) -> Dict[str, Any]:
        """Compute statistics over all paths from entry points to targets."""
        paths = self.find_paths_from_entry_points(entry_points, targets)
        if not paths:
            return {
                "total_paths": 0,
                "avg_length": 0.0,
                "max_risk": 0.0,
                "min_risk": 0.0,
            }
        lengths = [len(p) for p in paths]
        risks = [self.calculate_path_risk(p) for p in paths]
        return {
            "total_paths": len(paths),
            "avg_length": sum(lengths) / len(lengths),
            "max_risk": max(risks),
            "min_risk": min(risks),
        }


# ─── Critical Node Analyzer ────────────────────────────────────────────────

class CriticalNodeAnalyzer:
    """Identifies critical nodes in the attack graph."""

    def __init__(self, graph: AttackGraph) -> None:
        self.graph = graph

    def betweenness_centrality(self) -> Dict[str, float]:
        """Compute betweenness centrality using Brandes' algorithm."""
        cb: Dict[str, float] = {nid: 0.0 for nid in self.graph.get_nodes()}

        for s in self.graph.get_nodes():
            # Single-source shortest paths
            stack: List[str] = []
            preds: Dict[str, List[str]] = {w: [] for w in self.graph.get_nodes()}
            sigma: Dict[str, float] = {w: 0.0 for w in self.graph.get_nodes()}
            sigma[s] = 1.0
            dist: Dict[str, int] = {w: -1 for w in self.graph.get_nodes()}
            dist[s] = 0
            queue: deque[str] = deque([s])

            while queue:
                v = queue.popleft()
                stack.append(v)
                for w in sorted(self.graph.get_neighbors(v)):
                    if dist[w] < 0:
                        dist[w] = dist[v] + 1
                        queue.append(w)
                    if dist[w] == dist[v] + 1:
                        sigma[w] += sigma[v]
                        preds[w].append(v)

            # Dependency accumulation
            delta: Dict[str, float] = {w: 0.0 for w in self.graph.get_nodes()}
            while stack:
                w = stack.pop()
                for v in preds[w]:
                    delta[v] += (sigma[v] / sigma[w]) * (1.0 + delta[w])
                if w != s:
                    cb[w] += delta[w]

        return cb

    def degree_centrality(self) -> Dict[str, float]:
        """Compute degree centrality for all nodes."""
        n = self.graph.node_count()
        if n <= 1:
            return {nid: 0.0 for nid in self.graph.get_nodes()}
        dc: Dict[str, float] = {}
        for nid in self.graph.get_nodes():
            degree = len(self.graph.get_neighbors(nid)) + \
                len(self.graph.get_predecessors(nid))
            dc[nid] = degree / (n - 1)
        return dc

    def get_critical_nodes(
        self, top_n: Optional[int] = None
    ) -> List[Tuple[str, float]]:
        """Return nodes ranked by composite importance score.

        Score = betweenness_centrality + degree_centrality.
        Returns list of (node_id, score) sorted descending.
        """
        bc = self.betweenness_centrality()
        dc = self.degree_centrality()
        scores: Dict[str, float] = {}
        for nid in self.graph.get_nodes():
            scores[nid] = bc.get(nid, 0.0) + dc.get(nid, 0.0)
        ranked = sorted(scores.items(), key=lambda x: x[1], reverse=True)
        if top_n is not None:
            ranked = ranked[:top_n]
        return ranked

    def get_articulation_points(self) -> Set[str]:
        """Find articulation points using DFS on the undirected version."""
        # Build undirected adjacency
        adj: Dict[str, Set[str]] = {nid: set() for nid in self.graph.get_nodes()}
        for (src, dst) in self.graph.get_edges():
            adj[src].add(dst)
            adj[dst].add(src)

        visited: Set[str] = set()
        disc: Dict[str, int] = {}
        low: Dict[str, int] = {}
        parent: Dict[str, Optional[str]] = {}
        aps: Set[str] = set()
        timer = [0]

        def dfs(u: str) -> None:
            children = 0
            visited.add(u)
            disc[u] = low[u] = timer[0]
            timer[0] += 1
            for v in sorted(adj.get(u, set())):
                if v not in visited:
                    children += 1
                    parent[v] = u
                    dfs(v)
                    low[u] = min(low[u], low[v])
                    # u is root and has 2+ children
                    if parent.get(u) is None and children > 1:
                        aps.add(u)
                    # u is not root and low[v] >= disc[u]
                    if parent.get(u) is not None and low[v] >= disc[u]:
                        aps.add(u)
                elif v != parent.get(u):
                    low[u] = min(low[u], disc[v])

        for node in sorted(self.graph.get_nodes()):
            if node not in visited:
                parent[node] = None
                dfs(node)

        return aps

    def get_node_importance(self, node_id: str) -> float:
        """Get the importance score of a specific node."""
        if node_id not in self.graph.get_nodes():
            raise KeyError(f"Node '{node_id}' not found")
        bc = self.betweenness_centrality()
        dc = self.degree_centrality()
        return bc.get(node_id, 0.0) + dc.get(node_id, 0.0)


# ─── Mitigation Recommender ────────────────────────────────────────────────

class MitigationRecommender:
    """Recommends mitigations based on graph analysis."""

    def __init__(self, graph: AttackGraph, path_analyzer: PathAnalyzer,
                 critical_analyzer: CriticalNodeAnalyzer) -> None:
        self.graph = graph
        self.path_analyzer = path_analyzer
        self.critical_analyzer = critical_analyzer

    def recommend_mitigations(
        self, budget: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """Generate mitigation recommendations for critical nodes.

        Each recommendation includes node_id, priority, action, and
        risk_reduction. Budget limits the number of recommendations.
        """
        critical = self.critical_analyzer.get_critical_nodes(top_n=budget)
        recommendations: List[Dict[str, Any]] = []
        for node_id, score in critical:
            rec = self._build_recommendation(node_id, score)
            recommendations.append(rec)
        return recommendations

    def prioritize_mitigations(self) -> List[Dict[str, Any]]:
        """Return all recommendations sorted by priority (ascending)."""
        recs = self.recommend_mitigations()
        return sorted(recs, key=lambda r: r["priority"])

    def get_mitigation_for_node(self, node_id: str) -> Dict[str, Any]:
        """Get a specific mitigation recommendation for a node."""
        if node_id not in self.graph.get_nodes():
            raise KeyError(f"Node '{node_id}' not found")
        importance = self.critical_analyzer.get_node_importance(node_id)
        return self._build_recommendation(node_id, importance)

    def _build_recommendation(
        self, node_id: str, importance: float
    ) -> Dict[str, Any]:
        node = self.graph.get_node(node_id)
        priority = self._compute_priority(node)
        action = self._get_action(node)
        risk_reduction = self._estimate_risk_reduction(node)
        return {
            "node_id": node_id,
            "priority": priority,
            "action": action,
            "risk_reduction": risk_reduction,
            "importance_score": round(importance, 4),
        }

    def _compute_priority(self, node: Node) -> int:
        """Compute priority: 1 = highest, higher numbers = lower priority."""
        if node.node_type == "critical":
            if node.risk >= 0.8:
                return 1
            return 2
        if node.risk >= 0.7:
            return 2
        if node.risk >= 0.4:
            return 3
        return 4

    def _get_action(self, node: Node) -> str:
        """Get a mitigation action based on node type."""
        actions = {
            "entry": "Implement network segmentation and access controls",
            "firewall": "Update firewall rules and enable deep packet inspection",
            "host": "Apply security patches and enable endpoint protection",
            "critical": "Implement redundancy, backup, and continuous monitoring",
            "server": "Harden configuration and enable intrusion detection",
            "database": "Enable encryption, access auditing, and backup",
        }
        return actions.get(node.node_type,
                            "Review and harden configuration")

    def _estimate_risk_reduction(self, node: Node) -> float:
        """Estimate the risk reduction from mitigating this node."""
        return round(node.risk * 0.8, 4)
