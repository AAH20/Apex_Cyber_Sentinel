"""Critical path analysis, attack surface quantification, and mitigation prioritization.

Extends the attack graph module with:
- CriticalPathAnalyzer: identifies and ranks the most dangerous attack paths
- AttackSurfaceQuantifier: measures the reachable attack surface from entry points
- MitigationPrioritizer: ranks mitigations by ROI and selects optimal sets within budget
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Set, Tuple

from cyber.attack_graph import AttackGraph, PathAnalyzer, CriticalNodeAnalyzer


# ─── Critical Path Analyzer ─────────────────────────────────────────────────

class CriticalPathAnalyzer:
    """Identifies and ranks the most dangerous attack paths through the graph."""

    def __init__(self, graph: AttackGraph, path_analyzer: PathAnalyzer) -> None:
        self.graph = graph
        self.path_analyzer = path_analyzer

    def find_critical_paths(
        self,
        entry_points: List[str],
        targets: List[str],
        top_n: Optional[int] = None,
    ) -> List[Tuple[List[str], float]]:
        """Find and rank critical paths from entry points to targets.

        Returns a list of (path, score) tuples sorted by score descending.
        Score combines path risk, path length, and target criticality.
        """
        all_paths = self.path_analyzer.find_paths_from_entry_points(entry_points, targets)
        if not all_paths:
            return []

        scored: List[Tuple[List[str], float]] = []
        for path in all_paths:
            score = self.compute_path_criticality(path)
            scored.append((path, score))

        scored.sort(key=lambda x: x[1], reverse=True)
        if top_n is not None:
            scored = scored[:top_n]
        return scored

    def compute_path_criticality(self, path: List[str]) -> float:
        """Compute a criticality score for a single path.

        Score = max_node_risk * length_factor * target_criticality_multiplier

        Where:
        - max_node_risk is the highest risk among nodes on the path
        - length_factor = 1 + len(path) / 10 (longer paths get a small bonus)
        - target node type adds a multiplier (critical=2.0, others=1.0)
        """
        if not path:
            return 0.0

        max_node_risk = 0.0
        for node_id in path:
            node = self.graph.get_nodes().get(node_id)
            if node and node.risk > max_node_risk:
                max_node_risk = node.risk

        length_factor = 1.0 + len(path) / 10.0

        # Target criticality multiplier
        target_node = self.graph.get_nodes().get(path[-1])
        if target_node and target_node.node_type == "critical":
            target_multiplier = 2.0
        else:
            target_multiplier = 1.0

        return max_node_risk * length_factor * target_multiplier

    def rank_paths_by_danger(
        self, entry_points: List[str], targets: List[str]
    ) -> List[Tuple[List[str], float]]:
        """Rank all paths from entry points to targets by danger score.

        Alias for find_critical_paths without a top_n limit.
        """
        return self.find_critical_paths(entry_points, targets)


# ─── Attack Surface Quantifier ──────────────────────────────────────────────

class AttackSurfaceQuantifier:
    """Measures and quantifies the attack surface reachable from entry points."""

    def __init__(self, graph: AttackGraph) -> None:
        self.graph = graph

    def quantify_attack_surface(
        self, entry_points: List[str]
    ) -> Dict[str, Any]:
        """Quantify the attack surface reachable from the given entry points.

        Returns a dict with:
        - total_nodes: total nodes in the graph
        - reachable_nodes: nodes reachable from any entry point
        - unreachable_nodes: nodes not reachable from any entry point
        - attack_surface_ratio: reachable / total
        """
        total = self.graph.node_count()
        reachable = self._get_reachable_nodes(entry_points)
        unreachable = total - len(reachable)

        if total == 0:
            ratio = 0.0
        else:
            ratio = len(reachable) / total

        return {
            "total_nodes": total,
            "reachable_nodes": len(reachable),
            "unreachable_nodes": unreachable,
            "attack_surface_ratio": ratio,
        }

    def get_exposure_score(self, node_id: str) -> float:
        """Compute the exposure score for a node.

        Exposure = risk * (1 + predecessor_count) * (1 + successor_count)

        Higher exposure means the node is more exposed to attack.
        """
        if node_id not in self.graph.get_nodes():
            raise KeyError(f"Node '{node_id}' not found")

        node = self.graph.get_node(node_id)
        pred_count = len(self.graph.get_predecessors(node_id))
        succ_count = len(self.graph.get_neighbors(node_id))

        return node.risk * (1 + pred_count) * (1 + succ_count)

    def get_attack_surface_ratio(self, entry_points: List[str]) -> float:
        """Get the ratio of reachable nodes to total nodes."""
        metrics = self.quantify_attack_surface(entry_points)
        return metrics["attack_surface_ratio"]

    def _get_reachable_nodes(self, entry_points: List[str]) -> Set[str]:
        """BFS from all entry points to find all reachable nodes."""
        reachable: Set[str] = set()
        queue: List[str] = []

        for ep in entry_points:
            if ep in self.graph.get_nodes() and ep not in reachable:
                reachable.add(ep)
                queue.append(ep)

        while queue:
            current = queue.pop(0)
            for neighbor in self.graph.get_neighbors(current):
                if neighbor not in reachable:
                    reachable.add(neighbor)
                    queue.append(neighbor)

        return reachable


# ─── Mitigation Prioritizer ─────────────────────────────────────────────────

class MitigationPrioritizer:
    """Ranks mitigations by ROI and selects optimal sets within budget constraints."""

    # Cost mapping by node type
    COST_MAP: Dict[str, int] = {
        "entry": 2,
        "firewall": 2,
        "host": 1,
        "server": 2,
        "database": 3,
        "critical": 3,
    }

    def __init__(
        self, graph: AttackGraph, critical_analyzer: CriticalNodeAnalyzer
    ) -> None:
        self.graph = graph
        self.critical_analyzer = critical_analyzer

    def prioritize_mitigations(self) -> List[Dict[str, Any]]:
        """Return all mitigations sorted by ROI (descending).

        Each mitigation dict contains:
        - node_id: the node to mitigate
        - risk_reduction: estimated risk reduction (risk * 0.8)
        - cost: mitigation cost based on node type
        - roi: return on investment (risk_reduction / cost)
        """
        nodes = self.graph.get_nodes()
        mitigations: List[Dict[str, Any]] = []

        for node_id, node in nodes.items():
            risk_reduction = round(node.risk * 0.8, 4)
            cost = self._get_cost(node)
            roi = risk_reduction / cost if cost > 0 else 0.0

            mitigations.append({
                "node_id": node_id,
                "risk_reduction": risk_reduction,
                "cost": cost,
                "roi": round(roi, 4),
            })

        mitigations.sort(key=lambda m: m["roi"], reverse=True)
        return mitigations

    def get_mitigation_roi(self, node_id: str) -> float:
        """Get the ROI for mitigating a specific node.

        ROI = risk_reduction / cost
        """
        if node_id not in self.graph.get_nodes():
            raise KeyError(f"Node '{node_id}' not found")

        node = self.graph.get_node(node_id)
        risk_reduction = node.risk * 0.8
        cost = self._get_cost(node)
        return risk_reduction / cost if cost > 0 else 0.0

    def get_optimal_mitigation_set(
        self, budget: int
    ) -> List[Dict[str, Any]]:
        """Select the optimal set of mitigations within a budget.

        Uses a greedy approach: pick highest-ROI mitigations first
        until the budget is exhausted.
        """
        if budget <= 0:
            return []

        all_mitigations = self.prioritize_mitigations()
        selected: List[Dict[str, Any]] = []
        remaining_budget = budget

        for m in all_mitigations:
            if m["cost"] <= remaining_budget:
                selected.append(m)
                remaining_budget -= m["cost"]

        return selected

    def _get_cost(self, node: Any) -> int:
        """Get the mitigation cost for a node based on its type."""
        return self.COST_MAP.get(node.node_type, 1)
