"""Tests for critical path analysis, attack surface quantification, and mitigation prioritization."""
import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from cyber.attack_graph import AttackGraph, PathAnalyzer, CriticalNodeAnalyzer
from cyber.critical_path import (
    CriticalPathAnalyzer,
    AttackSurfaceQuantifier,
    MitigationPrioritizer,
)


# ─── Fixtures ───────────────────────────────────────────────────────────────

@pytest.fixture
def simple_graph():
    """Simple linear graph: A -> B -> C -> D"""
    g = AttackGraph()
    g.add_node("A", node_type="entry", risk=0.1)
    g.add_node("B", node_type="host", risk=0.3)
    g.add_node("C", node_type="host", risk=0.5)
    g.add_node("D", node_type="critical", risk=0.9)
    g.add_edge("A", "B", probability=0.8)
    g.add_edge("B", "C", probability=0.7)
    g.add_edge("C", "D", probability=0.9)
    return g


@pytest.fixture
def branched_graph():
    """Branched graph with multiple paths to critical node."""
    g = AttackGraph()
    g.add_node("internet", node_type="entry", risk=0.1)
    g.add_node("fw", node_type="firewall", risk=0.2)
    g.add_node("dmz", node_type="host", risk=0.4)
    g.add_node("db", node_type="critical", risk=0.95)
    g.add_node("app", node_type="host", risk=0.6)
    g.add_node("backup", node_type="critical", risk=0.85)
    g.add_edge("internet", "fw", probability=0.9)
    g.add_edge("fw", "dmz", probability=0.8)
    g.add_edge("fw", "app", probability=0.5)
    g.add_edge("dmz", "db", probability=0.7)
    g.add_edge("app", "db", probability=0.6)
    g.add_edge("app", "backup", probability=0.4)
    return g


@pytest.fixture
def disconnected_graph():
    """Graph with disconnected components."""
    g = AttackGraph()
    g.add_node("A", node_type="entry", risk=0.1)
    g.add_node("B", node_type="host", risk=0.3)
    g.add_node("X", node_type="entry", risk=0.1)
    g.add_node("Y", node_type="critical", risk=0.9)
    g.add_edge("A", "B", probability=0.8)
    g.add_edge("X", "Y", probability=0.9)
    return g


# ─── CriticalPathAnalyzer Tests ────────────────────────────────────────────

class TestCriticalPathAnalyzer:
    def test_find_critical_paths_returns_highest_risk(self, branched_graph):
        pa = PathAnalyzer(branched_graph)
        cpa = CriticalPathAnalyzer(branched_graph, pa)
        results = cpa.find_critical_paths(["internet"], ["db", "backup"])
        assert len(results) > 0
        # Results should be (path, score) tuples
        path, score = results[0]
        assert isinstance(path, list)
        assert isinstance(score, float)
        assert score > 0

    def test_critical_path_score_computation(self, simple_graph):
        pa = PathAnalyzer(simple_graph)
        cpa = CriticalPathAnalyzer(simple_graph, pa)
        path = ["A", "B", "C", "D"]
        score = cpa.compute_path_criticality(path)
        assert score > 0
        # Score should be higher for paths with higher-risk nodes
        low_risk_path = ["A"]
        low_score = cpa.compute_path_criticality(low_risk_path)
        assert score > low_score

    def test_rank_paths_by_danger_ordering(self, branched_graph):
        pa = PathAnalyzer(branched_graph)
        cpa = CriticalPathAnalyzer(branched_graph, pa)
        results = cpa.rank_paths_by_danger(["internet"], ["db", "backup"])
        assert len(results) >= 2
        scores = [s for _, s in results]
        assert scores == sorted(scores, reverse=True)

    def test_critical_paths_empty_graph(self):
        g = AttackGraph()
        pa = PathAnalyzer(g)
        cpa = CriticalPathAnalyzer(g, pa)
        results = cpa.find_critical_paths(["A"], ["B"])
        assert results == []

    def test_critical_paths_with_budget(self, branched_graph):
        pa = PathAnalyzer(branched_graph)
        cpa = CriticalPathAnalyzer(branched_graph, pa)
        results = cpa.find_critical_paths(["internet"], ["db", "backup"], top_n=1)
        assert len(results) == 1

    def test_path_criticality_includes_node_risk(self, simple_graph):
        pa = PathAnalyzer(simple_graph)
        cpa = CriticalPathAnalyzer(simple_graph, pa)
        # Path through high-risk node should score higher
        high_risk_path = ["A", "B", "C", "D"]  # D has risk 0.9
        score = cpa.compute_path_criticality(high_risk_path)
        # Empty path should score 0
        empty_score = cpa.compute_path_criticality([])
        assert empty_score == 0.0
        assert score > empty_score


# ─── AttackSurfaceQuantifier Tests ─────────────────────────────────────────

class TestAttackSurfaceQuantifier:
    def test_quantify_attack_surface_basic(self, simple_graph):
        asq = AttackSurfaceQuantifier(simple_graph)
        metrics = asq.quantify_attack_surface(["A"])
        assert metrics["total_nodes"] == 4
        assert metrics["reachable_nodes"] == 4
        assert metrics["unreachable_nodes"] == 0
        assert metrics["attack_surface_ratio"] == 1.0

    def test_exposure_score_for_entry_node(self, simple_graph):
        asq = AttackSurfaceQuantifier(simple_graph)
        score = asq.get_exposure_score("A")
        # A has risk 0.1, 0 predecessors, 1 successor
        # exposure = 0.1 * (1+0) * (1+1) = 0.2
        assert score == pytest.approx(0.2)

    def test_exposure_score_for_unreachable_node(self, disconnected_graph):
        asq = AttackSurfaceQuantifier(disconnected_graph)
        # X is not reachable from A
        score = asq.get_exposure_score("X")
        # X has risk 0.1, 0 predecessors, 1 successor
        assert score == pytest.approx(0.2)

    def test_attack_surface_ratio(self, disconnected_graph):
        asq = AttackSurfaceQuantifier(disconnected_graph)
        ratio = asq.get_attack_surface_ratio(["A"])
        # Only A and B reachable from A, out of 4 total
        assert ratio == pytest.approx(0.5)

    def test_attack_surface_empty_graph(self):
        g = AttackGraph()
        asq = AttackSurfaceQuantifier(g)
        metrics = asq.quantify_attack_surface(["A"])
        assert metrics["total_nodes"] == 0
        assert metrics["attack_surface_ratio"] == 0.0

    def test_attack_surface_with_multiple_entries(self, disconnected_graph):
        asq = AttackSurfaceQuantifier(disconnected_graph)
        metrics = asq.quantify_attack_surface(["A", "X"])
        assert metrics["reachable_nodes"] == 4
        assert metrics["attack_surface_ratio"] == 1.0

    def test_exposure_score_nonexistent_node(self, simple_graph):
        asq = AttackSurfaceQuantifier(simple_graph)
        with pytest.raises(KeyError):
            asq.get_exposure_score("Z")


# ─── MitigationPrioritizer Tests ───────────────────────────────────────────

class TestMitigationPrioritizer:
    def test_prioritize_mitigations_by_roi(self, branched_graph):
        cna = CriticalNodeAnalyzer(branched_graph)
        mp = MitigationPrioritizer(branched_graph, cna)
        mitigations = mp.prioritize_mitigations()
        assert len(mitigations) > 0
        rois = [m["roi"] for m in mitigations]
        assert rois == sorted(rois, reverse=True)

    def test_mitigation_roi_computation(self, simple_graph):
        cna = CriticalNodeAnalyzer(simple_graph)
        mp = MitigationPrioritizer(simple_graph, cna)
        roi = mp.get_mitigation_roi("B")
        # B: risk=0.3, type=host -> cost=1, risk_reduction=0.3*0.8=0.24
        # roi = 0.24 / 1 = 0.24
        assert roi == pytest.approx(0.24)

    def test_optimal_mitigation_set_within_budget(self, branched_graph):
        cna = CriticalNodeAnalyzer(branched_graph)
        mp = MitigationPrioritizer(branched_graph, cna)
        selected = mp.get_optimal_mitigation_set(budget=5)
        assert len(selected) > 0
        total_cost = sum(m["cost"] for m in selected)
        assert total_cost <= 5

    def test_optimal_mitigation_set_empty_budget(self, branched_graph):
        cna = CriticalNodeAnalyzer(branched_graph)
        mp = MitigationPrioritizer(branched_graph, cna)
        selected = mp.get_optimal_mitigation_set(budget=0)
        assert selected == []

    def test_mitigation_effectiveness_score(self, simple_graph):
        cna = CriticalNodeAnalyzer(simple_graph)
        mp = MitigationPrioritizer(simple_graph, cna)
        mitigations = mp.prioritize_mitigations()
        assert all("risk_reduction" in m for m in mitigations)
        assert all("cost" in m for m in mitigations)
        assert all("roi" in m for m in mitigations)

    def test_prioritize_mitigations_empty_graph(self):
        g = AttackGraph()
        cna = CriticalNodeAnalyzer(g)
        mp = MitigationPrioritizer(g, cna)
        mitigations = mp.prioritize_mitigations()
        assert mitigations == []

    def test_mitigation_roi_nonexistent_node(self, simple_graph):
        cna = CriticalNodeAnalyzer(simple_graph)
        mp = MitigationPrioritizer(simple_graph, cna)
        with pytest.raises(KeyError):
            mp.get_mitigation_roi("Z")

    def test_optimal_mitigation_set_prioritizes_high_roi(self, branched_graph):
        cna = CriticalNodeAnalyzer(branched_graph)
        mp = MitigationPrioritizer(branched_graph, cna)
        # With budget=1, should pick the highest ROI mitigation
        selected = mp.get_optimal_mitigation_set(budget=1)
        assert len(selected) == 1
        # The selected one should have the highest ROI
        all_mitigations = mp.prioritize_mitigations()
        assert selected[0]["roi"] == all_mitigations[0]["roi"]
