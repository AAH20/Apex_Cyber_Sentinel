"""Tests for attack graph generation, path analysis, critical nodes, and mitigation."""
import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from cyber.attack_graph import (
    AttackGraph, PathAnalyzer, CriticalNodeAnalyzer, MitigationRecommender,
    Node, Edge
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
def cyclic_graph():
    """Graph with cycles."""
    g = AttackGraph()
    g.add_node("A", node_type="entry", risk=0.1)
    g.add_node("B", node_type="host", risk=0.3)
    g.add_node("C", node_type="host", risk=0.5)
    g.add_node("D", node_type="critical", risk=0.9)
    g.add_edge("A", "B", probability=0.8)
    g.add_edge("B", "C", probability=0.7)
    g.add_edge("C", "B", probability=0.3)
    g.add_edge("C", "D", probability=0.9)
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


# ─── AttackGraph Tests ─────────────────────────────────────────────────────

class TestAttackGraph:
    def test_create_empty_graph(self):
        g = AttackGraph()
        assert len(g.get_nodes()) == 0
        assert len(g.get_edges()) == 0

    def test_add_node(self):
        g = AttackGraph()
        g.add_node("host1", node_type="host", risk=0.5)
        nodes = g.get_nodes()
        assert "host1" in nodes
        assert nodes["host1"].node_type == "host"
        assert nodes["host1"].risk == 0.5

    def test_add_node_default_risk(self):
        g = AttackGraph()
        g.add_node("host1")
        assert g.get_nodes()["host1"].risk == 0.5

    def test_add_edge(self):
        g = AttackGraph()
        g.add_node("A")
        g.add_node("B")
        g.add_edge("A", "B", probability=0.7)
        edges = g.get_edges()
        assert ("A", "B") in edges
        assert edges[("A", "B")].probability == 0.7

    def test_add_edge_default_probability(self):
        g = AttackGraph()
        g.add_node("A")
        g.add_node("B")
        g.add_edge("A", "B")
        assert g.get_edges()[("A", "B")].probability == 1.0

    def test_add_edge_auto_creates_nodes(self):
        g = AttackGraph()
        g.add_edge("X", "Y", probability=0.5)
        assert "X" in g.get_nodes()
        assert "Y" in g.get_nodes()

    def test_get_neighbors(self, simple_graph):
        neighbors = simple_graph.get_neighbors("B")
        assert "C" in neighbors
        assert "A" not in neighbors

    def test_get_predecessors(self, simple_graph):
        preds = simple_graph.get_predecessors("C")
        assert "B" in preds
        assert "D" not in preds

    def test_remove_node(self, simple_graph):
        simple_graph.remove_node("B")
        assert "B" not in simple_graph.get_nodes()
        assert ("A", "B") not in simple_graph.get_edges()
        assert ("B", "C") not in simple_graph.get_edges()

    def test_remove_edge(self, simple_graph):
        simple_graph.remove_edge("B", "C")
        assert ("B", "C") not in simple_graph.get_edges()
        assert "B" in simple_graph.get_nodes()
        assert "C" in simple_graph.get_nodes()

    def test_remove_nonexistent_node_raises(self, simple_graph):
        with pytest.raises(KeyError):
            simple_graph.remove_node("Z")

    def test_remove_nonexistent_edge_raises(self, simple_graph):
        with pytest.raises(KeyError):
            simple_graph.remove_edge("A", "D")

    def test_to_dict(self, simple_graph):
        d = simple_graph.to_dict()
        assert "nodes" in d
        assert "edges" in d
        assert len(d["nodes"]) == 4
        assert len(d["edges"]) == 3

    def test_from_dict(self, simple_graph):
        d = simple_graph.to_dict()
        g2 = AttackGraph.from_dict(d)
        assert len(g2.get_nodes()) == 4
        assert len(g2.get_edges()) == 3
        assert "A" in g2.get_nodes()
        assert ("A", "B") in g2.get_edges()

    def test_node_attributes(self):
        g = AttackGraph()
        g.add_node("h1", node_type="host", risk=0.7, os="linux", ip="10.0.0.1")
        n = g.get_nodes()["h1"]
        assert n.os == "linux"
        assert n.ip == "10.0.0.1"

    def test_edge_attributes(self):
        g = AttackGraph()
        g.add_edge("A", "B", probability=0.5, technique="T1190", port=443)
        e = g.get_edges()[("A", "B")]
        assert e.technique == "T1190"
        assert e.port == 443

    def test_get_nodes_by_type(self, branched_graph):
        critical = branched_graph.get_nodes_by_type("critical")
        assert "db" in critical
        assert "backup" in critical
        assert "fw" not in critical

    def test_get_entry_points(self, branched_graph):
        entries = branched_graph.get_entry_points()
        assert "internet" in entries

    def test_get_critical_assets(self, branched_graph):
        critical = branched_graph.get_critical_assets()
        assert "db" in critical
        assert "backup" in critical

    def test_graph_size(self, simple_graph):
        assert simple_graph.node_count() == 4
        assert simple_graph.edge_count() == 3

    def test_has_path(self, simple_graph):
        assert simple_graph.has_path("A", "D")
        assert not simple_graph.has_path("D", "A")

    def test_has_path_disconnected(self, disconnected_graph):
        assert not disconnected_graph.has_path("A", "Y")
        assert disconnected_graph.has_path("X", "Y")

    def test_self_loop(self):
        g = AttackGraph()
        g.add_node("A")
        g.add_edge("A", "A", probability=0.5)
        assert ("A", "A") in g.get_edges()
        assert g.has_path("A", "A")


# ─── PathAnalyzer Tests ────────────────────────────────────────────────────

class TestPathAnalyzer:
    def test_find_all_paths_simple(self, simple_graph):
        pa = PathAnalyzer(simple_graph)
        paths = pa.find_all_paths("A", "D")
        assert len(paths) == 1
        assert paths[0] == ["A", "B", "C", "D"]

    def test_find_all_paths_branched(self, branched_graph):
        pa = PathAnalyzer(branched_graph)
        paths = pa.find_all_paths("internet", "db")
        assert len(paths) == 2
        path_strs = ["->".join(p) for p in paths]
        assert "internet->fw->dmz->db" in path_strs
        assert "internet->fw->app->db" in path_strs

    def test_find_all_paths_no_path(self, disconnected_graph):
        pa = PathAnalyzer(disconnected_graph)
        paths = pa.find_all_paths("A", "Y")
        assert len(paths) == 0

    def test_find_all_paths_with_cycle(self, cyclic_graph):
        pa = PathAnalyzer(cyclic_graph)
        paths = pa.find_all_paths("A", "D")
        assert len(paths) >= 1
        # Should not infinite loop
        for p in paths:
            assert len(p) <= 10

    def test_find_shortest_path(self, branched_graph):
        pa = PathAnalyzer(branched_graph)
        path = pa.find_shortest_path("internet", "db")
        assert path is not None
        assert path[0] == "internet"
        assert path[-1] == "db"
        assert len(path) == 4  # internet -> fw -> dmz -> db

    def test_find_shortest_path_no_path(self, disconnected_graph):
        pa = PathAnalyzer(disconnected_graph)
        path = pa.find_shortest_path("A", "Y")
        assert path is None

    def test_find_paths_from_entry_points(self, branched_graph):
        pa = PathAnalyzer(branched_graph)
        paths = pa.find_paths_from_entry_points(["internet"], ["db", "backup"])
        assert len(paths) >= 2
        targets = [p[-1] for p in paths]
        assert "db" in targets
        assert "backup" in targets

    def test_calculate_path_risk(self, simple_graph):
        pa = PathAnalyzer(simple_graph)
        path = ["A", "B", "C", "D"]
        risk = pa.calculate_path_risk(path)
        # Risk = product of edge probabilities * product of node risks
        assert 0 < risk < 1

    def test_calculate_path_risk_single_node(self, simple_graph):
        pa = PathAnalyzer(simple_graph)
        risk = pa.calculate_path_risk(["A"])
        assert risk == simple_graph.get_nodes()["A"].risk

    def test_get_path_statistics(self, branched_graph):
        pa = PathAnalyzer(branched_graph)
        stats = pa.get_path_statistics(["internet"], ["db", "backup"])
        assert "total_paths" in stats
        assert "avg_length" in stats
        assert "max_risk" in stats
        assert "min_risk" in stats
        assert stats["total_paths"] >= 2

    def test_find_all_paths_max_depth(self, cyclic_graph):
        pa = PathAnalyzer(cyclic_graph)
        paths = pa.find_all_paths("A", "D", max_depth=3)
        # With max_depth=3, A->B->C->D is length 4, so no paths
        assert len(paths) == 0

    def test_find_all_paths_max_depth_sufficient(self, cyclic_graph):
        pa = PathAnalyzer(cyclic_graph)
        paths = pa.find_all_paths("A", "D", max_depth=4)
        assert len(paths) >= 1


# ─── CriticalNodeAnalyzer Tests ───────────────────────────────────────────

class TestCriticalNodeAnalyzer:
    def test_betweenness_centrality(self, simple_graph):
        cna = CriticalNodeAnalyzer(simple_graph)
        bc = cna.betweenness_centrality()
        # B and C are on the only path, so they should have high betweenness
        assert bc["B"] > 0
        assert bc["C"] > 0
        assert bc["A"] == 0  # source
        assert bc["D"] == 0  # sink

    def test_degree_centrality(self, simple_graph):
        cna = CriticalNodeAnalyzer(simple_graph)
        dc = cna.degree_centrality()
        assert "A" in dc
        assert "B" in dc
        assert "C" in dc
        assert "D" in dc

    def test_get_critical_nodes(self, branched_graph):
        cna = CriticalNodeAnalyzer(branched_graph)
        critical = cna.get_critical_nodes(top_n=3)
        assert len(critical) == 3
        # fw should be critical as it's on all paths
        node_ids = [n[0] for n in critical]
        assert "fw" in node_ids

    def test_get_articulation_points(self, simple_graph):
        cna = CriticalNodeAnalyzer(simple_graph)
        aps = cna.get_articulation_points()
        # B and C are articulation points in a linear graph
        assert "B" in aps
        assert "C" in aps

    def test_get_articulation_points_no_aps(self):
        g = AttackGraph()
        g.add_node("A")
        g.add_node("B")
        g.add_node("C")
        g.add_edge("A", "B")
        g.add_edge("B", "C")
        g.add_edge("C", "A")
        cna = CriticalNodeAnalyzer(g)
        aps = cna.get_articulation_points()
        assert len(aps) == 0

    def test_get_node_importance(self, simple_graph):
        cna = CriticalNodeAnalyzer(simple_graph)
        importance = cna.get_node_importance("B")
        assert importance > 0

    def test_get_node_importance_nonexistent(self, simple_graph):
        cna = CriticalNodeAnalyzer(simple_graph)
        with pytest.raises(KeyError):
            cna.get_node_importance("Z")

    def test_critical_nodes_sorted_by_score(self, branched_graph):
        cna = CriticalNodeAnalyzer(branched_graph)
        critical = cna.get_critical_nodes(top_n=5)
        scores = [n[1] for n in critical]
        assert scores == sorted(scores, reverse=True)


# ─── MitigationRecommender Tests ──────────────────────────────────────────

class TestMitigationRecommender:
    def test_recommend_mitigations(self, branched_graph):
        pa = PathAnalyzer(branched_graph)
        cna = CriticalNodeAnalyzer(branched_graph)
        mr = MitigationRecommender(branched_graph, pa, cna)
        recs = mr.recommend_mitigations()
        assert len(recs) > 0
        assert all("node_id" in r for r in recs)
        assert all("priority" in r for r in recs)
        assert all("action" in r for r in recs)

    def test_recommend_mitigations_with_budget(self, branched_graph):
        pa = PathAnalyzer(branched_graph)
        cna = CriticalNodeAnalyzer(branched_graph)
        mr = MitigationRecommender(branched_graph, pa, cna)
        recs = mr.recommend_mitigations(budget=2)
        assert len(recs) <= 2

    def test_prioritize_mitigations(self, branched_graph):
        pa = PathAnalyzer(branched_graph)
        cna = CriticalNodeAnalyzer(branched_graph)
        mr = MitigationRecommender(branched_graph, pa, cna)
        recs = mr.prioritize_mitigations()
        assert len(recs) > 0
        priorities = [r["priority"] for r in recs]
        assert priorities == sorted(priorities)

    def test_get_mitigation_for_node(self, simple_graph):
        pa = PathAnalyzer(simple_graph)
        cna = CriticalNodeAnalyzer(simple_graph)
        mr = MitigationRecommender(simple_graph, pa, cna)
        rec = mr.get_mitigation_for_node("B")
        assert rec is not None
        assert rec["node_id"] == "B"

    def test_get_mitigation_for_nonexistent_node(self, simple_graph):
        pa = PathAnalyzer(simple_graph)
        cna = CriticalNodeAnalyzer(simple_graph)
        mr = MitigationRecommender(simple_graph, pa, cna)
        with pytest.raises(KeyError):
            mr.get_mitigation_for_node("Z")

    def test_mitigation_includes_risk_reduction(self, branched_graph):
        pa = PathAnalyzer(branched_graph)
        cna = CriticalNodeAnalyzer(branched_graph)
        mr = MitigationRecommender(branched_graph, pa, cna)
        recs = mr.recommend_mitigations()
        assert all("risk_reduction" in r for r in recs)

    def test_mitigation_for_critical_asset(self, branched_graph):
        pa = PathAnalyzer(branched_graph)
        cna = CriticalNodeAnalyzer(branched_graph)
        mr = MitigationRecommender(branched_graph, pa, cna)
        rec = mr.get_mitigation_for_node("db")
        assert rec is not None
        assert rec["priority"] <= 2  # High priority for critical assets


# ─── Integration Tests ────────────────────────────────────────────────────

class TestIntegration:
    def test_full_pipeline(self, branched_graph):
        """Test the full pipeline: graph -> paths -> critical nodes -> mitigations."""
        pa = PathAnalyzer(branched_graph)
        cna = CriticalNodeAnalyzer(branched_graph)
        mr = MitigationRecommender(branched_graph, pa, cna)

        # Find paths
        paths = pa.find_paths_from_entry_points(["internet"], ["db", "backup"])
        assert len(paths) >= 2

        # Find critical nodes
        critical = cna.get_critical_nodes(top_n=3)
        assert len(critical) == 3

        # Get mitigations
        recs = mr.recommend_mitigations()
        assert len(recs) > 0

    def test_graph_serialization_roundtrip(self, branched_graph):
        """Test that graph can be serialized and deserialized."""
        d = branched_graph.to_dict()
        g2 = AttackGraph.from_dict(d)
        assert g2.node_count() == branched_graph.node_count()
        assert g2.edge_count() == branched_graph.edge_count()

        # Verify paths are preserved
        pa1 = PathAnalyzer(branched_graph)
        pa2 = PathAnalyzer(g2)
        paths1 = pa1.find_all_paths("internet", "db")
        paths2 = pa2.find_all_paths("internet", "db")
        assert len(paths1) == len(paths2)

    def test_empty_graph_operations(self):
        """Test operations on empty graph."""
        g = AttackGraph()
        pa = PathAnalyzer(g)
        cna = CriticalNodeAnalyzer(g)
        mr = MitigationRecommender(g, pa, cna)

        assert pa.find_all_paths("A", "B") == []
        assert pa.find_shortest_path("A", "B") is None
        assert cna.get_critical_nodes() == []
        assert mr.recommend_mitigations() == []

    def test_large_graph_performance(self):
        """Test that operations complete in reasonable time on larger graph."""
        import time
        g = AttackGraph()
        # Create a grid-like graph
        size = 10
        for i in range(size):
            for j in range(size):
                g.add_node(f"n_{i}_{j}", node_type="host", risk=0.3)
                if i > 0:
                    g.add_edge(f"n_{i-1}_{j}", f"n_{i}_{j}", probability=0.8)
                if j > 0:
                    g.add_edge(f"n_{i}_{j-1}", f"n_{i}_{j}", probability=0.8)

        pa = PathAnalyzer(g)
        start = time.time()
        paths = pa.find_all_paths("n_0_0", f"n_{size-1}_{size-1}", max_depth=25)
        elapsed = time.time() - start
        assert elapsed < 5.0  # Should complete in under 5 seconds
        assert len(paths) > 0
