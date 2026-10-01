"""Tests for adversarial co-evolution engine."""
import pytest
from src.cyber.coevolution import (
    AttackTechnique,
    DefenseControl,
    AttackSimulation,
    DefenseHardening,
    CoEvolutionEngine,
    ThreatLandscape,
    AttackOutcome,
    DefenseAction,
)


# ── AttackTechnique ──────────────────────────────────────────────────────────

class TestAttackTechnique:
    def test_create_attack_technique(self):
        at = AttackTechnique(name="SQL Injection", category="injection", severity=0.8)
        assert at.name == "SQL Injection"
        assert at.category == "injection"
        assert at.severity == 0.8

    def test_attack_technique_default_success_prob(self):
        at = AttackTechnique(name="XSS", category="injection", severity=0.5)
        assert at.base_success_prob == 0.5

    def test_attack_technique_custom_success_prob(self):
        at = AttackTechnique(name="RCE", category="exploit", severity=0.9, base_success_prob=0.3)
        assert at.base_success_prob == 0.3

    def test_attack_technique_invalid_severity(self):
        with pytest.raises(ValueError):
            AttackTechnique(name="Test", category="test", severity=1.5)

    def test_attack_technique_invalid_severity_negative(self):
        with pytest.raises(ValueError):
            AttackTechnique(name="Test", category="test", severity=-0.1)

    def test_attack_technique_invalid_success_prob(self):
        with pytest.raises(ValueError):
            AttackTechnique(name="Test", category="test", severity=0.5, base_success_prob=1.5)

    def test_attack_technique_to_dict(self):
        at = AttackTechnique(name="Phishing", category="social", severity=0.6, base_success_prob=0.4)
        d = at.to_dict()
        assert d["name"] == "Phishing"
        assert d["category"] == "social"
        assert d["severity"] == 0.6
        assert d["base_success_prob"] == 0.4

    def test_attack_technique_from_dict(self):
        d = {"name": "DDoS", "category": "availability", "severity": 0.7, "base_success_prob": 0.6}
        at = AttackTechnique.from_dict(d)
        assert at.name == "DDoS"
        assert at.category == "availability"
        assert at.severity == 0.7
        assert at.base_success_prob == 0.6


# ── DefenseControl ───────────────────────────────────────────────────────────

class TestDefenseControl:
    def test_create_defense_control(self):
        dc = DefenseControl(name="WAF", category="network", effectiveness=0.7)
        assert dc.name == "WAF"
        assert dc.category == "network"
        assert dc.effectiveness == 0.7

    def test_defense_control_mitigates(self):
        dc = DefenseControl(name="WAF", category="network", effectiveness=0.7)
        at = AttackTechnique(name="SQLi", category="injection", severity=0.8)
        assert dc.mitigates(at) is True

    def test_defense_control_does_not_mitigate(self):
        dc = DefenseControl(name="WAF", category="network", effectiveness=0.7)
        at = AttackTechnique(name="Phishing", category="social", severity=0.5)
        assert dc.mitigates(at) is False

    def test_defense_control_invalid_effectiveness(self):
        with pytest.raises(ValueError):
            DefenseControl(name="Test", category="test", effectiveness=1.5)

    def test_defense_control_to_dict(self):
        dc = DefenseControl(name="IDS", category="network", effectiveness=0.6)
        d = dc.to_dict()
        assert d["name"] == "IDS"
        assert d["category"] == "network"
        assert d["effectiveness"] == 0.6

    def test_defense_control_from_dict(self):
        d = {"name": "Firewall", "category": "network", "effectiveness": 0.8}
        dc = DefenseControl.from_dict(d)
        assert dc.name == "Firewall"
        assert dc.effectiveness == 0.8


# ── AttackSimulation ─────────────────────────────────────────────────────────

class TestAttackSimulation:
    def test_simulate_attack_success(self):
        sim = AttackSimulation(seed=42)
        at = AttackTechnique(name="Test", category="test", severity=0.5, base_success_prob=1.0)
        outcome = sim.simulate(at, defenses=[])
        assert outcome.success is True
        assert outcome.technique_name == "Test"

    def test_simulate_attack_blocked_by_defense(self):
        sim = AttackSimulation(seed=42)
        at = AttackTechnique(name="SQLi", category="injection", severity=0.8, base_success_prob=0.9)
        dc = DefenseControl(name="WAF", category="injection", effectiveness=1.0)
        outcome = sim.simulate(at, defenses=[dc])
        assert outcome.success is False

    def test_simulate_attack_partial_defense(self):
        sim = AttackSimulation(seed=42)
        at = AttackTechnique(name="XSS", category="injection", severity=0.5, base_success_prob=0.5)
        dc = DefenseControl(name="WAF", category="injection", effectiveness=0.5)
        outcome = sim.simulate(at, defenses=[dc])
        assert isinstance(outcome.success, bool)

    def test_simulate_attack_no_defenses(self):
        sim = AttackSimulation(seed=42)
        at = AttackTechnique(name="Test", category="test", severity=0.5, base_success_prob=0.0)
        outcome = sim.simulate(at, defenses=[])
        assert outcome.success is False

    def test_simulate_multiple_defenses(self):
        sim = AttackSimulation(seed=42)
        at = AttackTechnique(name="SQLi", category="injection", severity=0.8, base_success_prob=0.9)
        dc1 = DefenseControl(name="WAF", category="injection", effectiveness=0.5)
        dc2 = DefenseControl(name="IDS", category="injection", effectiveness=0.5)
        outcome = sim.simulate(at, defenses=[dc1, dc2])
        assert outcome.success is False

    def test_simulate_deterministic_with_seed(self):
        sim1 = AttackSimulation(seed=123)
        sim2 = AttackSimulation(seed=123)
        at = AttackTechnique(name="Test", category="test", severity=0.5, base_success_prob=0.5)
        outcome1 = sim1.simulate(at, defenses=[])
        outcome2 = sim2.simulate(at, defenses=[])
        assert outcome1.success == outcome2.success

    def test_simulate_different_seeds(self):
        sim1 = AttackSimulation(seed=1)
        sim2 = AttackSimulation(seed=999)
        at = AttackTechnique(name="Test", category="test", severity=0.5, base_success_prob=0.5)
        outcomes1 = [sim1.simulate(at, defenses=[]).success for _ in range(10)]
        outcomes2 = [sim2.simulate(at, defenses=[]).success for _ in range(10)]
        assert outcomes1 != outcomes2

    def test_outcome_has_severity(self):
        sim = AttackSimulation(seed=42)
        at = AttackTechnique(name="Test", category="test", severity=0.7, base_success_prob=1.0)
        outcome = sim.simulate(at, defenses=[])
        assert outcome.severity == 0.7

    def test_outcome_has_category(self):
        sim = AttackSimulation(seed=42)
        at = AttackTechnique(name="Test", category="exploit", severity=0.5, base_success_prob=1.0)
        outcome = sim.simulate(at, defenses=[])
        assert outcome.category == "exploit"


# ── DefenseHardening ─────────────────────────────────────────────────────────

class TestDefenseHardening:
    def test_harden_from_successful_attack(self):
        dh = DefenseHardening()
        at = AttackTechnique(name="SQLi", category="injection", severity=0.8)
        action = dh.harden(at, was_successful=True)
        assert action.action_type == "add"
        assert action.target_category == "injection"

    def test_harden_from_failed_attack(self):
        dh = DefenseHardening()
        at = AttackTechnique(name="SQLi", category="injection", severity=0.8)
        action = dh.harden(at, was_successful=False)
        assert action.action_type == "strengthen"

    def test_harden_increases_effectiveness(self):
        dh = DefenseHardening()
        at = AttackTechnique(name="SQLi", category="injection", severity=0.8)
        action = dh.harden(at, was_successful=True)
        assert action.new_effectiveness > action.old_effectiveness

    def test_harden_creates_new_defense(self):
        dh = DefenseHardening()
        at = AttackTechnique(name="ZeroDay", category="exploit", severity=0.9)
        action = dh.harden(at, was_successful=True)
        assert action.action_type == "add"
        assert action.defense_name is not None

    def test_harden_strengthens_existing(self):
        dh = DefenseHardening()
        at = AttackTechnique(name="SQLi", category="injection", severity=0.8)
        action = dh.harden(at, was_successful=False)
        assert action.action_type == "strengthen"
        assert action.old_effectiveness >= 0.0


# ── ThreatLandscape ──────────────────────────────────────────────────────────

class TestThreatLandscape:
    def test_create_landscape(self):
        tl = ThreatLandscape()
        assert tl.attack_count == 0
        assert tl.defense_count == 0

    def test_add_attack(self):
        tl = ThreatLandscape()
        at = AttackTechnique(name="SQLi", category="injection", severity=0.8)
        tl.add_attack(at)
        assert tl.attack_count == 1

    def test_add_defense(self):
        tl = ThreatLandscape()
        dc = DefenseControl(name="WAF", category="network", effectiveness=0.7)
        tl.add_defense(dc)
        assert tl.defense_count == 1

    def test_get_attacks_by_category(self):
        tl = ThreatLandscape()
        at1 = AttackTechnique(name="SQLi", category="injection", severity=0.8)
        at2 = AttackTechnique(name="XSS", category="injection", severity=0.6)
        at3 = AttackTechnique(name="DDoS", category="availability", severity=0.7)
        tl.add_attack(at1)
        tl.add_attack(at2)
        tl.add_attack(at3)
        injection_attacks = tl.get_attacks_by_category("injection")
        assert len(injection_attacks) == 2

    def test_get_defenses_by_category(self):
        tl = ThreatLandscape()
        dc1 = DefenseControl(name="WAF", category="network", effectiveness=0.7)
        dc2 = DefenseControl(name="IDS", category="network", effectiveness=0.6)
        dc3 = DefenseControl(name="AV", category="endpoint", effectiveness=0.8)
        tl.add_defense(dc1)
        tl.add_defense(dc2)
        tl.add_defense(dc3)
        network_defenses = tl.get_defenses_by_category("network")
        assert len(network_defenses) == 2

    def test_attack_history_empty(self):
        tl = ThreatLandscape()
        assert len(tl.attack_history) == 0

    def test_defense_history_empty(self):
        tl = ThreatLandscape()
        assert len(tl.defense_history) == 0

    def test_record_attack_outcome(self):
        tl = ThreatLandscape()
        at = AttackTechnique(name="SQLi", category="injection", severity=0.8)
        tl.add_attack(at)
        outcome = AttackOutcome(
            technique_name="SQLi",
            category="injection",
            severity=0.8,
            success=True,
            timestamp=0.0,
        )
        tl.record_attack_outcome(outcome)
        assert len(tl.attack_history) == 1

    def test_record_defense_action(self):
        tl = ThreatLandscape()
        dc = DefenseControl(name="WAF", category="network", effectiveness=0.7)
        tl.add_defense(dc)
        action = DefenseAction(
            action_type="add",
            target_category="network",
            defense_name="WAF",
            old_effectiveness=0.0,
            new_effectiveness=0.7,
            timestamp=0.0,
        )
        tl.record_defense_action(action)
        assert len(tl.defense_history) == 1

    def test_get_success_rate(self):
        tl = ThreatLandscape()
        at = AttackTechnique(name="SQLi", category="injection", severity=0.8)
        tl.add_attack(at)
        tl.record_attack_outcome(AttackOutcome("SQLi", "injection", 0.8, True, 0.0))
        tl.record_attack_outcome(AttackOutcome("SQLi", "injection", 0.8, False, 1.0))
        assert tl.get_success_rate() == 0.5

    def test_get_success_rate_no_attacks(self):
        tl = ThreatLandscape()
        assert tl.get_success_rate() == 0.0

    def test_get_coverage(self):
        tl = ThreatLandscape()
        at1 = AttackTechnique(name="SQLi", category="injection", severity=0.8)
        at2 = AttackTechnique(name="DDoS", category="availability", severity=0.7)
        tl.add_attack(at1)
        tl.add_attack(at2)
        dc1 = DefenseControl(name="WAF", category="injection", effectiveness=0.7)
        tl.add_defense(dc1)
        assert tl.get_coverage() == 0.5

    def test_get_coverage_no_attacks(self):
        tl = ThreatLandscape()
        assert tl.get_coverage() == 0.0

    def test_reset(self):
        tl = ThreatLandscape()
        at = AttackTechnique(name="SQLi", category="injection", severity=0.8)
        tl.add_attack(at)
        dc = DefenseControl(name="WAF", category="network", effectiveness=0.7)
        tl.add_defense(dc)
        tl.reset()
        assert tl.attack_count == 0
        assert tl.defense_count == 0
        assert len(tl.attack_history) == 0
        assert len(tl.defense_history) == 0


# ── CoEvolutionEngine ────────────────────────────────────────────────────────

class TestCoEvolutionEngine:
    def test_create_engine(self):
        engine = CoEvolutionEngine(seed=42)
        assert engine.iteration == 0

    def test_run_single_iteration(self):
        engine = CoEvolutionEngine(seed=42)
        at = AttackTechnique(name="SQLi", category="injection", severity=0.8)
        engine.add_attack_technique(at)
        engine.run_iteration()
        assert engine.iteration == 1

    def test_run_multiple_iterations(self):
        engine = CoEvolutionEngine(seed=42)
        at = AttackTechnique(name="SQLi", category="injection", severity=0.8)
        engine.add_attack_technique(at)
        engine.run_iterations(5)
        assert engine.iteration == 5

    def test_engine_adds_defense_after_successful_attack(self):
        engine = CoEvolutionEngine(seed=42)
        at = AttackTechnique(name="SQLi", category="injection", severity=0.8, base_success_prob=1.0)
        engine.add_attack_technique(at)
        engine.run_iterations(3)
        assert engine.landscape.defense_count > 0

    def test_engine_improves_defense_over_time(self):
        engine = CoEvolutionEngine(seed=42)
        at = AttackTechnique(name="SQLi", category="injection", severity=0.8, base_success_prob=0.9)
        engine.add_attack_technique(at)
        engine.run_iterations(10)
        assert engine.landscape.get_coverage() > 0.0

    def test_engine_success_rate_decreases(self):
        engine = CoEvolutionEngine(seed=42)
        at = AttackTechnique(name="SQLi", category="injection", severity=0.8, base_success_prob=0.9)
        engine.add_attack_technique(at)
        engine.run_iterations(10)
        assert engine.landscape.get_success_rate() < 0.9

    def test_engine_with_multiple_attacks(self):
        engine = CoEvolutionEngine(seed=42)
        at1 = AttackTechnique(name="SQLi", category="injection", severity=0.8)
        at2 = AttackTechnique(name="XSS", category="injection", severity=0.6)
        at3 = AttackTechnique(name="DDoS", category="availability", severity=0.7)
        engine.add_attack_technique(at1)
        engine.add_attack_technique(at2)
        engine.add_attack_technique(at3)
        engine.run_iterations(5)
        assert engine.iteration == 5
        assert engine.landscape.attack_count == 3

    def test_engine_with_no_attacks(self):
        engine = CoEvolutionEngine(seed=42)
        engine.run_iterations(3)
        assert engine.iteration == 3
        assert engine.landscape.attack_count == 0

    def test_engine_metrics_tracked(self):
        engine = CoEvolutionEngine(seed=42)
        at = AttackTechnique(name="SQLi", category="injection", severity=0.8)
        engine.add_attack_technique(at)
        engine.run_iterations(5)
        metrics = engine.get_metrics()
        assert "iterations" in metrics
        assert "attack_count" in metrics
        assert "defense_count" in metrics
        assert "success_rate" in metrics
        assert "coverage" in metrics

    def test_engine_reset(self):
        engine = CoEvolutionEngine(seed=42)
        at = AttackTechnique(name="SQLi", category="injection", severity=0.8)
        engine.add_attack_technique(at)
        engine.run_iterations(3)
        engine.reset()
        assert engine.iteration == 0
        assert engine.landscape.attack_count == 0

    def test_engine_add_defense_control(self):
        engine = CoEvolutionEngine(seed=42)
        dc = DefenseControl(name="WAF", category="network", effectiveness=0.7)
        engine.add_defense_control(dc)
        assert engine.landscape.defense_count == 1

    def test_engine_get_attack_techniques(self):
        engine = CoEvolutionEngine(seed=42)
        at = AttackTechnique(name="SQLi", category="injection", severity=0.8)
        engine.add_attack_technique(at)
        techniques = engine.get_attack_techniques()
        assert len(techniques) == 1
        assert techniques[0].name == "SQLi"

    def test_engine_get_defense_controls(self):
        engine = CoEvolutionEngine(seed=42)
        dc = DefenseControl(name="WAF", category="network", effectiveness=0.7)
        engine.add_defense_control(dc)
        defenses = engine.get_defense_controls()
        assert len(defenses) == 1
        assert defenses[0].name == "WAF"

    def test_engine_converges(self):
        engine = CoEvolutionEngine(seed=42)
        at = AttackTechnique(name="SQLi", category="injection", severity=0.8, base_success_prob=0.9)
        engine.add_attack_technique(at)
        engine.run_iterations(20)
        assert engine.landscape.get_success_rate() < 0.5

    def test_engine_deterministic(self):
        engine1 = CoEvolutionEngine(seed=42)
        engine2 = CoEvolutionEngine(seed=42)
        at = AttackTechnique(name="SQLi", category="injection", severity=0.8)
        engine1.add_attack_technique(at)
        engine2.add_attack_technique(at)
        engine1.run_iterations(5)
        engine2.run_iterations(5)
        assert engine1.landscape.get_success_rate() == engine2.landscape.get_success_rate()

    def test_engine_export_state(self):
        engine = CoEvolutionEngine(seed=42)
        at = AttackTechnique(name="SQLi", category="injection", severity=0.8)
        engine.add_attack_technique(at)
        engine.run_iterations(3)
        state = engine.export_state()
        assert "iteration" in state
        assert "attacks" in state
        assert "defenses" in state
        assert "metrics" in state

    def test_engine_import_state(self):
        engine = CoEvolutionEngine(seed=42)
        at = AttackTechnique(name="SQLi", category="injection", severity=0.8)
        engine.add_attack_technique(at)
        engine.run_iterations(3)
        state = engine.export_state()

        engine2 = CoEvolutionEngine(seed=99)
        engine2.import_state(state)
        assert engine2.iteration == 3
        assert engine2.landscape.attack_count == 1

    def test_engine_import_state_preserves_defenses(self):
        engine = CoEvolutionEngine(seed=42)
        at = AttackTechnique(name="SQLi", category="injection", severity=0.8, base_success_prob=1.0)
        engine.add_attack_technique(at)
        engine.run_iterations(5)
        state = engine.export_state()

        engine2 = CoEvolutionEngine(seed=99)
        engine2.import_state(state)
        assert engine2.landscape.defense_count == engine.landscape.defense_count

    def test_engine_run_iteration_returns_results(self):
        engine = CoEvolutionEngine(seed=42)
        at = AttackTechnique(name="SQLi", category="injection", severity=0.8)
        engine.add_attack_technique(at)
        results = engine.run_iteration()
        assert "attacks" in results
        assert "defenses_added" in results
        assert "success_rate" in results

    def test_engine_with_defense_already_present(self):
        engine = CoEvolutionEngine(seed=42)
        at = AttackTechnique(name="SQLi", category="injection", severity=0.8, base_success_prob=0.9)
        dc = DefenseControl(name="WAF", category="injection", effectiveness=0.5)
        engine.add_attack_technique(at)
        engine.add_defense_control(dc)
        engine.run_iterations(5)
        assert engine.landscape.defense_count >= 1

    def test_engine_coverage_increases(self):
        engine = CoEvolutionEngine(seed=42)
        at1 = AttackTechnique(name="SQLi", category="injection", severity=0.8)
        at2 = AttackTechnique(name="DDoS", category="availability", severity=0.7)
        engine.add_attack_technique(at1)
        engine.add_attack_technique(at2)
        engine.run_iterations(10)
        assert engine.landscape.get_coverage() > 0.0

    def test_engine_attack_history_grows(self):
        engine = CoEvolutionEngine(seed=42)
        at = AttackTechnique(name="SQLi", category="injection", severity=0.8)
        engine.add_attack_technique(at)
        engine.run_iterations(5)
        assert len(engine.landscape.attack_history) > 0

    def test_engine_defense_history_grows(self):
        engine = CoEvolutionEngine(seed=42)
        at = AttackTechnique(name="SQLi", category="injection", severity=0.8, base_success_prob=1.0)
        engine.add_attack_technique(at)
        engine.run_iterations(5)
        assert len(engine.landscape.defense_history) > 0

    def test_engine_multiple_categories(self):
        engine = CoEvolutionEngine(seed=42)
        at1 = AttackTechnique(name="SQLi", category="injection", severity=0.8)
        at2 = AttackTechnique(name="DDoS", category="availability", severity=0.7)
        at3 = AttackTechnique(name="Phishing", category="social", severity=0.6)
        engine.add_attack_technique(at1)
        engine.add_attack_technique(at2)
        engine.add_attack_technique(at3)
        engine.run_iterations(10)
        assert engine.landscape.attack_count == 3
        assert engine.landscape.get_coverage() > 0.0

    def test_engine_iteration_zero_no_attacks(self):
        engine = CoEvolutionEngine(seed=42)
        results = engine.run_iteration()
        assert results["attacks"] == []
        assert results["defenses_added"] == []
