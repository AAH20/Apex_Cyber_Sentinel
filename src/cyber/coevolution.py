"""Adversarial co-evolution engine for autonomous cyber defense."""
import random
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass
class AttackTechnique:
    """Represents an attack technique in the red team arsenal."""

    name: str
    category: str
    severity: float
    base_success_prob: float = 0.5

    def __post_init__(self) -> None:
        if not 0.0 <= self.severity <= 1.0:
            raise ValueError("severity must be between 0 and 1")
        if not 0.0 <= self.base_success_prob <= 1.0:
            raise ValueError("base_success_prob must be between 0 and 1")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "category": self.category,
            "severity": self.severity,
            "base_success_prob": self.base_success_prob,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "AttackTechnique":
        return cls(
            name=d["name"],
            category=d["category"],
            severity=d["severity"],
            base_success_prob=d.get("base_success_prob", 0.5),
        )


@dataclass
class DefenseControl:
    """Represents a defensive control in the blue team arsenal."""

    name: str
    category: str
    effectiveness: float

    def __post_init__(self) -> None:
        if not 0.0 <= self.effectiveness <= 1.0:
            raise ValueError("effectiveness must be between 0 and 1")

    def mitigates(self, attack: AttackTechnique) -> bool:
        """Check if this defense can mitigate the given attack."""
        if self.category == attack.category:
            return True
        if self.category == "network" and attack.category != "social":
            return True
        return False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "category": self.category,
            "effectiveness": self.effectiveness,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "DefenseControl":
        return cls(
            name=d["name"],
            category=d["category"],
            effectiveness=d["effectiveness"],
        )


@dataclass
class AttackOutcome:
    """Result of a simulated attack."""

    technique_name: str
    category: str
    severity: float
    success: bool
    timestamp: float


@dataclass
class DefenseAction:
    """Action taken by the defense hardening system."""

    action_type: str
    target_category: str
    defense_name: str
    old_effectiveness: float
    new_effectiveness: float
    timestamp: float


class AttackSimulation:
    """Simulates attacks against defenses using probabilistic outcomes."""

    def __init__(self, seed: int = 42) -> None:
        self._rng = random.Random(seed)

    def simulate(
        self, attack: AttackTechnique, defenses: List[DefenseControl]
    ) -> AttackOutcome:
        """Simulate an attack and return the outcome."""
        prob = attack.base_success_prob
        for defense in defenses:
            if defense.mitigates(attack):
                prob *= 1.0 - defense.effectiveness
        success = self._rng.random() < prob
        return AttackOutcome(
            technique_name=attack.name,
            category=attack.category,
            severity=attack.severity,
            success=success,
            timestamp=time.time(),
        )


class DefenseHardening:
    """Generates defense actions based on attack outcomes."""

    def __init__(self, seed: int = 42) -> None:
        self._rng = random.Random(seed)
        self._counter = 0

    def harden(self, attack: AttackTechnique, was_successful: bool) -> DefenseAction:
        """Generate a defense action based on whether the attack succeeded."""
        if was_successful:
            self._counter += 1
            effectiveness = 0.3 + self._rng.random() * 0.4
            return DefenseAction(
                action_type="add",
                target_category=attack.category,
                defense_name=f"Auto-Defense-{self._counter}",
                old_effectiveness=0.0,
                new_effectiveness=effectiveness,
                timestamp=time.time(),
            )
        return DefenseAction(
            action_type="strengthen",
            target_category=attack.category,
            defense_name=f"Strengthen-{attack.category}",
            old_effectiveness=0.5,
            new_effectiveness=0.7,
            timestamp=time.time(),
        )


class ThreatLandscape:
    """Tracks the current state of attacks, defenses, and their history."""

    def __init__(self) -> None:
        self._attacks: List[AttackTechnique] = []
        self._defenses: List[DefenseControl] = []
        self.attack_history: List[AttackOutcome] = []
        self.defense_history: List[DefenseAction] = []

    @property
    def attack_count(self) -> int:
        return len(self._attacks)

    @property
    def defense_count(self) -> int:
        return len(self._defenses)

    def add_attack(self, attack: AttackTechnique) -> None:
        self._attacks.append(attack)

    def add_defense(self, defense: DefenseControl) -> None:
        self._defenses.append(defense)

    def get_attacks_by_category(self, category: str) -> List[AttackTechnique]:
        return [a for a in self._attacks if a.category == category]

    def get_defenses_by_category(self, category: str) -> List[DefenseControl]:
        return [d for d in self._defenses if d.category == category]

    def record_attack_outcome(self, outcome: AttackOutcome) -> None:
        self.attack_history.append(outcome)

    def record_defense_action(self, action: DefenseAction) -> None:
        self.defense_history.append(action)

    def get_success_rate(self) -> float:
        if not self.attack_history:
            return 0.0
        successes = sum(1 for o in self.attack_history if o.success)
        return successes / len(self.attack_history)

    def get_coverage(self) -> float:
        if not self._attacks:
            return 0.0
        attack_categories = {a.category for a in self._attacks}
        defense_categories = {d.category for d in self._defenses}
        covered = attack_categories & defense_categories
        return len(covered) / len(attack_categories)

    def reset(self) -> None:
        self._attacks.clear()
        self._defenses.clear()
        self.attack_history.clear()
        self.defense_history.clear()


class CoEvolutionEngine:
    """Main adversarial co-evolution engine.

    Runs red/blue team iterations where attacks are simulated and defenses
    are hardened in response, creating a continuous improvement loop.
    """

    def __init__(self, seed: int = 42) -> None:
        self._seed = seed
        self.landscape = ThreatLandscape()
        self._simulation = AttackSimulation(seed)
        self._hardening = DefenseHardening(seed)
        self.iteration = 0

    def add_attack_technique(self, attack: AttackTechnique) -> None:
        self.landscape.add_attack(attack)

    def add_defense_control(self, defense: DefenseControl) -> None:
        self.landscape.add_defense(defense)

    def get_attack_techniques(self) -> List[AttackTechnique]:
        return list(self.landscape._attacks)

    def get_defense_controls(self) -> List[DefenseControl]:
        return list(self.landscape._defenses)

    def run_iteration(self) -> Dict[str, Any]:
        """Run a single co-evolution iteration.

        Simulates all attacks, records outcomes, and hardens defenses
        based on the results.
        """
        self.iteration += 1
        attacks_results: List[AttackOutcome] = []
        defenses_added: List[DefenseControl] = []

        for attack in self.landscape._attacks:
            outcome = self._simulation.simulate(attack, self.landscape._defenses)
            self.landscape.record_attack_outcome(outcome)
            attacks_results.append(outcome)

            action = self._hardening.harden(attack, outcome.success)
            self.landscape.record_defense_action(action)

            if action.action_type == "add":
                new_defense = DefenseControl(
                    name=action.defense_name,
                    category=action.target_category,
                    effectiveness=action.new_effectiveness,
                )
                self.landscape.add_defense(new_defense)
                defenses_added.append(new_defense)
            elif action.action_type == "strengthen":
                existing = self.landscape.get_defenses_by_category(
                    action.target_category
                )
                if existing:
                    existing[0].effectiveness = min(
                        1.0, existing[0].effectiveness + 0.1
                    )

        return {
            "attacks": attacks_results,
            "defenses_added": defenses_added,
            "success_rate": self.landscape.get_success_rate(),
        }

    def run_iterations(self, n: int) -> None:
        """Run multiple co-evolution iterations."""
        for _ in range(n):
            self.run_iteration()

    def get_metrics(self) -> Dict[str, Any]:
        """Return current engine metrics."""
        return {
            "iterations": self.iteration,
            "attack_count": self.landscape.attack_count,
            "defense_count": self.landscape.defense_count,
            "success_rate": self.landscape.get_success_rate(),
            "coverage": self.landscape.get_coverage(),
        }

    def export_state(self) -> Dict[str, Any]:
        """Export the current engine state as a serializable dict."""
        return {
            "iteration": self.iteration,
            "attacks": [a.to_dict() for a in self.landscape._attacks],
            "defenses": [d.to_dict() for d in self.landscape._defenses],
            "metrics": self.get_metrics(),
        }

    def import_state(self, state: Dict[str, Any]) -> None:
        """Restore engine state from a previously exported dict."""
        self.iteration = state["iteration"]
        self.landscape.reset()
        for a_dict in state["attacks"]:
            self.landscape.add_attack(AttackTechnique.from_dict(a_dict))
        for d_dict in state["defenses"]:
            self.landscape.add_defense(DefenseControl.from_dict(d_dict))

    def reset(self) -> None:
        """Reset the engine to its initial state."""
        self.iteration = 0
        self.landscape.reset()
