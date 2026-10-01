"""Sequence anomaly detection, protocol analysis, and encrypted traffic inspection.

Deepens the behavioral grammar with three capabilities:
- SequenceAnomalyDetector: Markov-chain based anomaly detection over event sequences.
- ProtocolAnalyzer: TCP state machine for protocol-level anomaly detection.
- EncryptedTrafficInspector: TLS fingerprinting, entropy analysis, and flow inspection.
"""

from __future__ import annotations

import hashlib
import math
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple


# ── Sequence Anomaly Detection ────────────────────────────────────────


class SequenceAnomalyDetector:
    """Markov-chain based anomaly detection over event symbol sequences.

    Learns transition probabilities between consecutive event symbols.
    Sequences with low-probability transitions are flagged as anomalous.
    """

    def __init__(self):
        self._transition_counts: Dict[Tuple[str, str], int] = defaultdict(int)
        self._symbol_counts: Dict[str, int] = defaultdict(int)
        self._total_transitions: int = 0

    def learn(self, events: List[str]) -> None:
        """Learn transition probabilities from a sequence of event symbols."""
        if not events:
            return

        for i, event in enumerate(events):
            self._symbol_counts[event] += 1
            if i > 0:
                prev = events[i - 1]
                self._transition_counts[(prev, event)] += 1
                self._total_transitions += 1

    def score_sequence(self, events: List[str]) -> float:
        """Score a sequence for anomaly likelihood (0.0 = normal, 1.0 = anomalous)."""
        if not events:
            return 0.0

        if self._total_transitions == 0:
            return 1.0

        anomaly_scores = []
        for i in range(1, len(events)):
            prev = events[i - 1]
            curr = events[i]
            transition = (prev, curr)

            if transition in self._transition_counts:
                # Known transition — score based on its probability
                prob = self._transition_counts[transition] / self._symbol_counts[prev]
                anomaly_scores.append(1.0 - prob)
            else:
                # Unknown transition — fully anomalous
                anomaly_scores.append(1.0)

        if not anomaly_scores:
            return 0.0

        return sum(anomaly_scores) / len(anomaly_scores)

    def detect_anomalies(
        self, events: List[str], threshold: float = 0.5
    ) -> List[Tuple[int, str, str]]:
        """Detect anomalous transitions in a sequence.

        Returns list of (index, prev_symbol, curr_symbol) for transitions
        whose anomaly score exceeds the threshold.
        """
        if not events:
            return []

        anomalies = []
        for i in range(1, len(events)):
            prev = events[i - 1]
            curr = events[i]
            transition = (prev, curr)

            if transition in self._transition_counts:
                prob = self._transition_counts[transition] / self._symbol_counts[prev]
                score = 1.0 - prob
            else:
                score = 1.0

            if score >= threshold:
                anomalies.append((i, prev, curr))

        return anomalies

    def get_transition_counts(self) -> Dict[Tuple[str, str], int]:
        """Return a copy of transition counts."""
        return dict(self._transition_counts)

    def get_transition_probabilities(self) -> Dict[Tuple[str, str], float]:
        """Return transition probabilities."""
        probs = {}
        for (prev, curr), count in self._transition_counts.items():
            probs[(prev, curr)] = count / self._symbol_counts[prev]
        return probs

    def reset(self) -> None:
        """Reset all learned state."""
        self._transition_counts.clear()
        self._symbol_counts.clear()
        self._total_transitions = 0


# ── Protocol Analysis ─────────────────────────────────────────────────


class ProtocolState(Enum):
    """TCP connection states."""

    CLOSED = "closed"
    SYN_SENT = "syn_sent"
    SYN_ACK_RECEIVED = "syn_ack_received"
    ESTABLISHED = "established"
    FIN_WAIT = "fin_wait"
    CLOSING = "closing"
    TIME_WAIT = "time_wait"


class ProtocolAnalyzer:
    """TCP state machine for protocol-level anomaly detection.

    Tracks connection state transitions and flags invalid or suspicious
    protocol behavior.
    """

    _VALID_TRANSITIONS: Dict[ProtocolState, Set[ProtocolState]] = {
        ProtocolState.CLOSED: {ProtocolState.SYN_SENT},
        ProtocolState.SYN_SENT: {ProtocolState.SYN_ACK_RECEIVED, ProtocolState.CLOSED},
        ProtocolState.SYN_ACK_RECEIVED: {ProtocolState.ESTABLISHED, ProtocolState.CLOSED},
        ProtocolState.ESTABLISHED: {ProtocolState.FIN_WAIT, ProtocolState.CLOSING, ProtocolState.CLOSED},
        ProtocolState.FIN_WAIT: {ProtocolState.CLOSING, ProtocolState.TIME_WAIT, ProtocolState.CLOSED},
        ProtocolState.CLOSING: {ProtocolState.TIME_WAIT, ProtocolState.CLOSED},
        ProtocolState.TIME_WAIT: {ProtocolState.CLOSED},
    }

    _EVENT_MAP: Dict[str, Tuple[ProtocolState, ProtocolState]] = {
        "SYN": (ProtocolState.CLOSED, ProtocolState.SYN_SENT),
        "SYN_ACK": (ProtocolState.SYN_SENT, ProtocolState.SYN_ACK_RECEIVED),
        "ACK": (ProtocolState.SYN_ACK_RECEIVED, ProtocolState.ESTABLISHED),
        "FIN": (ProtocolState.ESTABLISHED, ProtocolState.FIN_WAIT),
        "FIN_ACK": (ProtocolState.FIN_WAIT, ProtocolState.CLOSING),
        "RST": (ProtocolState.ESTABLISHED, ProtocolState.CLOSED),
    }

    def __init__(self):
        self._state = ProtocolState.CLOSED
        self._history: List[Tuple[str, ProtocolState]] = []

    def process_event(self, event: str) -> None:
        """Process a protocol event and transition state.

        Raises ValueError if the event is not valid from the current state.
        """
        if event not in self._EVENT_MAP:
            raise ValueError(f"Unknown protocol event: {event}")

        expected_from, to_state = self._EVENT_MAP[event]
        if self._state != expected_from:
            raise ValueError(
                f"Invalid transition: {event} from state {self._state.value}"
            )

        self._history.append((event, to_state))
        self._state = to_state

    def validate_transition(
        self, from_state: ProtocolState, to_state: ProtocolState
    ) -> bool:
        """Check if a transition between two states is valid."""
        return to_state in self._VALID_TRANSITIONS.get(from_state, set())

    def analyze_handshake(self, events: List[str]) -> List[str]:
        """Analyze a sequence of handshake events for anomalies.

        Returns a list of anomaly descriptions.
        """
        anomalies = []
        temp_state = ProtocolState.CLOSED

        for event in events:
            if event not in self._EVENT_MAP:
                anomalies.append(f"Unknown event: {event}")
                continue

            expected_from, to_state = self._EVENT_MAP[event]
            if temp_state != expected_from:
                anomalies.append(
                    f"Invalid transition: {event} from state {temp_state.value}"
                )
                # Try to recover by jumping to the expected state
                temp_state = to_state
            else:
                temp_state = to_state

        return anomalies

    def get_state(self) -> ProtocolState:
        """Return the current protocol state."""
        return self._state

    def get_valid_transitions(self, state: ProtocolState) -> Set[ProtocolState]:
        """Return valid next states from a given state."""
        return set(self._VALID_TRANSITIONS.get(state, set()))

    def reset(self) -> None:
        """Reset to initial state."""
        self._state = ProtocolState.CLOSED
        self._history.clear()


# ── Encrypted Traffic Inspection ──────────────────────────────────────


class TLSVersion(Enum):
    """TLS protocol versions."""

    SSL_3_0 = "SSLv3"
    TLS_1_0 = "TLSv1.0"
    TLS_1_1 = "TLSv1.1"
    TLS_1_2 = "TLSv1.2"
    TLS_1_3 = "TLSv1.3"


class CipherSuite(Enum):
    """Common TLS cipher suites."""

    TLS_AES_128_GCM_SHA256 = "TLS_AES_128_GCM_SHA256"
    TLS_AES_256_GCM_SHA384 = "TLS_AES_256_GCM_SHA384"
    TLS_CHACHA20_POLY1305_SHA256 = "TLS_CHACHA20_POLY1305_SHA256"
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
    TLS_RSA_WITH_RC4_128_MD5 = "TLS_RSA_WITH_RC4_128_MD5"
    TLS_RSA_WITH_RC4_128_SHA = "TLS_RSA_WITH_RC4_128_SHA"
    TLS_RSA_WITH_AES_128_CBC_SHA = "TLS_RSA_WITH_AES_128_CBC_SHA"
    TLS_RSA_WITH_3DES_EDE_CBC_SHA = "TLS_RSA_WITH_3DES_EDE_CBC_SHA"


# Known weak/deprecated cipher suites
_WEAK_CIPHERS: Set[CipherSuite] = {
    CipherSuite.TLS_RSA_WITH_RC4_128_MD5,
    CipherSuite.TLS_RSA_WITH_RC4_128_SHA,
    CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
}

# Known suspicious SNI patterns
_SUSPICIOUS_SNI_PATTERNS: List[str] = [
    "evil",
    "c2",
    "command",
    "control",
    "botnet",
    "malware",
    "payload",
    "exploit",
]


@dataclass
class FlowInspectionResult:
    """Result of inspecting an encrypted flow."""

    suspicious: bool
    ja3: str
    entropy: float
    sni: str
    tls_version: str
    reasons: List[str] = field(default_factory=list)


class EncryptedTrafficInspector:
    """Inspects encrypted traffic for anomalies and suspicious patterns.

    Uses entropy analysis, JA3 fingerprinting, cipher suite evaluation,
    and SNI analysis to detect potentially malicious encrypted flows.
    """

    def calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of byte data (0.0 to 8.0)."""
        if not data:
            return 0.0

        counter = Counter(data)
        length = len(data)
        entropy = 0.0

        for count in counter.values():
            prob = count / length
            if prob > 0:
                entropy -= prob * math.log2(prob)

        return entropy

    def calculate_ja3(
        self,
        tls_version: TLSVersion,
        cipher_suites: List[CipherSuite],
        extensions: List[int],
        elliptic_curves: List[int],
        ec_point_formats: List[int],
    ) -> str:
        """Calculate JA3 fingerprint from TLS handshake parameters.

        JA3 is a hash of the TLS client hello fields used to fingerprint
        TLS clients regardless of destination.
        """
        version_str = tls_version.value
        ciphers_str = ",".join(c.value for c in cipher_suites)
        ext_str = ",".join(str(e) for e in extensions)
        curves_str = ",".join(str(c) for c in elliptic_curves)
        formats_str = ",".join(str(f) for f in ec_point_formats)

        ja3_string = f"{version_str},{ciphers_str},{ext_str},{curves_str},{formats_str}"
        return hashlib.md5(ja3_string.encode()).hexdigest()

    def inspect_flow(self, flow: Dict[str, Any]) -> FlowInspectionResult:
        """Inspect an encrypted flow for suspicious characteristics.

        Returns a FlowInspectionResult with suspicion assessment.
        """
        reasons = []

        tls_version = flow.get("tls_version", TLSVersion.TLS_1_2)
        cipher_suites = flow.get("cipher_suites", [])
        sni = flow.get("sni", "")
        payload = flow.get("payload", b"")

        # Calculate entropy
        entropy = self.calculate_entropy(payload)

        # Calculate JA3
        ja3 = self.calculate_ja3(
            tls_version=tls_version,
            cipher_suites=cipher_suites,
            extensions=flow.get("extensions", []),
            elliptic_curves=flow.get("elliptic_curves", []),
            ec_point_formats=flow.get("ec_point_formats", []),
        )

        # Check for weak cipher suites
        for cipher in cipher_suites:
            if cipher in _WEAK_CIPHERS:
                reasons.append(f"Weak cipher suite: {cipher.value}")

        # Check for deprecated TLS versions
        if tls_version in (TLSVersion.SSL_3_0, TLSVersion.TLS_1_0, TLSVersion.TLS_1_1):
            reasons.append(f"Deprecated TLS version: {tls_version.value}")

        # Check SNI for suspicious patterns
        if sni:
            sni_lower = sni.lower()
            for pattern in _SUSPICIOUS_SNI_PATTERNS:
                if pattern in sni_lower:
                    reasons.append(f"Suspicious SNI pattern: {pattern}")
                    break
        else:
            # Missing SNI is suspicious for modern TLS
            if tls_version in (TLSVersion.TLS_1_2, TLSVersion.TLS_1_3):
                reasons.append("Missing SNI in TLS 1.2+ flow")

        # Check entropy — very low entropy in "encrypted" payload is suspicious
        if payload and entropy < 3.0:
            reasons.append(f"Low entropy payload: {entropy:.2f}")

        suspicious = len(reasons) > 0

        return FlowInspectionResult(
            suspicious=suspicious,
            ja3=ja3,
            entropy=entropy,
            sni=sni,
            tls_version=tls_version.value,
            reasons=reasons,
        )

    def detect_suspicious_patterns(self, flow: Dict[str, Any]) -> List[str]:
        """Detect suspicious patterns in an encrypted flow.

        Returns a list of pattern descriptions.
        """
        result = self.inspect_flow(flow)
        return result.reasons

    def get_fingerprint(self, flow: Dict[str, Any]) -> Dict[str, Any]:
        """Get a comprehensive fingerprint of an encrypted flow."""
        result = self.inspect_flow(flow)
        return {
            "ja3": result.ja3,
            "entropy": result.entropy,
            "sni": result.sni,
            "tls_version": result.tls_version,
            "suspicious": result.suspicious,
            "reasons": result.reasons,
        }
