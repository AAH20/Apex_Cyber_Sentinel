"""Unit tests for sequence anomaly detection, protocol analysis, and encrypted traffic inspection."""
import math
import pytest

from src.cyber.sequence import (
    SequenceAnomalyDetector,
    ProtocolState,
    ProtocolAnalyzer,
    EncryptedTrafficInspector,
    TLSVersion,
    CipherSuite,
)


# ── Sequence Anomaly Detection ────────────────────────────────────────

class TestSequenceAnomalyDetector:
    def test_learn_empty_events(self):
        detector = SequenceAnomalyDetector()
        detector.learn([])
        assert detector.get_transition_counts() == {}

    def test_learn_single_event_no_transitions(self):
        detector = SequenceAnomalyDetector()
        detector.learn(["a"])
        assert detector.get_transition_counts() == {}

    def test_learn_creates_transitions(self):
        detector = SequenceAnomalyDetector()
        detector.learn(["a", "b", "c"])
        transitions = detector.get_transition_counts()
        assert ("a", "b") in transitions
        assert ("b", "c") in transitions

    def test_transition_counts_accumulate(self):
        detector = SequenceAnomalyDetector()
        detector.learn(["a", "b"])
        detector.learn(["a", "b"])
        transitions = detector.get_transition_counts()
        assert transitions[("a", "b")] == 2

    def test_score_normal_sequence_low(self):
        detector = SequenceAnomalyDetector()
        detector.learn(["a", "b", "c", "a", "b", "c"])
        score = detector.score_sequence(["a", "b", "c"])
        assert score < 0.5

    def test_score_anomalous_sequence_high(self):
        detector = SequenceAnomalyDetector()
        detector.learn(["a", "b", "c", "a", "b", "c"])
        score = detector.score_sequence(["a", "x", "y"])
        assert score > 0.5

    def test_score_empty_sequence(self):
        detector = SequenceAnomalyDetector()
        detector.learn(["a", "b"])
        score = detector.score_sequence([])
        assert score == 0.0

    def test_detect_anomalies_returns_flagged(self):
        detector = SequenceAnomalyDetector()
        detector.learn(["a", "b", "c", "a", "b", "c"])
        anomalies = detector.detect_anomalies(["a", "x", "y"], threshold=0.5)
        assert len(anomalies) > 0

    def test_detect_anomalies_empty_input(self):
        detector = SequenceAnomalyDetector()
        detector.learn(["a", "b"])
        anomalies = detector.detect_anomalies([])
        assert anomalies == []

    def test_reset_clears_state(self):
        detector = SequenceAnomalyDetector()
        detector.learn(["a", "b", "c"])
        detector.reset()
        assert detector.get_transition_counts() == {}

    def test_get_transition_probabilities(self):
        detector = SequenceAnomalyDetector()
        detector.learn(["a", "b", "a", "c"])
        probs = detector.get_transition_probabilities()
        assert ("a", "b") in probs
        assert ("a", "c") in probs
        assert abs(probs[("a", "b")] - 0.5) < 0.01
        assert abs(probs[("a", "c")] - 0.5) < 0.01


# ── Protocol Analysis ─────────────────────────────────────────────────

class TestProtocolAnalyzer:
    def test_initial_state_is_closed(self):
        analyzer = ProtocolAnalyzer()
        assert analyzer.get_state() == ProtocolState.CLOSED

    def test_valid_tcp_handshake(self):
        analyzer = ProtocolAnalyzer()
        analyzer.process_event("SYN")
        assert analyzer.get_state() == ProtocolState.SYN_SENT
        analyzer.process_event("SYN_ACK")
        assert analyzer.get_state() == ProtocolState.SYN_ACK_RECEIVED
        analyzer.process_event("ACK")
        assert analyzer.get_state() == ProtocolState.ESTABLISHED

    def test_invalid_transition_raises(self):
        analyzer = ProtocolAnalyzer()
        with pytest.raises(ValueError):
            analyzer.process_event("ACK")

    def test_validate_transition_valid(self):
        analyzer = ProtocolAnalyzer()
        assert analyzer.validate_transition(ProtocolState.CLOSED, ProtocolState.SYN_SENT) is True

    def test_validate_transition_invalid(self):
        analyzer = ProtocolAnalyzer()
        assert analyzer.validate_transition(ProtocolState.CLOSED, ProtocolState.ESTABLISHED) is False

    def test_detect_anomalies_in_handshake(self):
        analyzer = ProtocolAnalyzer()
        events = ["SYN", "SYN_ACK", "ACK"]
        anomalies = analyzer.analyze_handshake(events)
        assert anomalies == []

    def test_detect_anomalies_invalid_handshake(self):
        analyzer = ProtocolAnalyzer()
        events = ["SYN", "ACK"]
        anomalies = analyzer.analyze_handshake(events)
        assert len(anomalies) > 0

    def test_reset_returns_to_closed(self):
        analyzer = ProtocolAnalyzer()
        analyzer.process_event("SYN")
        analyzer.reset()
        assert analyzer.get_state() == ProtocolState.CLOSED

    def test_get_valid_transitions(self):
        analyzer = ProtocolAnalyzer()
        valid = analyzer.get_valid_transitions(ProtocolState.CLOSED)
        assert ProtocolState.SYN_SENT in valid


# ── Encrypted Traffic Inspection ──────────────────────────────────────

class TestEncryptedTrafficInspector:
    def test_calculate_entropy_uniform(self):
        inspector = EncryptedTrafficInspector()
        # Uniform byte distribution should have high entropy
        data = bytes(range(256))
        entropy = inspector.calculate_entropy(data)
        assert entropy > 7.0

    def test_calculate_entropy_zero_for_constant(self):
        inspector = EncryptedTrafficInspector()
        data = b"\x00" * 100
        entropy = inspector.calculate_entropy(data)
        assert entropy == 0.0

    def test_calculate_ja3_fingerprint(self):
        inspector = EncryptedTrafficInspector()
        ja3 = inspector.calculate_ja3(
            tls_version=TLSVersion.TLS_1_2,
            cipher_suites=[CipherSuite.TLS_AES_128_GCM_SHA256, CipherSuite.TLS_AES_256_GCM_SHA384],
            extensions=[0, 11, 10],
            elliptic_curves=[23, 24],
            ec_point_formats=[0, 1],
        )
        assert len(ja3) == 32  # MD5 hash length
        assert ja3 == ja3.lower()

    def test_calculate_ja3_deterministic(self):
        inspector = EncryptedTrafficInspector()
        ja3_1 = inspector.calculate_ja3(
            tls_version=TLSVersion.TLS_1_2,
            cipher_suites=[CipherSuite.TLS_AES_128_GCM_SHA256],
            extensions=[0, 11],
            elliptic_curves=[23],
            ec_point_formats=[0],
        )
        ja3_2 = inspector.calculate_ja3(
            tls_version=TLSVersion.TLS_1_2,
            cipher_suites=[CipherSuite.TLS_AES_128_GCM_SHA256],
            extensions=[0, 11],
            elliptic_curves=[23],
            ec_point_formats=[0],
        )
        assert ja3_1 == ja3_2

    def test_inspect_flow_normal(self):
        inspector = EncryptedTrafficInspector()
        flow = {
            "tls_version": TLSVersion.TLS_1_2,
            "cipher_suites": [CipherSuite.TLS_AES_128_GCM_SHA256],
            "sni": "example.com",
            "payload": bytes(range(256)),
        }
        result = inspector.inspect_flow(flow)
        assert result.suspicious is False

    def test_inspect_flow_suspicious_sni(self):
        inspector = EncryptedTrafficInspector()
        flow = {
            "tls_version": TLSVersion.TLS_1_2,
            "cipher_suites": [CipherSuite.TLS_AES_128_GCM_SHA256],
            "sni": "evil-c2-server.xyz",
            "payload": bytes(range(256)),
        }
        result = inspector.inspect_flow(flow)
        assert result.suspicious is True

    def test_inspect_flow_weak_cipher(self):
        inspector = EncryptedTrafficInspector()
        flow = {
            "tls_version": TLSVersion.TLS_1_0,
            "cipher_suites": [CipherSuite.TLS_RSA_WITH_RC4_128_MD5],
            "sni": "example.com",
            "payload": bytes(range(256)),
        }
        result = inspector.inspect_flow(flow)
        assert result.suspicious is True

    def test_detect_suspicious_patterns_high_entropy(self):
        inspector = EncryptedTrafficInspector()
        # High entropy payload with no SNI is suspicious
        flow = {
            "tls_version": TLSVersion.TLS_1_2,
            "cipher_suites": [CipherSuite.TLS_AES_128_GCM_SHA256],
            "sni": "",
            "payload": bytes(range(256)),
        }
        patterns = inspector.detect_suspicious_patterns(flow)
        assert len(patterns) > 0

    def test_get_fingerprint(self):
        inspector = EncryptedTrafficInspector()
        flow = {
            "tls_version": TLSVersion.TLS_1_2,
            "cipher_suites": [CipherSuite.TLS_AES_128_GCM_SHA256],
            "extensions": [0, 11, 10],
            "elliptic_curves": [23, 24],
            "ec_point_formats": [0, 1],
            "sni": "example.com",
            "payload": bytes(range(256)),
        }
        fingerprint = inspector.get_fingerprint(flow)
        assert "ja3" in fingerprint
        assert "entropy" in fingerprint
        assert "sni" in fingerprint
