"""TDD tests for identity_analytics — deepened ITDR capabilities."""
import sys
import os
import unittest
from datetime import datetime, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from cyber.identity_analytics import (
    LoginEvent,
    NetworkConnection,
    IdentityThreatAnalyzer,
    CredentialCompromiseAnalyzer,
    LateralMovementAnalyzer,
    IdentityAnalyticsReport,
    run_identity_analytics,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _login(user="alice", ip="10.0.0.1", lat=40.71, lon=-74.0,
           success=True, minutes_ago=0, auth="password"):
    return LoginEvent(
        timestamp=datetime(2026, 1, 1, 12, 0) - timedelta(minutes=minutes_ago),
        user=user,
        source_ip=ip,
        location=(lat, lon),
        success=success,
        auth_method=auth,
    )


def _conn(user="alice", src="host-a", dst="host-b", minutes_ago=0,
          protocol="smb"):
    return NetworkConnection(
        timestamp=datetime(2026, 1, 1, 12, 0) - timedelta(minutes=minutes_ago),
        source_host=src,
        dest_host=dst,
        user=user,
        protocol=protocol,
    )


# ---------------------------------------------------------------------------
# Identity Threat Analytics
# ---------------------------------------------------------------------------

class TestIdentityThreatAnalyzer(unittest.TestCase):

    def test_user_risk_score_increases_with_failures(self):
        """More failed logins → higher risk score."""
        events = [_login(success=False, minutes_ago=i) for i in range(5)]
        analyzer = IdentityThreatAnalyzer()
        score = analyzer.compute_user_risk_score("alice", events)
        self.assertGreater(score, 0)

    def test_user_risk_score_zero_for_clean_history(self):
        """No failures → zero risk score."""
        events = [_login(success=True, minutes_ago=i) for i in range(3)]
        analyzer = IdentityThreatAnalyzer()
        score = analyzer.compute_user_risk_score("alice", events)
        self.assertEqual(score, 0)

    def test_detect_impossible_travel(self):
        """Two logins 30 min apart from distant cities = impossible travel."""
        events = [
            _login(minutes_ago=30, lat=40.71, lon=-74.0),   # NYC
            _login(minutes_ago=0, lat=51.51, lon=-0.13),     # London
        ]
        analyzer = IdentityThreatAnalyzer()
        alerts = analyzer.detect_impossible_travel(events, max_kmh=900)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["type"], "impossible_travel")
        self.assertEqual(alerts[0]["user"], "alice")

    def test_detect_off_hours_access(self):
        """Login at 3 AM is off-hours."""
        event = LoginEvent(
            timestamp=datetime(2026, 1, 1, 3, 0),
            user="alice", source_ip="10.0.0.1",
            location=(40.71, -74.0), success=True,
        )
        analyzer = IdentityThreatAnalyzer()
        alerts = analyzer.detect_off_hours([event], work_hours=(9, 17))
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["type"], "off_hours_access")

    def test_detect_new_location(self):
        """Login far from all historical locations = new location."""
        history = [_login(minutes_ago=60, lat=40.71, lon=-74.0)]
        new_event = _login(minutes_ago=0, lat=35.68, lon=139.69)  # Tokyo
        analyzer = IdentityThreatAnalyzer()
        alerts = analyzer.detect_new_location([new_event], history)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["type"], "new_location")

    def test_detect_concurrent_sessions(self):
        """Same user from two IPs within a short window."""
        events = [
            _login(minutes_ago=5, ip="10.0.0.1"),
            _login(minutes_ago=2, ip="10.0.0.2"),
        ]
        analyzer = IdentityThreatAnalyzer()
        alerts = analyzer.detect_concurrent_sessions(events, window_minutes=30)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["type"], "concurrent_sessions")


# ---------------------------------------------------------------------------
# Credential Compromise Detection
# ---------------------------------------------------------------------------

class TestCredentialCompromiseAnalyzer(unittest.TestCase):

    def test_detect_brute_force(self):
        """5+ failed logins in 10 min = brute force."""
        events = [_login(success=False, minutes_ago=i) for i in range(6)]
        analyzer = CredentialCompromiseAnalyzer()
        alerts = analyzer.detect_brute_force(events, threshold=5, window_minutes=10)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["type"], "brute_force")

    def test_detect_password_spraying(self):
        """Same IP hitting many accounts = spraying."""
        events = [
            _login(user=f"user{i}", ip="10.0.0.99", success=False, minutes_ago=i)
            for i in range(5)
        ]
        analyzer = CredentialCompromiseAnalyzer()
        alerts = analyzer.detect_password_spraying(events, threshold=3)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["type"], "password_spraying")

    def test_detect_credential_stuffing(self):
        """Login with known breached credentials."""
        events = [_login(user="alice", ip="10.0.0.1", success=True)]
        breached = {("alice", "10.0.0.1")}
        analyzer = CredentialCompromiseAnalyzer()
        alerts = analyzer.detect_credential_stuffing(events, breached)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["type"], "credential_stuffing")

    def test_detect_success_after_failures(self):
        """Success after multiple failures = possible compromise."""
        events = [
            _login(success=False, minutes_ago=10),
            _login(success=False, minutes_ago=9),
            _login(success=False, minutes_ago=8),
            _login(success=True, minutes_ago=0),
        ]
        analyzer = CredentialCompromiseAnalyzer()
        alerts = analyzer.detect_success_after_failures(events, max_failures=2)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["type"], "success_after_failures")


# ---------------------------------------------------------------------------
# Lateral Movement Analysis
# ---------------------------------------------------------------------------

class TestLateralMovementAnalyzer(unittest.TestCase):

    def test_detect_sequential_host_access(self):
        """One user hitting 4 hosts in 30 min = lateral movement."""
        conns = [
            _conn(user="alice", src="ws-1", dst=f"srv-{i}", minutes_ago=30 - i * 5)
            for i in range(4)
        ]
        analyzer = LateralMovementAnalyzer()
        alerts = analyzer.detect_sequential_host_access(conns, threshold=3, window_minutes=60)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["type"], "lateral_movement")

    def test_detect_pass_the_hash(self):
        """NTLM auth with no preceding interactive login = PtH."""
        conns = [
            _conn(user="admin", src="ws-1", dst="srv-1", protocol="ntlm"),
            _conn(user="admin", src="ws-1", dst="srv-2", protocol="ntlm"),
        ]
        analyzer = LateralMovementAnalyzer()
        alerts = analyzer.detect_pass_the_hash(conns, interactive_users=set())
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["type"], "pass_the_hash")

    def test_detect_new_admin_connection(self):
        """Admin connecting to a host they've never touched."""
        known = {("admin", "srv-1")}
        conns = [_conn(user="admin", src="ws-1", dst="srv-2")]
        analyzer = LateralMovementAnalyzer()
        alerts = analyzer.detect_new_admin_connection(conns, known_admin_targets=known)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["type"], "new_admin_connection")

    def test_detect_service_account_abuse(self):
        """Service account accessing many hosts in a short window."""
        conns = [
            _conn(user="svc-backup", src="srv-1", dst=f"ws-{i}", minutes_ago=30 - i * 2)
            for i in range(5)
        ]
        analyzer = LateralMovementAnalyzer()
        alerts = analyzer.detect_service_account_abuse(
            conns, service_accounts={"svc-backup"}, threshold=3, window_minutes=60
        )
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["type"], "service_account_abuse")

    def test_detect_lateral_movement_path(self):
        """Chain of connections forming a path through the network."""
        conns = [
            _conn(user="alice", src="ws-1", dst="srv-1", minutes_ago=30),
            _conn(user="alice", src="srv-1", dst="srv-2", minutes_ago=20),
            _conn(user="alice", src="srv-2", dst="srv-3", minutes_ago=10),
        ]
        analyzer = LateralMovementAnalyzer()
        paths = analyzer.find_lateral_paths(conns, min_hops=3)
        self.assertGreaterEqual(len(paths), 1)
        self.assertIn("alice", paths[0]["user"])


# ---------------------------------------------------------------------------
# Integration / Report
# ---------------------------------------------------------------------------

class TestIdentityAnalyticsReport(unittest.TestCase):

    def test_run_identity_analytics_aggregates_alerts(self):
        """Full pipeline returns report with all alert types."""
        logins = [
            _login(success=False, minutes_ago=10),
            _login(success=False, minutes_ago=9),
            _login(success=False, minutes_ago=8),
            _login(success=True, minutes_ago=0),
        ]
        conns = [
            _conn(user="alice", src="ws-1", dst=f"srv-{i}", minutes_ago=30 - i * 5)
            for i in range(4)
        ]
        report = run_identity_analytics(logins, conns)
        self.assertIsInstance(report, IdentityAnalyticsReport)
        self.assertGreater(report.total_alerts, 0)
        types = {a["type"] for a in report.alerts}
        self.assertIn("success_after_failures", types)
        self.assertIn("lateral_movement", types)

    def test_run_identity_analytics_empty_input(self):
        """No events = no alerts."""
        report = run_identity_analytics([], [])
        self.assertEqual(report.total_alerts, 0)

    def test_report_by_severity(self):
        """Report can filter alerts by severity."""
        logins = [
            _login(success=False, minutes_ago=10),
            _login(success=False, minutes_ago=9),
            _login(success=False, minutes_ago=8),
            _login(success=True, minutes_ago=0),
        ]
        report = run_identity_analytics(logins, [])
        critical = report.by_severity("critical")
        self.assertGreaterEqual(len(critical), 1)


if __name__ == "__main__":
    unittest.main()
