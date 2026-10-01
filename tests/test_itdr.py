"""TDD tests for ITDR — identity threat detection and response."""
import sys
import os
import unittest
from datetime import datetime, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from cyber.itdr import (
    LoginEvent,
    NetworkConnection,
    IdentityAnomalyDetector,
    CredentialCompromiseDetector,
    LateralMovementDetector,
    ITDRReport,
    run_itdr,
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
# Identity Anomaly Detection
# ---------------------------------------------------------------------------

class TestIdentityAnomalyDetector(unittest.TestCase):

    def test_impossible_travel_detected(self):
        """Two logins 30 min apart from NYC and London = impossible travel."""
        events = [
            _login(minutes_ago=30, lat=40.71, lon=-74.0),      # NYC
            _login(minutes_ago=0, lat=51.51, lon=-0.13),        # London
        ]
        det = IdentityAnomalyDetector()
        alerts = det.detect_impossible_travel(events, max_kmh=900)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["user"], "alice")
        self.assertEqual(alerts[0]["type"], "impossible_travel")

    def test_impossible_travel_not_triggered_for_nearby(self):
        """Two logins from nearby cities are fine."""
        events = [
            _login(minutes_ago=30, lat=40.71, lon=-74.0),   # NYC
            _login(minutes_ago=0, lat=40.73, lon=-73.99),   # still NYC
        ]
        det = IdentityAnomalyDetector()
        self.assertEqual(det.detect_impossible_travel(events), [])

    def test_off_hours_access_detected(self):
        """Login at 3 AM is off-hours."""
        event = LoginEvent(
            timestamp=datetime(2026, 1, 1, 3, 0),
            user="alice", source_ip="10.0.0.1",
            location=(40.71, -74.0), success=True, auth_method="password",
        )
        det = IdentityAnomalyDetector()
        alerts = det.detect_off_hours([event], work_hours=(9, 17))
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["type"], "off_hours_access")

    def test_off_hours_not_triggered_during_work(self):
        """Login at 10 AM is within work hours."""
        event = LoginEvent(
            timestamp=datetime(2026, 1, 1, 10, 0),
            user="alice", source_ip="10.0.0.1",
            location=(40.71, -74.0), success=True, auth_method="password",
        )
        det = IdentityAnomalyDetector()
        self.assertEqual(det.detect_off_hours([event], work_hours=(9, 17)), [])

    def test_new_location_detected(self):
        """A location never seen before for this user is an anomaly."""
        history = [_login(minutes_ago=60, lat=40.71, lon=-74.0)]
        new_event = _login(minutes_ago=0, lat=35.68, lon=139.69)  # Tokyo
        det = IdentityAnomalyDetector()
        alerts = det.detect_new_location([new_event], history)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["type"], "new_location")

    def test_concurrent_sessions_detected(self):
        """Same user logged in from two IPs within a short window."""
        events = [
            _login(minutes_ago=5, ip="10.0.0.1"),
            _login(minutes_ago=2, ip="10.0.0.2"),
        ]
        det = IdentityAnomalyDetector()
        alerts = det.detect_concurrent_sessions(events, window_minutes=30)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["type"], "concurrent_sessions")


# ---------------------------------------------------------------------------
# Credential Compromise Detection
# ---------------------------------------------------------------------------

class TestCredentialCompromiseDetector(unittest.TestCase):

    def test_brute_force_detected(self):
        """5+ failed logins in 10 minutes = brute force."""
        events = [_login(success=False, minutes_ago=i) for i in range(6)]
        det = CredentialCompromiseDetector()
        alerts = det.detect_brute_force(events, threshold=5, window_minutes=10)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["type"], "brute_force")
        self.assertEqual(alerts[0]["user"], "alice")

    def test_brute_force_not_triggered_below_threshold(self):
        """4 failures is below the threshold of 5."""
        events = [_login(success=False, minutes_ago=i) for i in range(4)]
        det = CredentialCompromiseDetector()
        self.assertEqual(det.detect_brute_force(events, threshold=5, window_minutes=10), [])

    def test_password_spraying_detected(self):
        """Same IP hitting many accounts with failures = spraying."""
        events = [
            _login(user=f"user{i}", ip="10.0.0.99", success=False, minutes_ago=i)
            for i in range(5)
        ]
        det = CredentialCompromiseDetector()
        alerts = det.detect_password_spraying(events, threshold=3)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["type"], "password_spraying")
        self.assertEqual(alerts[0]["source_ip"], "10.0.0.99")

    def test_credential_stuffing_detected(self):
        """Login with known breached credentials."""
        events = [_login(user="alice", ip="10.0.0.1", success=True)]
        breached = {("alice", "10.0.0.1")}
        det = CredentialCompromiseDetector()
        alerts = det.detect_credential_stuffing(events, breached)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["type"], "credential_stuffing")

    def test_success_after_failures_detected(self):
        """Successful login after multiple failures = possible compromise."""
        events = [
            _login(success=False, minutes_ago=10),
            _login(success=False, minutes_ago=9),
            _login(success=False, minutes_ago=8),
            _login(success=True, minutes_ago=0),
        ]
        det = CredentialCompromiseDetector()
        alerts = det.detect_success_after_failures(events, max_failures=2)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["type"], "success_after_failures")


# ---------------------------------------------------------------------------
# Lateral Movement Identification
# ---------------------------------------------------------------------------

class TestLateralMovementDetector(unittest.TestCase):

    def test_sequential_host_access_detected(self):
        """One user hitting 4 hosts in 30 min = lateral movement."""
        conns = [
            _conn(user="alice", src="ws-1", dst=f"srv-{i}", minutes_ago=30 - i * 5)
            for i in range(4)
        ]
        det = LateralMovementDetector()
        alerts = det.detect_sequential_host_access(conns, threshold=3, window_minutes=60)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["type"], "lateral_movement")
        self.assertEqual(alerts[0]["user"], "alice")

    def test_sequential_host_access_not_triggered_below_threshold(self):
        """Only 2 hosts accessed — below threshold of 3."""
        conns = [
            _conn(user="alice", src="ws-1", dst="srv-1", minutes_ago=20),
            _conn(user="alice", src="ws-1", dst="srv-2", minutes_ago=10),
        ]
        det = LateralMovementDetector()
        self.assertEqual(det.detect_sequential_host_access(conns, threshold=3), [])

    def test_pass_the_hash_detected(self):
        """NTLM auth with no preceding interactive login = PtH."""
        conns = [
            _conn(user="admin", src="ws-1", dst="srv-1", protocol="ntlm"),
            _conn(user="admin", src="ws-1", dst="srv-2", protocol="ntlm"),
        ]
        det = LateralMovementDetector()
        alerts = det.detect_pass_the_hash(conns, interactive_users=set())
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["type"], "pass_the_hash")

    def test_new_admin_connection_detected(self):
        """Admin connecting to a host they've never touched."""
        known = {("admin", "srv-1")}
        conns = [_conn(user="admin", src="ws-1", dst="srv-2")]
        det = LateralMovementDetector()
        alerts = det.detect_new_admin_connection(conns, known_admin_targets=known)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["type"], "new_admin_connection")

    def test_service_account_abuse_detected(self):
        """Service account accessing many hosts in a short window."""
        conns = [
            _conn(user="svc-backup", src="srv-1", dst=f"ws-{i}", minutes_ago=30 - i * 2)
            for i in range(5)
        ]
        det = LateralMovementDetector()
        alerts = det.detect_service_account_abuse(
            conns, service_accounts={"svc-backup"}, threshold=3, window_minutes=60
        )
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["type"], "service_account_abuse")


# ---------------------------------------------------------------------------
# Integration / Report
# ---------------------------------------------------------------------------

class TestITDRReport(unittest.TestCase):

    def test_run_itdr_aggregates_alerts(self):
        """Full pipeline returns an ITDRReport with all alert types."""
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
        report = run_itdr(logins, conns)
        self.assertIsInstance(report, ITDRReport)
        self.assertGreater(report.total_alerts, 0)
        types = {a["type"] for a in report.alerts}
        self.assertIn("success_after_failures", types)
        self.assertIn("lateral_movement", types)

    def test_run_itdr_empty_input(self):
        """No events = no alerts."""
        report = run_itdr([], [])
        self.assertEqual(report.total_alerts, 0)
        self.assertEqual(report.alerts, [])


if __name__ == "__main__":
    unittest.main()
