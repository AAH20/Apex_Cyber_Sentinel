"""Identity Threat Analytics — deepened ITDR capabilities.

Provides identity threat analytics, credential compromise detection,
and lateral movement analysis with risk scoring and path tracing.
"""
from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

@dataclass
class LoginEvent:
    """A single authentication event."""
    timestamp: datetime
    user: str
    source_ip: str
    location: Tuple[float, float]  # (latitude, longitude)
    success: bool
    auth_method: str = "password"


@dataclass
class NetworkConnection:
    """A network connection between hosts."""
    timestamp: datetime
    source_host: str
    dest_host: str
    user: str
    protocol: str = "smb"


@dataclass
class IdentityAnalyticsReport:
    """Aggregated identity analytics report."""
    alerts: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def total_alerts(self) -> int:
        return len(self.alerts)

    def by_type(self, alert_type: str) -> List[Dict[str, Any]]:
        return [a for a in self.alerts if a["type"] == alert_type]

    def by_severity(self, severity: str) -> List[Dict[str, Any]]:
        return [a for a in self.alerts if a.get("severity") == severity]


# ---------------------------------------------------------------------------
# Identity Threat Analytics
# ---------------------------------------------------------------------------

class IdentityThreatAnalyzer:
    """Detects anomalous identity behavior and computes risk scores."""

    def compute_user_risk_score(
        self,
        user: str,
        events: List[LoginEvent],
    ) -> float:
        """Compute a risk score for a user based on their login history.

        Score increases with failed logins, off-hours access, and
        impossible travel events.
        """
        user_events = [e for e in events if e.user == user]
        if not user_events:
            return 0.0

        score = 0.0
        failures = sum(1 for e in user_events if not e.success)
        score += failures * 10.0

        # Off-hours penalty
        for e in user_events:
            if e.timestamp.hour < 9 or e.timestamp.hour >= 17:
                score += 5.0

        # Impossible travel penalty
        sorted_events = sorted(user_events, key=lambda x: x.timestamp)
        for prev, curr in zip(sorted_events, sorted_events[1:]):
            dist_km = _haversine(prev.location, curr.location)
            time_h = (curr.timestamp - prev.timestamp).total_seconds() / 3600
            if time_h > 0:
                speed = dist_km / time_h
                if speed > 900:
                    score += 20.0

        return score

    def detect_impossible_travel(
        self,
        events: List[LoginEvent],
        max_kmh: float = 900,
    ) -> List[Dict[str, Any]]:
        """Flag logins from geographically distant locations in short time."""
        alerts = []
        by_user: Dict[str, List[LoginEvent]] = defaultdict(list)
        for e in events:
            by_user[e.user].append(e)

        for user, user_events in by_user.items():
            sorted_events = sorted(user_events, key=lambda x: x.timestamp)
            for prev, curr in zip(sorted_events, sorted_events[1:]):
                dist_km = _haversine(prev.location, curr.location)
                time_h = (curr.timestamp - prev.timestamp).total_seconds() / 3600
                if time_h <= 0:
                    continue
                speed = dist_km / time_h
                if speed > max_kmh:
                    alerts.append({
                        "type": "impossible_travel",
                        "user": user,
                        "from_location": prev.location,
                        "to_location": curr.location,
                        "distance_km": round(dist_km, 1),
                        "speed_kmh": round(speed, 1),
                        "severity": "high",
                    })
        return alerts

    def detect_off_hours(
        self,
        events: List[LoginEvent],
        work_hours: Tuple[int, int] = (9, 17),
    ) -> List[Dict[str, Any]]:
        """Flag logins outside normal working hours."""
        alerts = []
        start_h, end_h = work_hours
        for e in events:
            hour = e.timestamp.hour
            if hour < start_h or hour >= end_h:
                alerts.append({
                    "type": "off_hours_access",
                    "user": e.user,
                    "timestamp": e.timestamp.isoformat(),
                    "hour": hour,
                    "severity": "medium",
                })
        return alerts

    def detect_new_location(
        self,
        events: List[LoginEvent],
        history: List[LoginEvent],
        min_distance_km: float = 100,
    ) -> List[Dict[str, Any]]:
        """Flag logins from locations far from all historical locations."""
        alerts = []
        history_by_user: Dict[str, List[Tuple[float, float]]] = defaultdict(list)
        for h in history:
            history_by_user[h.user].append(h.location)

        for e in events:
            user_locs = history_by_user.get(e.user, [])
            if not user_locs:
                continue
            min_dist = min(_haversine(e.location, loc) for loc in user_locs)
            if min_dist > min_distance_km:
                alerts.append({
                    "type": "new_location",
                    "user": e.user,
                    "location": e.location,
                    "min_distance_km": round(min_dist, 1),
                    "severity": "medium",
                })
        return alerts

    def detect_concurrent_sessions(
        self,
        events: List[LoginEvent],
        window_minutes: int = 30,
    ) -> List[Dict[str, Any]]:
        """Flag same user with multiple source IPs in a short window."""
        alerts = []
        by_user: Dict[str, List[LoginEvent]] = defaultdict(list)
        for e in events:
            by_user[e.user].append(e)

        for user, user_events in by_user.items():
            sorted_events = sorted(user_events, key=lambda x: x.timestamp)
            window = timedelta(minutes=window_minutes)
            for i, e1 in enumerate(sorted_events):
                for e2 in sorted_events[i + 1:]:
                    if e2.timestamp - e1.timestamp > window:
                        break
                    if e1.source_ip != e2.source_ip:
                        alerts.append({
                            "type": "concurrent_sessions",
                            "user": user,
                            "ip1": e1.source_ip,
                            "ip2": e2.source_ip,
                            "severity": "high",
                        })
                        break
                else:
                    continue
                break
        return alerts


# ---------------------------------------------------------------------------
# Credential Compromise Detection
# ---------------------------------------------------------------------------

class CredentialCompromiseAnalyzer:
    """Detects credential-based attacks and compromise."""

    def detect_brute_force(
        self,
        events: List[LoginEvent],
        threshold: int = 5,
        window_minutes: int = 10,
    ) -> List[Dict[str, Any]]:
        """Flag accounts with excessive failed logins in a time window."""
        alerts = []
        failures = [e for e in events if not e.success]
        by_user: Dict[str, List[LoginEvent]] = defaultdict(list)
        for e in failures:
            by_user[e.user].append(e)

        for user, user_events in by_user.items():
            sorted_events = sorted(user_events, key=lambda x: x.timestamp)
            window = timedelta(minutes=window_minutes)
            for i, e1 in enumerate(sorted_events):
                count = 1
                for e2 in sorted_events[i + 1:]:
                    if e2.timestamp - e1.timestamp <= window:
                        count += 1
                    else:
                        break
                if count >= threshold:
                    alerts.append({
                        "type": "brute_force",
                        "user": user,
                        "failed_attempts": count,
                        "window_minutes": window_minutes,
                        "severity": "high",
                    })
                    break
        return alerts

    def detect_password_spraying(
        self,
        events: List[LoginEvent],
        threshold: int = 3,
    ) -> List[Dict[str, Any]]:
        """Flag single IP targeting many accounts with failures."""
        alerts = []
        failures = [e for e in events if not e.success]
        by_ip: Dict[str, Set[str]] = defaultdict(set)
        for e in failures:
            by_ip[e.source_ip].add(e.user)

        for ip, users in by_ip.items():
            if len(users) >= threshold:
                alerts.append({
                    "type": "password_spraying",
                    "source_ip": ip,
                    "targeted_accounts": len(users),
                    "severity": "high",
                })
        return alerts

    def detect_credential_stuffing(
        self,
        events: List[LoginEvent],
        breached_credentials: Set[Tuple[str, str]],
    ) -> List[Dict[str, Any]]:
        """Flag logins using known breached credentials."""
        alerts = []
        for e in events:
            if e.success and (e.user, e.source_ip) in breached_credentials:
                alerts.append({
                    "type": "credential_stuffing",
                    "user": e.user,
                    "source_ip": e.source_ip,
                    "severity": "critical",
                })
        return alerts

    def detect_success_after_failures(
        self,
        events: List[LoginEvent],
        max_failures: int = 2,
    ) -> List[Dict[str, Any]]:
        """Flag successful logins preceded by multiple failures."""
        alerts = []
        by_user: Dict[str, List[LoginEvent]] = defaultdict(list)
        for e in events:
            by_user[e.user].append(e)

        for user, user_events in by_user.items():
            sorted_events = sorted(user_events, key=lambda x: x.timestamp)
            consecutive_failures = 0
            for e in sorted_events:
                if not e.success:
                    consecutive_failures += 1
                else:
                    if consecutive_failures > max_failures:
                        alerts.append({
                            "type": "success_after_failures",
                            "user": user,
                            "prior_failures": consecutive_failures,
                            "severity": "critical",
                        })
                    consecutive_failures = 0
        return alerts


# ---------------------------------------------------------------------------
# Lateral Movement Analysis
# ---------------------------------------------------------------------------

class LateralMovementAnalyzer:
    """Identifies lateral movement patterns in network connections."""

    def detect_sequential_host_access(
        self,
        connections: List[NetworkConnection],
        threshold: int = 3,
        window_minutes: int = 60,
    ) -> List[Dict[str, Any]]:
        """Flag users accessing many distinct hosts in a short window."""
        alerts = []
        by_user: Dict[str, List[NetworkConnection]] = defaultdict(list)
        for c in connections:
            by_user[c.user].append(c)

        for user, user_conns in by_user.items():
            sorted_conns = sorted(user_conns, key=lambda x: x.timestamp)
            window = timedelta(minutes=window_minutes)
            for i, c1 in enumerate(sorted_conns):
                hosts = {c1.dest_host}
                for c2 in sorted_conns[i + 1:]:
                    if c2.timestamp - c1.timestamp <= window:
                        hosts.add(c2.dest_host)
                    else:
                        break
                if len(hosts) >= threshold:
                    alerts.append({
                        "type": "lateral_movement",
                        "user": user,
                        "hosts_accessed": len(hosts),
                        "window_minutes": window_minutes,
                        "severity": "high",
                    })
                    break
        return alerts

    def detect_pass_the_hash(
        self,
        connections: List[NetworkConnection],
        interactive_users: Set[str],
    ) -> List[Dict[str, Any]]:
        """Flag NTLM authentication without prior interactive login."""
        alerts = []
        ntlm_users = {c.user for c in connections if c.protocol == "ntlm"}
        for user in ntlm_users:
            if user not in interactive_users:
                alerts.append({
                    "type": "pass_the_hash",
                    "user": user,
                    "severity": "critical",
                })
        return alerts

    def detect_new_admin_connection(
        self,
        connections: List[NetworkConnection],
        known_admin_targets: Set[Tuple[str, str]],
    ) -> List[Dict[str, Any]]:
        """Flag admin accounts connecting to previously unseen hosts."""
        alerts = []
        for c in connections:
            if (c.user, c.dest_host) not in known_admin_targets:
                alerts.append({
                    "type": "new_admin_connection",
                    "user": c.user,
                    "dest_host": c.dest_host,
                    "severity": "medium",
                })
        return alerts

    def detect_service_account_abuse(
        self,
        connections: List[NetworkConnection],
        service_accounts: Set[str],
        threshold: int = 3,
        window_minutes: int = 60,
    ) -> List[Dict[str, Any]]:
        """Flag service accounts accessing many hosts in a short window."""
        alerts = []
        by_user: Dict[str, List[NetworkConnection]] = defaultdict(list)
        for c in connections:
            if c.user in service_accounts:
                by_user[c.user].append(c)

        for user, user_conns in by_user.items():
            sorted_conns = sorted(user_conns, key=lambda x: x.timestamp)
            window = timedelta(minutes=window_minutes)
            for i, c1 in enumerate(sorted_conns):
                hosts = {c1.dest_host}
                for c2 in sorted_conns[i + 1:]:
                    if c2.timestamp - c1.timestamp <= window:
                        hosts.add(c2.dest_host)
                    else:
                        break
                if len(hosts) >= threshold:
                    alerts.append({
                        "type": "service_account_abuse",
                        "user": user,
                        "hosts_accessed": len(hosts),
                        "window_minutes": window_minutes,
                        "severity": "high",
                    })
                    break
        return alerts

    def find_lateral_paths(
        self,
        connections: List[NetworkConnection],
        min_hops: int = 3,
    ) -> List[Dict[str, Any]]:
        """Find chains of connections forming lateral movement paths.

        A path is a sequence of connections where each connection's source
        matches the previous connection's destination, forming a chain.
        """
        alerts = []
        by_user: Dict[str, List[NetworkConnection]] = defaultdict(list)
        for c in connections:
            by_user[c.user].append(c)

        for user, user_conns in by_user.items():
            sorted_conns = sorted(user_conns, key=lambda x: x.timestamp)
            # Build adjacency: source_host -> [(dest_host, timestamp)]
            adj: Dict[str, List[Tuple[str, datetime]]] = defaultdict(list)
            for c in sorted_conns:
                adj[c.source_host].append((c.dest_host, c.timestamp))

            # DFS to find paths of length >= min_hops
            for start_conn in sorted_conns:
                path = [start_conn.source_host, start_conn.dest_host]
                self._dfs_paths(
                    adj, start_conn.dest_host, path, start_conn.timestamp,
                    min_hops, alerts, user,
                )
        return alerts

    def _dfs_paths(
        self,
        adj: Dict[str, List[Tuple[str, datetime]]],
        current: str,
        path: List[str],
        last_ts: datetime,
        min_hops: int,
        alerts: List[Dict[str, Any]],
        user: str,
    ) -> None:
        """DFS helper for find_lateral_paths."""
        if len(path) >= min_hops:
            alerts.append({
                "type": "lateral_path",
                "user": user,
                "path": list(path),
                "hops": len(path) - 1,
                "severity": "high",
            })
            return

        for next_host, ts in adj.get(current, []):
            if ts >= last_ts and next_host not in path:
                path.append(next_host)
                self._dfs_paths(adj, next_host, path, ts, min_hops, alerts, user)
                path.pop()


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------

def run_identity_analytics(
    logins: List[LoginEvent],
    connections: List[NetworkConnection],
    breached_credentials: Optional[Set[Tuple[str, str]]] = None,
    interactive_users: Optional[Set[str]] = None,
    known_admin_targets: Optional[Set[Tuple[str, str]]] = None,
    service_accounts: Optional[Set[str]] = None,
) -> IdentityAnalyticsReport:
    """Run full identity analytics pipeline and return aggregated report."""
    alerts: List[Dict[str, Any]] = []

    # Identity threat analytics
    id_analyzer = IdentityThreatAnalyzer()
    alerts.extend(id_analyzer.detect_impossible_travel(logins))
    alerts.extend(id_analyzer.detect_off_hours(logins))
    alerts.extend(id_analyzer.detect_concurrent_sessions(logins))

    # Credential compromise
    cred_analyzer = CredentialCompromiseAnalyzer()
    alerts.extend(cred_analyzer.detect_brute_force(logins))
    alerts.extend(cred_analyzer.detect_password_spraying(logins))
    if breached_credentials:
        alerts.extend(cred_analyzer.detect_credential_stuffing(logins, breached_credentials))
    alerts.extend(cred_analyzer.detect_success_after_failures(logins))

    # Lateral movement
    lat_analyzer = LateralMovementAnalyzer()
    alerts.extend(lat_analyzer.detect_sequential_host_access(connections))
    if interactive_users is not None:
        alerts.extend(lat_analyzer.detect_pass_the_hash(connections, interactive_users))
    if known_admin_targets:
        alerts.extend(lat_analyzer.detect_new_admin_connection(connections, known_admin_targets))
    if service_accounts:
        alerts.extend(lat_analyzer.detect_service_account_abuse(connections, service_accounts))
    alerts.extend(lat_analyzer.find_lateral_paths(connections))

    return IdentityAnalyticsReport(alerts=alerts)


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _haversine(loc1: Tuple[float, float], loc2: Tuple[float, float]) -> float:
    """Calculate great-circle distance between two lat/lon points in km."""
    lat1, lon1 = loc1
    lat2, lon2 = loc2
    R = 6371  # Earth radius in km
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = (math.sin(dlat / 2) ** 2 +
         math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) *
         math.sin(dlon / 2) ** 2)
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
