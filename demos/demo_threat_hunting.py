#!/usr/bin/env python3
"""
Apex_Cyber_Sentinel — Threat Hunting Demo
=========================================

Demonstrates proactive threat hunting by scanning sample telemetry data
against a set of Indicators of Compromise (IOCs) and behavioral rules.

The demo simulates:
  1. IOC matching (IPs, domains, file hashes)
  2. Behavioral anomaly detection (unusual login times, privilege escalation)
  3. Risk scoring and alert generation

Usage:
    python demo_threat_hunting.py
"""

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class IOC:
    """Indicator of Compromise."""
    value: str
    ioc_type: str          # ip, domain, hash
    threat: str            # e.g. "C2 Server", "Phishing Domain"
    severity: str          # low, medium, high, critical
    source: str            # threat intel feed name


@dataclass
class TelemetryEvent:
    """A single telemetry event from the environment."""
    event_id: str
    timestamp: datetime
    source_ip: str
    destination_ip: str
    destination_port: int
    domain: Optional[str]
    process_name: Optional[str]
    file_hash: Optional[str]
    user: Optional[str]
    event_type: str        # network, process, auth, file


@dataclass
class Alert:
    """A generated threat-hunting alert."""
    alert_id: str
    title: str
    severity: str
    matched_ioc: Optional[IOC]
    event: TelemetryEvent
    description: str
    recommended_action: str


# ---------------------------------------------------------------------------
# Sample IOC feed
# ---------------------------------------------------------------------------

SAMPLE_IOCS: List[IOC] = [
    IOC("185.220.101.42",    "ip",     "C2 Server",           "critical", "AlienVault OTX"),
    IOC("45.155.204.101",    "ip",     "Brute-Force Scanner",  "high",     "AbuseIPDB"),
    IOC("evil-c2.example.com","domain", "Phishing Domain",      "high",     "PhishTank"),
    IOC("malware-c2.net",    "domain", "Malware C2",           "critical", "VirusTotal"),
    IOC("a3f2b8c91d4e5f67890abcdef1234567890abcd", "hash", "Ransomware Payload", "critical", "Hybrid-Analysis"),
    IOC("0000000000000000000000000000000000000000", "hash", "Benign File",        "low",      "Internal Allowlist"),
]


# ---------------------------------------------------------------------------
# Sample telemetry (simulated events)
# ---------------------------------------------------------------------------

def _generate_sample_events() -> List[TelemetryEvent]:
    """Generate a batch of realistic telemetry events."""
    base_time = datetime(2026, 10, 1, 14, 0, 0)

    events = [
        TelemetryEvent(
            event_id="EVT-001",
            timestamp=base_time,
            source_ip="10.0.1.15",
            destination_ip="185.220.101.42",
            destination_port=443,
            domain="evil-c2.example.com",
            process_name="svchost.exe",
            file_hash=None,
            user="jsmith",
            event_type="network",
        ),
        TelemetryEvent(
            event_id="EVT-002",
            timestamp=base_time + timedelta(minutes=5),
            source_ip="10.0.1.22",
            destination_ip="8.8.8.8",
            destination_port=53,
            domain="dns.google",
            process_name="chrome.exe",
            file_hash=None,
            user="agarcia",
            event_type="network",
        ),
        TelemetryEvent(
            event_id="EVT-003",
            timestamp=base_time + timedelta(minutes=12),
            source_ip="10.0.1.15",
            destination_ip="10.0.2.10",
            destination_port=445,
            domain=None,
            process_name="powershell.exe",
            file_hash="a3f2b8c91d4e5f67890abcdef1234567890abcd",
            user="jsmith",
            event_type="process",
        ),
        TelemetryEvent(
            event_id="EVT-004",
            timestamp=base_time + timedelta(hours=2),
            source_ip="10.0.1.8",
            destination_ip="45.155.204.101",
            destination_port=22,
            domain=None,
            process_name="ssh",
            file_hash=None,
            user="root",
            event_type="auth",
        ),
        TelemetryEvent(
            event_id="EVT-005",
            timestamp=base_time + timedelta(hours=3),
            source_ip="10.0.1.30",
            destination_ip="10.0.2.20",
            destination_port=3389,
            domain=None,
            process_name="mstsc.exe",
            file_hash=None,
            user="admin",
            event_type="auth",
        ),
        TelemetryEvent(
            event_id="EVT-006",
            timestamp=base_time + timedelta(hours=4),
            source_ip="10.0.1.15",
            destination_ip="malware-c2.net",
            destination_port=8080,
            domain="malware-c2.net",
            process_name="rundll32.exe",
            file_hash=None,
            user="jsmith",
            event_type="network",
        ),
        TelemetryEvent(
            event_id="EVT-007",
            timestamp=base_time + timedelta(hours=5),
            source_ip="10.0.1.42",
            destination_ip="10.0.2.10",
            destination_port=445,
            domain=None,
            process_name="explorer.exe",
            file_hash=None,
            user="mwilson",
            event_type="file",
        ),
    ]
    return events


# ---------------------------------------------------------------------------
# Threat hunting engine
# ---------------------------------------------------------------------------

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def match_iocs(event: TelemetryEvent, iocs: List[IOC]) -> List[IOC]:
    """Return all IOCs that match the given telemetry event."""
    matches: List[IOC] = []
    for ioc in iocs:
        if ioc.ioc_type == "ip" and event.destination_ip == ioc.value:
            matches.append(ioc)
        elif ioc.ioc_type == "domain" and event.domain == ioc.value:
            matches.append(ioc)
        elif ioc.ioc_type == "hash" and event.file_hash == ioc.value:
            matches.append(ioc)
    return matches


def detect_behavioral_anomalies(event: TelemetryEvent) -> List[str]:
    """Apply behavioral rules and return descriptions of anomalies."""
    anomalies: List[str] = []

    # Rule 1: Unusual login time (outside 06:00–22:00)
    if event.event_type == "auth":
        hour = event.timestamp.hour
        if hour < 6 or hour >= 22:
            anomalies.append(
                f"Unusual login time: {event.timestamp.strftime('%H:%M')} "
                f"(outside business hours 06:00-22:00)"
            )

    # Rule 2: Privilege escalation pattern
    if event.event_type == "process" and event.user == "root":
        anomalies.append("Root-level process execution detected")

    # Rule 3: Suspicious process names
    suspicious_processes = {"powershell.exe", "rundll32.exe", "certutil.exe", "bitsadmin.exe"}
    if event.process_name and event.process_name.lower() in suspicious_processes:
        anomalies.append(f"Suspicious process: {event.process_name}")

    # Rule 4: Lateral movement (SMB to multiple internal hosts)
    if event.destination_port == 445 and event.source_ip.startswith("10.0."):
        anomalies.append("SMB traffic to internal host — possible lateral movement")

    return anomalies


def calculate_risk_score(event: TelemetryEvent, ioc_matches: List[IOC], anomalies: List[str]) -> int:
    """Calculate a composite risk score (0-100)."""
    score = 0

    # IOC matches contribute up to 60 points
    for ioc in ioc_matches:
        score += SEVERITY_ORDER.get(ioc.severity, 0) * 15

    # Anomalies contribute up to 30 points
    score += min(len(anomalies) * 10, 30)

    # Critical destination ports add 10
    if event.destination_port in {445, 3389, 22}:
        score += 10

    return min(score, 100)


def severity_from_score(score: int) -> str:
    if score >= 80:
        return "critical"
    elif score >= 60:
        return "high"
    elif score >= 40:
        return "medium"
    else:
        return "low"


def hunt_threats(events: List[TelemetryEvent], iocs: List[IOC]) -> List[Alert]:
    """Run the full threat-hunting pipeline and return alerts."""
    alerts: List[Alert] = []

    for event in events:
        ioc_matches = match_iocs(event, iocs)
        anomalies = detect_behavioral_anomalies(event)

        if not ioc_matches and not anomalies:
            continue

        risk_score = calculate_risk_score(event, ioc_matches, anomalies)
        severity = severity_from_score(risk_score)

        # Build alert description
        parts: List[str] = []
        if ioc_matches:
            parts.append(f"IOC matches: {', '.join(i.value for i in ioc_matches)}")
        if anomalies:
            parts.append(f"Anomalies: {'; '.join(anomalies)}")

        description = " | ".join(parts)

        # Recommended action
        if severity == "critical":
            action = "ISOLATE host immediately and initiate incident response"
        elif severity == "high":
            action = "Block IOC at firewall and investigate host"
        elif severity == "medium":
            action = "Monitor closely and review related logs"
        else:
            action = "Log for trend analysis"

        alert = Alert(
            alert_id=f"ALT-{event.event_id}",
            title=f"[{severity.upper()}] Threat detected on {event.source_ip}",
            severity=severity,
            matched_ioc=ioc_matches[0] if ioc_matches else None,
            event=event,
            description=description,
            recommended_action=action,
        )
        alerts.append(alert)

    # Sort by severity (critical first)
    alerts.sort(key=lambda a: SEVERITY_ORDER.get(a.severity, 0), reverse=True)
    return alerts


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------

def print_header(title: str) -> None:
    print(f"\n{'=' * 70}")
    print(f"  {title}")
    print(f"{'=' * 70}")


def print_ioc_feed(iocs: List[IOC]) -> None:
    print_header("Loaded IOC Feed")
    print(f"  {'Type':<8} {'Value':<45} {'Threat':<25} {'Severity':<10} {'Source'}")
    print(f"  {'-'*8} {'-'*45} {'-'*25} {'-'*10} {'-'*20}")
    for ioc in iocs:
        print(f"  {ioc.ioc_type:<8} {ioc.value:<45} {ioc.threat:<25} {ioc.severity:<10} {ioc.source}")
    print()


def print_alerts(alerts: List[Alert]) -> None:
    print_header(f"Threat Hunting Results — {len(alerts)} Alert(s) Generated")

    if not alerts:
        print("  No threats detected. Environment is clean.")
        return

    for alert in alerts:
        print(f"  [{alert.severity.upper()}] {alert.alert_id}: {alert.title}")
        print(f"    Source IP      : {alert.event.source_ip}")
        print(f"    Destination    : {alert.event.destination_ip}:{alert.event.destination_port}")
        print(f"    User           : {alert.event.user or 'N/A'}")
        print(f"    Process        : {alert.event.process_name or 'N/A'}")
        print(f"    Time           : {alert.event.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        if alert.matched_ioc:
            print(f"    Matched IOC    : {alert.matched_ioc.value} ({alert.matched_ioc.threat})")
        print(f"    Description    : {alert.description}")
        print(f"    Recommended    : {alert.recommended_action}")
        print()


def print_summary(alerts: List[Alert]) -> None:
    print_header("Summary")
    severity_counts: Dict[str, int] = {}
    for alert in alerts:
        severity_counts[alert.severity] = severity_counts.get(alert.severity, 0) + 1

    print(f"  Total alerts: {len(alerts)}")
    for sev in ["critical", "high", "medium", "low"]:
        count = severity_counts.get(sev, 0)
        if count:
            print(f"    {sev.upper():<10}: {count}")
    print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    print("\n" + "#" * 70)
    print("#  Apex_Cyber_Sentinel — Threat Hunting Demo")
    print("#" * 70)

    events = _generate_sample_events()

    print_ioc_feed(SAMPLE_IOCS)
    print_header(f"Scanning {len(events)} telemetry events...")

    alerts = hunt_threats(events, SAMPLE_IOCS)

    print_alerts(alerts)
    print_summary(alerts)

    print("=" * 70)
    print("  Demo complete.")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    main()
