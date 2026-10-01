#!/usr/bin/env python3
"""
Apex_Cyber_Sentinel — Deception Technology Demo
===============================================

Demonstrates a deception layer by deploying sample decoy assets
(fake services, credentials, and files) across a simulated network,
then detecting and alerting on any interaction with those decoys.

The demo simulates:
  1. Decoy deployment (services, credentials, honeyfiles)
  2. Adversary interaction with decoys
  3. Real-time alerting and forensic capture

Usage:
    python demo_deception.py
"""

import hashlib
import json
import random
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

class DecoyType(Enum):
    SERVICE     = "service"      # fake network service (SSH, HTTP, etc.)
    CREDENTIAL  = "credential"   # fake credentials (honey tokens)
    FILE        = "file"         # honeyfiles (fake sensitive documents)
    DATABASE    = "database"     # fake database with synthetic records


class InteractionType(Enum):
    ACCESS      = "access"       # port scan or connection attempt
    LOGIN       = "login"        # authentication attempt with honey creds
    READ        = "read"         # file read / database query
    EXPLOIT     = "exploit"      # exploitation attempt against decoy service


@dataclass
class Decoy:
    """A deployed deception asset."""
    decoy_id: str
    name: str
    decoy_type: DecoyType
    ip_address: str
    port: int
    description: str
    deployed_at: datetime
    interactions: List["Interaction"] = field(default_factory=list)


@dataclass
class Interaction:
    """An adversary interaction with a decoy."""
    interaction_id: str
    timestamp: datetime
    source_ip: str
    interaction_type: InteractionType
    details: str
    captured_payload: Optional[str] = None


@dataclass
class DeceptionAlert:
    """An alert generated from a decoy interaction."""
    alert_id: str
    decoy: Decoy
    interaction: Interaction
    severity: str
    message: str
    recommended_action: str


# ---------------------------------------------------------------------------
# Decoy deployment
# ---------------------------------------------------------------------------

def deploy_decoys() -> List[Decoy]:
    """Deploy a set of deception assets across the simulated network."""
    now = datetime(2026, 10, 1, 12, 0, 0)

    decoys = [
        Decoy(
            decoy_id="DEC-001",
            name="Fake SSH Server",
            decoy_type=DecoyType.SERVICE,
            ip_address="10.0.3.10",
            port=22,
            description="OpenSSH 7.4 on Ubuntu — appears to be a misconfigured server",
            deployed_at=now,
        ),
        Decoy(
            decoy_id="DEC-002",
            name="Fake Web Portal",
            decoy_type=DecoyType.SERVICE,
            ip_address="10.0.3.11",
            port=8080,
            description="Apache/2.4.29 — appears to be an internal admin panel",
            deployed_at=now,
        ),
        Decoy(
            decoy_id="DEC-003",
            name="Honey Credentials — svc_backup",
            decoy_type=DecoyType.CREDENTIAL,
            ip_address="10.0.3.10",
            port=22,
            description="Fake service account: svc_backup / B@ckup!2026",
            deployed_at=now,
        ),
        Decoy(
            decoy_id="DEC-004",
            name="Honey Credentials — admin",
            decoy_type=DecoyType.CREDENTIAL,
            ip_address="10.0.3.11",
            port=8080,
            description="Fake admin account: admin / Adm1n$trator!",
            deployed_at=now,
        ),
        Decoy(
            decoy_id="DEC-005",
            name="Honeyfile — Q3_Financials.xlsx",
            decoy_type=DecoyType.FILE,
            ip_address="10.0.3.20",
            port=445,
            description="Fake financial spreadsheet on file share",
            deployed_at=now,
        ),
        Decoy(
            decoy_id="DEC-006",
            name="Honeyfile — customer_db.sql",
            decoy_type=DecoyType.FILE,
            ip_address="10.0.3.20",
            port=445,
            description="Fake customer database dump",
            deployed_at=now,
        ),
        Decoy(
            decoy_id="DEC-007",
            name="Fake PostgreSQL DB",
            decoy_type=DecoyType.DATABASE,
            ip_address="10.0.3.30",
            port=5432,
            description="PostgreSQL 12 — appears to contain production data",
            deployed_at=now,
        ),
    ]
    return decoys


# ---------------------------------------------------------------------------
# Simulated adversary interactions
# ---------------------------------------------------------------------------

def simulate_interactions(decoys: List[Decoy]) -> None:
    """Simulate an adversary interacting with deployed decoys."""
    base_time = datetime(2026, 10, 1, 14, 30, 0)
    attacker_ip = "185.220.101.42"

    # Interaction 1: Port scan against fake SSH
    decoys[0].interactions.append(Interaction(
        interaction_id="INT-001",
        timestamp=base_time,
        source_ip=attacker_ip,
        interaction_type=InteractionType.ACCESS,
        details="TCP SYN scan detected on port 22",
        captured_payload="Nmap scan: nmap -sS 10.0.3.10",
    ))

    # Interaction 2: SSH login attempt with honey creds
    decoys[0].interactions.append(Interaction(
        interaction_id="INT-002",
        timestamp=base_time.replace(minute=32),
        source_ip=attacker_ip,
        interaction_type=InteractionType.LOGIN,
        details="SSH login attempt: svc_backup / B@ckup!2026 (SUCCESS)",
        captured_payload="ssh svc_backup@10.0.3.10 — password accepted",
    ))

    # Interaction 3: Web admin panel access
    decoys[1].interactions.append(Interaction(
        interaction_id="INT-003",
        timestamp=base_time.replace(minute=35),
        source_ip=attacker_ip,
        interaction_type=InteractionType.ACCESS,
        details="HTTP GET /admin/login.php on fake web portal",
        captured_payload="GET /admin/login.php HTTP/1.1 — User-Agent: Mozilla/5.0",
    ))

    # Interaction 4: Admin login attempt
    decoys[1].interactions.append(Interaction(
        interaction_id="INT-004",
        timestamp=base_time.replace(minute=36),
        source_ip=attacker_ip,
        interaction_type=InteractionType.LOGIN,
        details="HTTP POST /admin/login.php — admin / Adm1n$trator! (SUCCESS)",
        captured_payload="POST /admin/login.php — username=admin&password=Adm1n$trator!",
    ))

    # Interaction 5: File access on fake file share
    decoys[4].interactions.append(Interaction(
        interaction_id="INT-005",
        timestamp=base_time.replace(minute=40),
        source_ip=attacker_ip,
        interaction_type=InteractionType.READ,
        details="SMB read: \\\\10.0.3.20\\finance\\Q3_Financials.xlsx",
        captured_payload="SMB2 Read Request — File: Q3_Financials.xlsx",
    ))

    # Interaction 6: Database query on fake PostgreSQL
    decoys[6].interactions.append(Interaction(
        interaction_id="INT-006",
        timestamp=base_time.replace(minute=45),
        source_ip=attacker_ip,
        interaction_type=InteractionType.READ,
        details="SQL query: SELECT * FROM customers WHERE ssn IS NOT NULL",
        captured_payload="psql -h 10.0.3.30 -U postgres -c 'SELECT * FROM customers'",
    ))

    # Interaction 7: Exploitation attempt against fake SSH
    decoys[0].interactions.append(Interaction(
        interaction_id="INT-007",
        timestamp=base_time.replace(minute=50),
        source_ip=attacker_ip,
        interaction_type=InteractionType.EXPLOIT,
        details="CVE-2018-15473 user enumeration exploit attempted",
        captured_payload="OpenSSH 7.4 — invalid user enumeration payload",
    ))


# ---------------------------------------------------------------------------
# Alert generation
# ---------------------------------------------------------------------------

SEVERITY_MAP = {
    InteractionType.ACCESS:  "medium",
    InteractionType.LOGIN:   "high",
    InteractionType.READ:    "high",
    InteractionType.EXPLOIT: "critical",
}

ACTION_MAP = {
    InteractionType.ACCESS:  "Monitor and log — possible reconnaissance phase",
    InteractionType.LOGIN:   "ISOLATE source IP and reset honey credentials",
    InteractionType.READ:    "ISOLATE source IP and capture forensic image",
    InteractionType.EXPLOIT: "ISOLATE source IP immediately and initiate IR playbook",
}


def generate_alerts(decoys: List[Decoy]) -> List[DeceptionAlert]:
    """Generate alerts from all decoy interactions."""
    alerts: List[DeceptionAlert] = []

    for decoy in decoys:
        for interaction in decoy.interactions:
            severity = SEVERITY_MAP.get(interaction.interaction_type, "low")
            action = ACTION_MAP.get(interaction.interaction_type, "Log and monitor")

            alert = DeceptionAlert(
                alert_id=f"DEC-ALERT-{interaction.interaction_id}",
                decoy=decoy,
                interaction=interaction,
                severity=severity,
                message=(
                    f"Deception trigger: {interaction.interaction_type.value} "
                    f"on {decoy.name} ({decoy.ip_address}:{decoy.port}) "
                    f"from {interaction.source_ip}"
                ),
                recommended_action=action,
            )
            alerts.append(alert)

    # Sort by severity (critical first)
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    alerts.sort(key=lambda a: severity_order.get(a.severity, 99))
    return alerts


# ---------------------------------------------------------------------------
# Forensic capture
# ---------------------------------------------------------------------------

def capture_forensics(alert: DeceptionAlert) -> Dict:
    """Simulate forensic capture for a given alert."""
    return {
        "alert_id": alert.alert_id,
        "timestamp": alert.interaction.timestamp.isoformat(),
        "source_ip": alert.interaction.source_ip,
        "decoy": alert.decoy.name,
        "interaction_type": alert.interaction.interaction_type.value,
        "payload": alert.interaction.captured_payload,
        "pcap_captured": True,
        "memory_dump": alert.interaction.interaction_type == InteractionType.EXPLOIT,
        "disk_image": alert.interaction.interaction_type == InteractionType.READ,
    }


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------

def print_header(title: str) -> None:
    print(f"\n{'=' * 70}")
    print(f"  {title}")
    print(f"{'=' * 70}")


def print_deployment(decoys: List[Decoy]) -> None:
    print_header(f"Decoy Deployment — {len(decoys)} assets")
    print(f"  {'ID':<10} {'Name':<35} {'Type':<12} {'IP':<16} {'Port':<6} {'Description'}")
    print(f"  {'-'*10} {'-'*35} {'-'*12} {'-'*16} {'-'*6} {'-'*30}")
    for d in decoys:
        print(f"  {d.decoy_id:<10} {d.name:<35} {d.decoy_type.value:<12} {d.ip_address:<16} {d.port:<6} {d.description}")
    print()


def print_interactions(decoys: List[Decoy]) -> None:
    total = sum(len(d.interactions) for d in decoys)
    print_header(f"Simulated Adversary Interactions — {total} events")

    for decoy in decoys:
        if not decoy.interactions:
            continue
        print(f"  {decoy.name} ({decoy.ip_address}:{decoy.port}):")
        for inter in decoy.interactions:
            print(f"    [{inter.interaction_type.value.upper():<8}] {inter.timestamp.strftime('%H:%M:%S')} "
                  f"from {inter.source_ip} — {inter.details}")
        print()


def print_alerts(alerts: List[DeceptionAlert]) -> None:
    print_header(f"Deception Alerts — {len(alerts)} generated")

    if not alerts:
        print("  No alerts. No adversary activity detected.")
        return

    for alert in alerts:
        print(f"  [{alert.severity.upper()}] {alert.alert_id}")
        print(f"    Message    : {alert.message}")
        print(f"    Source IP  : {alert.interaction.source_ip}")
        print(f"    Time       : {alert.interaction.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"    Payload    : {alert.interaction.captured_payload or 'N/A'}")
        print(f"    Action     : {alert.recommended_action}")
        print()


def print_forensics(alerts: List[DeceptionAlert]) -> None:
    print_header("Forensic Captures")
    for alert in alerts:
        forensics = capture_forensics(alert)
        print(f"  {forensics['alert_id']}:")
        print(f"    PCAP        : {'Captured' if forensics['pcap_captured'] else 'N/A'}")
        print(f"    Memory dump : {'Captured' if forensics['memory_dump'] else 'N/A'}")
        print(f"    Disk image  : {'Captured' if forensics['disk_image'] else 'N/A'}")
        print()


def print_summary(decoys: List[Decoy], alerts: List[DeceptionAlert]) -> None:
    print_header("Deception Summary")
    total_interactions = sum(len(d.interactions) for d in decoys)
    triggered_decoys = sum(1 for d in decoys if d.interactions)

    severity_counts: Dict[str, int] = {}
    for alert in alerts:
        severity_counts[alert.severity] = severity_counts.get(alert.severity, 0) + 1

    print(f"  Decoys deployed        : {len(decoys)}")
    print(f"  Decoys triggered       : {triggered_decoys}")
    print(f"  Total interactions     : {total_interactions}")
    print(f"  Alerts generated       : {len(alerts)}")
    print(f"  Alert breakdown:")
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
    print("#  Apex_Cyber_Sentinel — Deception Technology Demo")
    print("#" * 70)

    # Step 1: Deploy decoys
    decoys = deploy_decoys()
    print_deployment(decoys)

    # Step 2: Simulate adversary activity
    simulate_interactions(decoys)
    print_interactions(decoys)

    # Step 3: Generate alerts
    alerts = generate_alerts(decoys)
    print_alerts(alerts)

    # Step 4: Forensic capture
    print_forensics(alerts)

    # Step 5: Summary
    print_summary(decoys, alerts)

    print("=" * 70)
    print("  Demo complete.")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    main()
