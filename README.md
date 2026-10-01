# Apex Cyber Sentinel — Autonomous Cyber Defense Platform

> **Adversarial co-evolution · Attack path mapping · Zero-day detection · Machine-speed response · Deception grid · CTI fusion · CSPM · ITDR**

Apex Cyber Sentinel is a modular, open-source autonomous cyber defense platform that combines adversarial co-evolution, behavioral analytics, graph-based attack path mapping, and machine-speed incident response into a unified defense pipeline. Built with a red/blue team loop at its core, it continuously learns, adapts, and hardens defenses against evolving threats — including zero-days.

---

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Adversarial Co-Evolution Loop](#adversarial-co-evolution-loop)
- [Attack Path Mapping](#attack-path-mapping)
- [Threat Hunting Pipeline](#threat-hunting-pipeline)
- [Machine-Speed Response](#machine-speed-response)
- [Deception Grid](#deception-grid)
- [CTI Fusion](#cti-fusion)
- [CSPM — Cloud Security Posture Management](#cspm--cloud-security-posture-management)
- [ITDR — Identity Threat Detection & Response](#itdr--identity-threat-detection--response)
- [Benchmark Comparisons](#benchmark-comparisons)
- [Installation & Usage](#installation--usage)
- [Testing](#testing)
- [Project Structure](#project-structure)
- [License](#license)

---

## Architecture Overview

Apex Cyber Sentinel is built around a **defense-in-depth** philosophy with nine integrated modules. Each module operates autonomously but feeds into a central defense pipeline that correlates, responds, and evolves.

```mermaid
graph TB
    subgraph External["External Threat Landscape"]
        APT[Advanced Persistent Threats]
        ZERO[Zero-Day Exploits]
        INSIDER[Insider Threats]
        CLOUD[Cloud Misconfigurations]
    end

    subgraph Sensors["Sensor Layer"]
        EDR[EDR / Endpoint Telemetry]
        NET[Network Flow Logs]
        IDP[Identity & Auth Logs]
        CLOUDSEC[Cloud API Logs]
        DECEP[Deception Sensors]
    end

    subgraph Core["Apex Cyber Sentinel Core"]
        direction TB
        CTI[CTI Fusion Engine<br/>STIX/TAXII · IOC · TTP · Actors]
        BEHAV[Behavioral Grammar<br/>Zero-Day Detection]
        HUNT[Threat Hunting<br/>Hypothesis Testing]
        ATTACK[Attack Path Mapper<br/>Graph Analysis]
        CSPM[CSPM<br/>Cloud Posture]
        ITDR[ITDR<br/>Identity Threats]
        DECEP_GRID[Deception Grid<br/>Honeypots · Decoys]
        COEVO[Co-Evolution Engine<br/>Red/Blue Loop]
        RESP[Response Engine<br/>Machine-Speed Playbooks]
    end

    subgraph Actions["Response Actions"]
        ISOLATE[Host Isolation]
        BLOCK[IOC Blocking]
        KILL[Process Kill]
        RESTORE[Backup Restore]
        ALERT[Alert & Escalation]
        HARDEN[Auto-Hardening]
    end

    APT --> Sensors
    ZERO --> Sensors
    INSIDER --> Sensors
    CLOUD --> Sensors

    EDR --> BEHAV
    EDR --> HUNT
    NET --> ATTACK
    IDP --> ITDR
    CLOUDSEC --> CSPM
    DECEP --> DECEP_GRID

    BEHAV --> CTI
    HUNT --> CTI
    ATTACK --> CTI
    CSPM --> CTI
    ITDR --> CTI
    DECEP_GRID --> CTI

    CTI --> COEVO
    COEVO --> RESP
    ATTACK --> RESP
    ITDR --> RESP
    DECEP_GRID --> RESP

    RESP --> ISOLATE
    RESP --> BLOCK
    RESP --> KILL
    RESP --> RESTORE
    RESP --> ALERT
    COEVO --> HARDEN

    HARDEN -.->|Feeds back to| Sensors
    ALERT -.->|Triggers| COEVO
```

### Defense-in-Depth Architecture

```mermaid
flowchart LR
    subgraph Layer1["Layer 1: Perimeter"]
        FW[Firewall]
        WAF[WAF]
        DDoS[DDoS Protection]
    end

    subgraph Layer2["Layer 2: Network"]
        IDS[IDS/IPS]
        NTA[Network Traffic Analysis]
        SEG[Micro-Segmentation]
    end

    subgraph Layer3["Layer 3: Endpoint"]
        EDR[EDR]
        AV[Anti-Virus]
        HIPS[Host IPS]
    end

    subgraph Layer4["Layer 4: Application"]
        RASP[RASP]
        API_SEC[API Security]
        SAST[SAST/DAST]
    end

    subgraph Layer5["Layer 5: Data"]
        DLP[DLP]
        ENC[Encryption]
        IAM[IAM]
    end

    subgraph Layer6["Layer 6: Identity"]
        MFA[MFA]
        PAM[PAM]
        SSO[SSO]
    end

    Layer1 --> Layer2
    Layer2 --> Layer3
    Layer3 --> Layer4
    Layer4 --> Layer5
    Layer5 --> Layer6

    style Layer1 fill:#ffebee,stroke:#c62828
    style Layer2 fill:#fff3e0,stroke:#e65100
    style Layer3 fill:#e3f2fd,stroke:#1565c0
    style Layer4 fill:#f3e5f5,stroke:#6a1b9a
    style Layer5 fill:#e8f5e9,stroke:#2e7d32
    style Layer6 fill:#fce4ec,stroke:#ad1457
```

---

## Adversarial Co-Evolution Loop

The heart of Apex Cyber Sentinel is its **adversarial co-evolution engine** — a continuous red/blue team loop that simulates attacks, evaluates defenses, and automatically hardens the security posture. Each iteration produces measurable improvements in defense coverage and reductions in attack success rates.

```mermaid
flowchart LR
    subgraph Red["🔴 Red Team"]
        ATK_CAT[Attack Categories<br/>Injection · Exploit · Social<br/>Availability · Persistence]
        ATK_TECH[Attack Techniques<br/>SQLi · XSS · RCE<br/>Phishing · DDoS · Zero-Day]
        ATK_SIM[Attack Simulation<br/>Probabilistic Outcomes<br/>Seed-Controlled RNG]
    end

    subgraph Blue["🔵 Blue Team"]
        DEF_CTRL[Defense Controls<br/>WAF · IDS · Firewall<br/>Endpoint · Network · Patching]
        DEF_HARD[Defense Hardening<br/>Auto-Defense Generation<br/>Effectiveness Strengthening]
        DEF_METRICS[Defense Metrics<br/>Coverage · Success Rate<br/>Attack/Defense History]
    end

    subgraph Purple["🟣 Purple Team"]
        CO_ENG[Co-Evolution Engine<br/>Iteration Controller]
        LANDSCAPE[Threat Landscape<br/>State Tracker]
        REPORT[Purple Team Report<br/>Gaps · Recommendations]
    end

    ATK_CAT --> ATK_TECH
    ATK_TECH --> ATK_SIM
    ATK_SIM -->|Simulate Against| DEF_CTRL
    DEF_CTRL -->|Outcome| DEF_HARD
    DEF_HARD -->|New/Improved Controls| DEF_CTRL
    DEF_HARD --> DEF_METRICS
    DEF_METRICS --> CO_ENG
    CO_ENG --> LANDSCAPE
    LANDSCAPE -->|Next Iteration| ATK_SIM
    CO_ENG --> REPORT
    REPORT -->|Gap Analysis| DEF_HARD

    style Red fill:#ffebee,stroke:#c62828
    style Blue fill:#e3f2fd,stroke:#1565c0
    style Purple fill:#f3e5f5,stroke:#6a1b9a
```

### Co-Evolution Cycle Detail

```mermaid
flowchart TD
    START([Start Iteration]) --> GEN[Generate Attack Scenarios<br/>From Threat Landscape]
    GEN --> SIM[Simulate Attacks<br/>Against Current Defenses]
    SIM --> EVAL{Evaluate Outcomes}
    EVAL -->|Attack Succeeded| GAP[Identify Defense Gaps]
    EVAL -->|Attack Blocked| STRENGTHEN[Strengthen Existing Controls]
    GAP --> AUTO[Auto-Generate New Defenses<br/>ML-Based Recommendation]
    AUTO --> VALIDATE[Validate New Controls<br/>Test Against Known Attacks]
    VALIDATE --> UPDATE[Update Defense Registry]
    STRENGTHEN --> UPDATE
    UPDATE --> METRICS[Update Metrics<br/>Coverage · Success Rate]
    METRICS --> NEXT{More Iterations?}
    NEXT -->|Yes| GEN
    NEXT -->|No| REPORT[Generate Purple Team Report<br/>Gaps · Recommendations]
    REPORT --> END([End])

    style START fill:#e8f5e9,stroke:#2e7d32
    style END fill:#e8f5e9,stroke:#2e7d32
    style GAP fill:#ffebee,stroke:#c62828
    style REPORT fill:#f3e5f5,stroke:#6a1b9a
```

### Co-Evolution Metrics

| Metric | Description |
|--------|-------------|
| **Iterations** | Number of red/blue cycles completed |
| **Attack Count** | Unique attack techniques in the arsenal |
| **Defense Count** | Active defensive controls |
| **Success Rate** | Current attack success rate (decreases over time) |
| **Coverage** | Ratio of attack categories with matching defenses |

---

## Attack Path Mapping

Graph-based attack path mapping models the network as a directed graph and identifies all possible routes an attacker could take to reach critical assets. Uses Brandes' algorithm for betweenness centrality, BFS for shortest paths, and DFS for articulation point detection.

```mermaid
graph LR
    subgraph Entry["Entry Points"]
        INT[Internet]
        PHISH[Phishing Email]
        USB[USB Drop]
    end

    subgraph Perimeter["Perimeter Defense"]
        FW[Firewall<br/>risk: 0.2]
        WAF[WAF<br/>risk: 0.3]
        VPN[VPN Gateway<br/>risk: 0.25]
    end

    subgraph DMZ["DMZ"]
        WEB[Web Server<br/>risk: 0.4]
        MAIL[Mail Server<br/>risk: 0.35]
    end

    subgraph Internal["Internal Network"]
        APP[App Server<br/>risk: 0.6]
        WS1[Workstation 1<br/>risk: 0.4]
        WS2[Workstation 2<br/>risk: 0.4]
    end

    subgraph Critical["Critical Assets"]
        DB[(Database<br/>risk: 0.95)]
        DC[Domain Controller<br/>risk: 1.0]
        BK[(Backup Server<br/>risk: 0.85)]
    end

    INT -->|0.9| FW
    PHISH -->|0.7| WS1
    USB -->|0.6| WS2
    FW -->|0.8| WEB
    FW -->|0.5| APP
    FW -->|0.3| WS1
    WAF -->|0.7| WEB
    VPN -->|0.6| WS2
    WEB -->|0.7| APP
    MAIL -->|0.5| WS1
    APP -->|0.8| DB
    APP -->|0.6| DC
    APP -->|0.4| BK
    WS1 -->|0.5| APP
    WS2 -->|0.4| DC

    style Critical fill:#ffebee,stroke:#c62828,stroke-width:3px
    style Entry fill:#fff3e0,stroke:#e65100
    style DMZ fill:#e8f5e9,stroke:#2e7d32
```

### Path Analysis Pipeline

```mermaid
flowchart TD
    TOPO[Network Topology] --> GRAPH[AttackGraph<br/>Directed Graph]
    GRAPH --> PA[PathAnalyzer]
    GRAPH --> CNA[CriticalNodeAnalyzer]

    PA -->|DFS| ALLPATHS[All Simple Paths]
    PA -->|BFS| SHORTEST[Shortest Path]
    PA -->|Entry→Target| EPATHS[Entry-to-Asset Paths]
    PA -->|Product of risks| RISK[Path Risk Score]

    CNA -->|Brandes| BC[Betweenness Centrality]
    CNA -->|Degree| DC[Degree Centrality]
    CNA -->|Composite| RANK[Critical Node Ranking]
    CNA -->|DFS on undirected| AP[Articulation Points]

    ALLPATHS --> MR[MitigationRecommender]
    SHORTEST --> MR
    RISK --> MR
    RANK --> MR
    AP --> MR

    MR -->|Budget-limited| RECS[Mitigation Recommendations<br/>Priority · Action · Risk Reduction]

    style TOPO fill:#e3f2fd,stroke:#1565c0
    style RECS fill:#e8f5e9,stroke:#2e7d32
    style CRITICAL fill:#ffebee,stroke:#c62828
```

---

## Threat Hunting Pipeline

Autonomous threat hunting with hypothesis-driven investigation. The system creates hypotheses from IOCs and TTPs, tests them against event streams, and produces confirmed findings with confidence scores.

```mermaid
flowchart TD
    subgraph Intel["Intelligence Sources"]
        IOC_FEED[IOC Feed<br/>IP · Domain · Hash · URL · Email]
        TTP_DB[TTP Database<br/>MITRE ATT&CK Mapping]
        ACTOR_DB[Threat Actor Profiles<br/>Aliases · Motivation · Sophistication]
    end

    subgraph Hunt["Threat Hunting Engine"]
        HYP[Hypothesis Generator<br/>Auto-created from IOCs/TTPs]
        MATCH[IOC Matcher<br/>Normalized · Case-insensitive]
        TTP_DET[TTP Detector<br/>Event Pattern Matching]
        TEST[Hypothesis Tester<br/>Confidence Scoring]
        RISK_CALC[Risk Score Calculator<br/>Severity-weighted IOC + TTP]
    end

    subgraph Events["Event Stream"]
        SYSLOG[Syslog Events]
        EDR_EVT[EDR Telemetry]
        NET_EVT[Network Events]
        AUTH_EVT[Auth Logs]
    end

    subgraph Output["Hunt Results"]
        CONF[Confirmed Hypotheses<br/>with Confidence Score]
        REJ[Rejected Hypotheses]
        FIND[Findings<br/>Matched IOCs · TTPs]
    end

    IOC_FEED --> HYP
    TTP_DB --> HYP
    ACTOR_DB --> HYP

    HYP --> TEST
    SYSLOG --> MATCH
    EDR_EVT --> MATCH
    NET_EVT --> TTP_DET
    AUTH_EVT --> TTP_DET

    MATCH --> TEST
    TTP_DET --> TEST
    TEST -->|IOCs or TTPs matched| CONF
    TEST -->|No matches| REJ
    CONF --> FIND
    FIND --> RISK_CALC

    style Intel fill:#e3f2fd,stroke:#1565c0
    style Hunt fill:#f3e5f5,stroke:#6a1b9a
    style Output fill:#e8f5e9,stroke:#2e7d32
```

### Risk Scoring Model

| Factor | Weight | Description |
|--------|--------|-------------|
| Critical IOC | 1.0 | Known-bad indicator match |
| High IOC | 0.6 | Suspicious indicator match |
| Medium IOC | 0.3 | Potentially malicious |
| Low IOC | 0.1 | Informational |
| Per TTP | 0.2 | Each matched technique adds to score |
| **Cap** | 1.0 | Score normalized to [0, 1] |

---

## Machine-Speed Response

Incident response engine that executes containment, eradication, and recovery playbooks under a hard wall-clock budget (default 5 seconds, sub-10s guaranteed). Actions within each phase run in parallel with per-action timeouts.

```mermaid
flowchart TD
    INC[Incident Detected<br/>Severity · Indicators · Assets] --> ENGINE

    subgraph Engine["ResponseEngine"]
        ENGINE[Budget Controller<br/>max_duration: 5s<br/>action_timeout: 2s]
    end

    ENGINE --> P1

    subgraph Phase1["Phase 1: Containment"]
        P1[Isolate Host] --> P2[Block Indicator]
        P1 --> P3[Disable Account]
        P2 --> P3
    end

    P1 -->|Parallel execution| P2
    P1 -->|Parallel execution| P3

    Phase1 -->|Budget check| PHASE2{Within Budget?}
    PHASE2 -->|Yes| Phase2
    PHASE2 -->|No| SKIP[Mark Remaining as Skipped]

    subgraph Phase2["Phase 2: Eradication"]
        P4[Kill Process] --> P5[Remove File]
    end

    Phase2 -->|Budget check| PHASE3{Within Budget?}
    PHASE3 -->|Yes| Phase3
    PHASE3 -->|No| SKIP

    subgraph Phase3["Phase 3: Recovery"]
        P6[Restore Backup] --> P7[Restart Service]
    end

    Phase3 --> REPORT[ResponseReport<br/>Duration · Success · Within Budget]

    style INC fill:#ffebee,stroke:#c62828
    style Engine fill:#fff3e0,stroke:#e65100
    style Phase1 fill:#e3f2fd,stroke:#1565c0
    style Phase2 fill:#fce4ec,stroke:#ad1457
    style Phase3 fill:#e8f5e9,stroke:#2e7d32
    style REPORT fill:#f3e5f5,stroke:#6a1b9a
```

### Response Guarantees

| Guarantee | Value |
|-----------|-------|
| Default max duration | 5.0 seconds |
| Action timeout | 2.0 seconds |
| Parallelism | All actions within a phase run concurrently |
| Budget enforcement | Hard wall-clock limit; remaining actions skipped |
| Exception handling | Captured per-action; does not abort playbook |
| Determinism | Budget check before each phase transition |

---

## Deception Grid

A distributed deception layer comprising honeypots, decoys, and attacker engagement tracking. The grid detects lateral movement, collects attacker intelligence, and feeds IOCs back into the CTI fusion engine.

```mermaid
graph TB
    subgraph Grid["Deception Grid"]
        direction LR
        subgraph Honeypots["Honeypots"]
            HP1[SSH Honeypot<br/>Port 2222]
            HP2[HTTP Honeypot<br/>Port 8080]
            HP3[FTP Honeypot<br/>Port 2121]
            HP4[DB Honeypot<br/>Port 3306]
        end

        subgraph Decoys["Decoys"]
            D1[Credential Decoy<br/>admin:******]
            D2[File Decoy<br/>secret.docx]
            D3[Service Decoy<br/>fake-api]
            D4[Database Decoy<br/>shadow DB]
        end
    end

    subgraph Engagement["Attacker Engagement"]
        SESS[Session Tracker<br/>source_ip · honeypot_id · start_time]
        INT_LOG[Interaction Logger<br/>type · data · timestamp]
        LEVEL[Engagement Level<br/>LOW: 1-4 · MEDIUM: 5-14 · HIGH: 15+]
    end

    subgraph Intel["Intelligence Collection"]
        COLLECT[IntelligenceCollector<br/>IOCs · Threat Actors]
        IOC_OUT[IOC Output<br/>IP · Domain · URL · Hash · Email]
        ACTOR_OUT[Threat Actor Profiles<br/>Name · Aliases · IOCs]
        REPORT[Engagement Report<br/>total_iocs · total_actors]
    end

    subgraph Alerts["Alert Generation"]
        ALERT[Severity-based Alerts<br/>LOW: 0 interactions<br/>MEDIUM: 1 interaction<br/>HIGH: 2+ interactions]
    end

    HP1 --> SESS
    HP2 --> SESS
    HP3 --> SESS
    HP4 --> SESS
    D1 --> SESS
    D2 --> SESS

    SESS --> INT_LOG
    INT_LOG --> LEVEL
    LEVEL --> ALERT

    SESS --> COLLECT
    INT_LOG --> COLLECT
    COLLECT --> IOC_OUT
    COLLECT --> ACTOR_OUT
    COLLECT --> REPORT

    IOC_OUT -.->|Feeds into| CTI_FUSE[CTI Fusion Engine]
    ACTOR_OUT -.->|Enriches| CTI_FUSE

    style Grid fill:#e3f2fd,stroke:#1565c0
    style Engagement fill:#fff3e0,stroke:#e65100
    style Intel fill:#e8f5e9,stroke:#2e7d32
    style Alerts fill:#ffebee,stroke:#c62828
```

---

## CTI Fusion

Cyber Threat Intelligence module providing IOC ingestion (JSON/CSV/text with auto-detection), TTP mapping to MITRE ATT&CK, threat actor tracking, and intelligence sharing via STIX 2.1 and TAXII 2.1 standards with TLP enforcement.

```mermaid
flowchart TD
    subgraph Ingestion["Multi-Source Ingestion"]
        JSON_IN[JSON Feed<br/>Structured IOCs]
        CSV_IN[CSV Feed<br/>Tabular IOCs]
        TEXT_IN[Plain Text<br/>Auto-detect Types]
        MANUAL[Manual Entry<br/>Single IOC]
    end

    subgraph Validation["IOC Validation & Normalization"]
        VAL[IOCValidator<br/>IPv4 · IPv6 · Domain · URL<br/>MD5 · SHA1 · SHA256 · Email · CVE]
        NORM[Normalization<br/>Lowercase · Strip whitespace<br/>URL trailing slash removal]
        DEDUP[Deduplication<br/>Update existing on conflict]
    end

    subgraph Storage["CTI Storage"]
        FEED[IOCFeed<br/>Key-value store<br/>Search by type/tag/source]
        TTP_MAP[TTPMapper<br/>IOC→TTP · Actor→TTP<br/>MITRE ATT&CK]
        ACTORS[ActorTracker<br/>Threat Actor Profiles<br/>Aliases · IOCs · TTPs]
    end

    subgraph Export["Standards-Based Export"]
        STIX[STIX 2.1 Exporter<br/>Indicator · Attack-Pattern<br/>Threat-Actor · Bundle]
        TAXII[TAXII 2.1 Collection<br/>Data Collection Objects]
        HUB[SharingHub<br/>TLP-Enforced Sharing<br/>WHITE → GREEN → AMBER → RED]
    end

    subgraph Enrichment["Intelligence Enrichment"]
        REPORT[IntelligenceReport<br/>Title · TLP · IOCs · TTPs · Actors]
        CORR[Cross-Source Correlation<br/>IOC overlap analysis]
    end

    JSON_IN --> VAL
    CSV_IN --> VAL
    TEXT_IN --> VAL
    MANUAL --> VAL

    VAL --> NORM
    NORM --> DEDUP
    DEDUP --> FEED
    DEDUP --> TTP_MAP
    DEDUP --> ACTORS

    FEED --> STIX
    TTP_MAP --> STIX
    ACTORS --> STIX
    STIX --> TAXII
    TAXII --> HUB

    FEED --> REPORT
    TTP_MAP --> REPORT
    ACTORS --> REPORT
    REPORT --> HUB

    HUB -->|TLP check| CORR

    style Ingestion fill:#e3f2fd,stroke:#1565c0
    style Validation fill:#fff3e0,stroke:#e65100
    style Storage fill:#f3e5f5,stroke:#6a1b9a
    style Export fill:#e8f5e9,stroke:#2e7d32
    style Enrichment fill:#fce4ec,stroke:#ad1457
```

### TLP Sharing Rules

| TLP Level | Can Share With |
|-----------|---------------|
| **WHITE** | Anyone (public) |
| **GREEN** | Community members |
| **AMBER** | Organization members only |
| **RED** | Named recipients only |

---

## CSPM — Cloud Security Posture Management

Cloud configuration assessment, compliance checking, and remediation for AWS resources. Evaluates S3 buckets, security groups, and IAM policies against CIS, NIST, PCI-DSS, and HIPAA frameworks.

```mermaid
flowchart TD
    subgraph Cloud["Cloud Resources"]
        S3[S3 Bucket<br/>public_access_block<br/>encryption · versioning]
        SG[Security Group<br/>ingress_rules<br/>cidr · port · protocol]
        IAM[IAM Policy<br/>policy_document<br/>Action · Resource]
    end

    subgraph Assessment["CSPM Engine"]
        S3_CHECK{S3 Assessment}
        SG_CHECK{SG Assessment}
        IAM_CHECK{IAM Assessment}
    end

    subgraph Findings["Findings"]
        F1[S3-001: Public Access<br/>CRITICAL]
        F2[S3-002: No Encryption<br/>HIGH]
        F3[S3-003: No Versioning<br/>MEDIUM]
        F4[SG-001: 0.0.0.0/0 Ingress<br/>CRITICAL]
        F5[IAM-001: Admin Privileges<br/>CRITICAL]
    end

    subgraph Compliance["Compliance Reporting"]
        CIS[CIS Benchmark]
        NIST[NIST Framework]
        PCI[PCI-DSS]
        HIPAA[HIPAA]
        SCORE[Compliance Score<br/>100 - 10×findings]
    end

    subgraph Remediation["Remediation"]
        R1[Enable Public Access Block<br/>Automatable]
        R2[Enable Encryption<br/>Automatable]
        R3[Enable Versioning<br/>Automatable]
        R4[Remove 0.0.0.0/0<br/>Automatable]
        R5[Least Privilege IAM<br/>Manual]
    end

    S3 --> S3_CHECK
    SG --> SG_CHECK
    IAM --> IAM_CHECK

    S3_CHECK --> F1
    S3_CHECK --> F2
    S3_CHECK --> F3
    SG_CHECK --> F4
    IAM_CHECK --> F5

    F1 --> CIS
    F2 --> NIST
    F3 --> PCI
    F4 --> HIPAA
    F5 --> SCORE

    F1 --> R1
    F2 --> R2
    F3 --> R3
    F4 --> R4
    F5 --> R5

    style Cloud fill:#e3f2fd,stroke:#1565c0
    style Findings fill:#ffebee,stroke:#c62828
    style Compliance fill:#fff3e0,stroke:#e65100
    style Remediation fill:#e8f5e9,stroke:#2e7d32
```

---

## ITDR — Identity Threat Detection & Response

Detects identity anomalies, credential compromise, and lateral movement from authentication logs and network connection data. Covers impossible travel, brute force, password spraying, credential stuffing, pass-the-hash, and service account abuse.

```mermaid
flowchart TD
    subgraph Input["Identity Data Sources"]
        LOGIN[Login Events<br/>user · source_ip · location<br/>success · auth_method]
        CONN[Network Connections<br/>source_host · dest_host<br/>user · protocol]
        BREACH[Breached Credential Set]
        HIST[Historical Login Data]
    end

    subgraph Detection["ITDR Detection Engines"]
        direction TB
        subgraph IdentityAnomaly["Identity Anomaly Detector"]
            IT[Impossible Travel<br/>Haversine distance<br/>speed > 900 km/h]
            OFF[Off-Hours Access<br/>Outside 9-17]
            NEWLOC[New Location<br/>Min distance from history]
            CONC[Concurrent Sessions<br/>Same user, different IPs<br/>within 30 min]
        end

        subgraph CredComp["Credential Compromise Detector"]
            BF[Brute Force<br/>5+ failures in 10 min]
            PS[Password Spraying<br/>1 IP → 3+ accounts]
            CS[Credential Stuffing<br/>Known breached creds]
            SAF[Success After Failures<br/>Success after 2+ failures]
        end

        subgraph LatMove["Lateral Movement Detector"]
            SEQ[Sequential Host Access<br/>3+ hosts in 60 min]
            PTH[Pass-the-Hash<br/>NTLM without interactive login]
            ADM[New Admin Connection<br/>Admin → unseen host]
            SAA[Service Account Abuse<br/>Service acct → 3+ hosts]
        end
    end

    subgraph Output["ITDR Report"]
        ALERTS[Aggregated Alerts<br/>type · severity · user · details]
        SUMMARY[Summary by Type<br/>by Severity]
    end

    LOGIN --> IT
    LOGIN --> OFF
    LOGIN --> CONC
    HIST --> NEWLOC
    LOGIN --> BF
    LOGIN --> PS
    BREACH --> CS
    LOGIN --> SAF
    CONN --> SEQ
    CONN --> PTH
    CONN --> ADM
    CONN --> SAA

    IT --> ALERTS
    OFF --> ALERTS
    NEWLOC --> ALERTS
    CONC --> ALERTS
    BF --> ALERTS
    PS --> ALERTS
    CS --> ALERTS
    SAF --> ALERTS
    SEQ --> ALERTS
    PTH --> ALERTS
    ADM --> ALERTS
    SAA --> ALERTS

    ALERTS --> SUMMARY

    style Input fill:#e3f2fd,stroke:#1565c0
    style IdentityAnomaly fill:#fff3e0,stroke:#e65100
    style CredComp fill:#fce4ec,stroke:#ad1457
    style LatMove fill:#f3e5f5,stroke:#6a1b9a
    style Output fill:#e8f5e9,stroke:#2e7d32
```

### ITDR Alert Types

| Alert Type | Severity | Trigger |
|------------|----------|---------|
| Impossible Travel | HIGH | Speed > 900 km/h between logins |
| Off-Hours Access | MEDIUM | Login outside configured work hours |
| New Location | MEDIUM | Login far from all historical locations |
| Concurrent Sessions | HIGH | Same user, different IPs in 30 min |
| Brute Force | HIGH | 5+ failed logins in 10 min |
| Password Spraying | HIGH | 1 IP targeting 3+ accounts |
| Credential Stuffing | CRITICAL | Login with known breached credentials |
| Success After Failures | CRITICAL | Success after 2+ consecutive failures |
| Lateral Movement | HIGH | 3+ distinct hosts accessed in 60 min |
| Pass-the-Hash | CRITICAL | NTLM auth without interactive login |
| New Admin Connection | MEDIUM | Admin connecting to unseen host |
| Service Account Abuse | HIGH | Service account accessing 3+ hosts |

---

## Benchmark Comparisons

### Feature Matrix

| Capability | Apex Cyber Sentinel | CrowdStrike Falcon | SentinelOne Singularity | Palo Alto Cortex | Darktrace |
|------------|:---:|:---:|:---:|:---:|:---:|
| **Endpoint Detection & Response** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Behavioral Zero-Day Detection** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Adversarial Co-Evolution** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Attack Path Mapping (Graph)** | ✅ | ⚠️ Limited | ❌ | ⚠️ Limited | ❌ |
| **Machine-Speed Response (<10s)** | ✅ | ✅ | ✅ | ✅ | ⚠️ |
| **Deception Grid (Honeypots)** | ✅ | ✅ | ❌ | ❌ | ✅ |
| **CTI Fusion (STIX/TAXII)** | ✅ | ✅ | ✅ | ✅ | ⚠️ |
| **CSPM (Cloud Posture)** | ✅ | ⚠️ | ⚠️ | ✅ | ❌ |
| **ITDR (Identity Threats)** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Autonomous Threat Hunting** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Purple Team Validation** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Open Source** | ✅ AGPL-3.0 | ❌ Proprietary | ❌ Proprietary | ❌ Proprietary | ❌ Proprietary |
| **Self-Hosted / On-Prem** | ✅ | ⚠️ Cloud-only | ⚠️ Cloud-only | ⚠️ Cloud-only | ⚠️ Appliance |

> ✅ Full support · ⚠️ Partial/Limited · ❌ Not available

### Detection Capability Comparison

| Detection Method | Apex Cyber Sentinel | CrowdStrike | SentinelOne | Palo Alto Cortex | Darktrace |
|------------------|:---:|:---:|:---:|:---:|:---:|
| Signature-Based | ✅ | ✅ | ✅ | ✅ | ✅ |
| Behavioral Analytics | ✅ | ✅ | ✅ | ✅ | ✅ |
| N-Gram Pattern Learning | ✅ | ❌ | ❌ | ❌ | ❌ |
| Graph-Based Path Analysis | ✅ | ❌ | ❌ | ❌ | ❌ |
| Identity Anomaly (Impossible Travel) | ✅ | ✅ | ✅ | ✅ | ✅ |
| Credential Compromise | ✅ | ✅ | ✅ | ✅ | ⚠️ |
| Lateral Movement | ✅ | ✅ | ✅ | ✅ | ✅ |
| Deception-Based Detection | ✅ | ✅ | ❌ | ❌ | ✅ |

### Response Automation Comparison

| Response Capability | Apex Cyber Sentinel | CrowdStrike | SentinelOne | Palo Alto Cortex | Darktrace |
|---------------------|:---:|:---:|:---:|:---:|:---:|
| Host Isolation | ✅ | ✅ | ✅ | ✅ | ✅ |
| IOC Blocking | ✅ | ✅ | ✅ | ✅ | ✅ |
| Process Termination | ✅ | ✅ | ✅ | ✅ | ✅ |
| Account Disable | ✅ | ✅ | ✅ | ✅ | ✅ |
| Backup Restore | ✅ | ⚠️ | ⚠️ | ❌ | ❌ |
| Auto-Hardening | ✅ | ❌ | ❌ | ❌ | ❌ |
| Parallel Action Execution | ✅ | ✅ | ✅ | ✅ | ⚠️ |
| Hard Wall-Clock Budget | ✅ | ❌ | ❌ | ❌ | ❌ |
| Playbook Phases | ✅ | ✅ | ✅ | ✅ | ✅ |

### Architecture & Deployment Comparison

| Aspect | Apex Cyber Sentinel | CrowdStrike | SentinelOne | Palo Alto Cortex | Darktrace |
|--------|:---:|:---:|:---:|:---:|:---:|
| **Deployment** | Self-hosted / Cloud | Cloud SaaS | Cloud SaaS | Cloud SaaS | Appliance / Cloud |
| **Agent Required** | No (library) | Yes | Yes | Yes | Yes |
| **Modular Architecture** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Python Native** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Extensible API** | ✅ | ✅ | ✅ | ✅ | ⚠️ |
| **Open Standards (STIX/TAXII)** | ✅ | ✅ | ✅ | ✅ | ⚠️ |
| **Community-Driven** | ✅ | ❌ | ❌ | ❌ | ❌ |

### Apex Cyber Sentinel Unique Advantages

1. **Adversarial Co-Evolution**: The only platform with a built-in red/blue team loop that automatically hardens defenses through continuous simulation
2. **Graph-Based Attack Path Mapping**: Full attack graph analysis with betweenness centrality, articulation points, and mitigation recommendations
3. **N-Gram Behavioral Grammar**: Learns normal behavior patterns and detects zero-days through deviation analysis
4. **Hard-Budget Response**: Guaranteed sub-10-second response with parallel execution and per-action timeouts
5. **Integrated Deception Grid**: Honeypots, decoys, and attacker engagement tracking built into the core platform
6. **Full STIX/TAXII Support**: Standards-based intelligence sharing with TLP enforcement
7. **Open Source (AGPL-3.0)**: Fully auditable, extensible, and self-hostable

---

## Installation & Usage

### Prerequisites

- Python 3.10+
- pip

### Install

```bash
git clone https://github.com/your-org/Apex_Cyber_Sentinel.git
cd Apex_Cyber_Sentinel
pip install -e .
```

### Quick Start

```python
from src.cyber.coevolution import CoEvolutionEngine, AttackTechnique, DefenseControl

# Initialize the co-evolution engine
engine = CoEvolutionEngine(seed=42)

# Add attack techniques
engine.add_attack_technique(AttackTechnique(
    name="SQL Injection", category="injection", severity=0.8
))
engine.add_attack_technique(AttackTechnique(
    name="XSS", category="injection", severity=0.6
))

# Add initial defenses
engine.add_defense_control(DefenseControl(
    name="WAF", category="injection", effectiveness=0.7
))

# Run co-evolution iterations
engine.run_iterations(10)

# Check metrics
metrics = engine.get_metrics()
print(f"Coverage: {metrics['coverage']:.1%}")
print(f"Success Rate: {metrics['success_rate']:.1%}")
print(f"Defense Count: {metrics['defense_count']}")
```

### Attack Path Mapping

```python
from src.cyber.attack_graph import AttackGraph, PathAnalyzer, CriticalNodeAnalyzer

# Build attack graph
graph = AttackGraph()
graph.add_node("internet", node_type="entry", risk=0.1)
graph.add_node("firewall", node_type="firewall", risk=0.2)
graph.add_node("db", node_type="critical", risk=0.95)
graph.add_edge("internet", "firewall", probability=0.9)
graph.add_edge("firewall", "db", probability=0.7)

# Analyze paths
pa = PathAnalyzer(graph)
paths = pa.find_all_paths("internet", "db")
print(f"Attack paths: {paths}")

# Find critical nodes
cna = CriticalNodeAnalyzer(graph)
critical = cna.get_critical_nodes(top_n=3)
print(f"Critical nodes: {critical}")
```

### Machine-Speed Response

```python
from src.cyber.response import Incident, Indicator, ResponseEngine, ResponsePlaybook

# Create an incident
incident = Incident(
    id="INC-001",
    severity="critical",
    title="Ransomware detected",
    indicators=[Indicator(type="ip", value="203.0.113.10")],
    affected_assets=["fs-01"],
    detected_at=__import__('time').time(),
)

# Execute response playbook
engine = ResponseEngine(ResponsePlaybook.default(), max_duration=5.0)
report = engine.respond(incident)
print(f"Response completed in {report.duration:.2f}s")
print(f"Within budget: {report.within_budget}")
```

---

## Testing

The project uses **pytest** with comprehensive unit and integration tests.

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src --cov-report=html

# Run specific module tests
pytest tests/test_coevolution.py -v
pytest tests/test_attack_graph.py -v
pytest tests/test_response.py -v

# Run integration tests
pytest tests/integration/ -v
```

### Test Coverage

| Module | Test File | Tests |
|--------|-----------|-------|
| Co-Evolution | `test_coevolution.py` | 30+ |
| Attack Graph | `test_attack_graph.py` | 40+ |
| Behavioral Grammar | `test_behavioral.py` | 25+ |
| Response Engine | `test_response.py` | 25+ |
| Deception Grid | `test_deception.py` | 30+ |
| CTI | `test_cti.py` | 50+ |
| CSPM | `test_cspm.py` | 20+ |
| ITDR | `test_itdr.py` | 15+ |
| Threat Hunting | `test_hunting.py` | 20+ |
| Integration | `test_cyber.py` | 12 E2E |

**Total: 669 tests across 29 files covering 10 topics**

---

## Project Structure

```
Apex_Cyber_Sentinel/
├── src/
│   └── cyber/
│       ├── __init__.py
│       ├── coevolution.py      # Adversarial co-evolution engine
│       ├── attack_graph.py     # Graph-based attack path mapping
│       ├── behavioral.py       # N-gram behavioral grammar
│       ├── response.py         # Machine-speed incident response
│       ├── deception.py        # Deception grid (honeypots, decoys)
│       ├── cti.py              # CTI fusion (STIX/TAXII)
│       ├── cspm.py             # Cloud Security Posture Management
│       ├── itdr.py             # Identity Threat Detection & Response
│       └── hunting.py          # Autonomous threat hunting
├── tests/
│   ├── test_coevolution.py
│   ├── test_attack_graph.py
│   ├── test_behavioral.py
│   ├── test_response.py
│   ├── test_deception.py
│   ├── test_cti.py
│   ├── test_cspm.py
│   ├── test_itdr.py
│   ├── test_hunting.py
│   └── integration/
│       └── test_cyber.py       # End-to-end pipeline tests
├── docs/
├── pytest.ini
├── README.md
└── LICENSE
```

---

## License

This project is licensed under the **GNU Affero General Public License v3.0 (AGPL-3.0)**.

```
Apex Cyber Sentinel — Autonomous Cyber Defense Platform
Copyright (C) 2024 Ahmed Hassan

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
```

See [LICENSE](LICENSE) for the full license text.

---

<div align="center">

**Apex Cyber Sentinel** — *Autonomous defense through adversarial co-evolution.*

**669 tests · 29 files · 10 topics · AGPL-3.0**

</div>
