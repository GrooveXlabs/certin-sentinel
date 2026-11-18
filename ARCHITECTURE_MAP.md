# CERT-In Sentinel: Architecture Map & Domain Model

## 1. Architectural Philosophy: Sovereign-Grade Offline Triage
CERT-In Sentinel is engineered with a strict **air-gapped sovereign architecture**. It performs zero network calls during log analysis, incident classification, and report generation. Sensitive security logs, victim infrastructure topologies, and customer PII are processed completely in memory on local hardware.

```
┌─────────────────────────────────────────────────────────────┐
│                       CLI & UI LAYER                        │
│             (certin_sentinel.cli, Click, Rich)              │
└──────────────────────────────┬──────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────┐
│                    LOG ANALYZER SUBSYSTEM                   │
│  - AuthLogAnalyzer (SSH brute force, sudo escalation, users)│
│  - WebLogAnalyzer  (SQLi, webshells, directory traversal)   │
└──────────────────────────────┬──────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────┐
│                  CORE INTELLIGENCE LAYER                    │
│  - MitreMapper         (Curated ATT&CK v15 knowledge base)  │
│  - IncidentClassifier  (CERT-In categories & DPDP tagging)  │
│  - EvidenceHasher      (SHA-256 chain-of-custody engine)    │
└──────────────────────────────┬──────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────┐
│                      REPORTING ENGINE                       │
│  - CertInReportGenerator (CERT-In 6-Hour Directions format) │
└─────────────────────────────────────────────────────────────┘
```

---

## 2. Core Subsystems

### A. Analyzers (`certin_sentinel.analyzers.*`)
* **`AuthLogAnalyzer`**: Regex parser supporting OpenSSH syslog format, Windows Security Event ID 4625, and Linux `sudo` audit logs. Aggregates failed logons per source IP against a configurable threshold.
* **`WebLogAnalyzer`**: Common Log Format / Combined Log Format parser detecting SQL injection, path traversal payloads (`../`, `%2e%2e`), webshell arguments (`cmd=`, `passthru`), and enumeration scrapers.

### B. Core Intelligence (`certin_sentinel.core.*`)
* **`MitreMapper`**: Offline database of MITRE ATT&CK techniques with search by ID, tactic, and keyword.
* **`IncidentClassifier`**: Classifies raw findings into official CERT-In categories (Ransomware, Data Breach, Unauthorised Access, Defacement, etc.) and tags DPDP Act exposure.
* **`EvidenceHasher`**: Generates and verifies cryptographic SHA-256 hashes for evidence artifacts to ensure admissibility under Section 65B of the Indian Evidence Act.

### C. Reporting Engine (`certin_sentinel.reporters.*`)
* **`CertInReportGenerator`**: Formats structured Markdown incident reports containing the 6-hour countdown deadline, affected systems, IOC table, ATT&CK mapping, and remediation steps.
