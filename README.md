# CERT-In Sentinel 🇮🇳
> **Sovereign Cyber Incident Triage, MITRE ATT&CK Mapping & 6-Hour CERT-In / DPDP Compliance Engine**  
> *Crafted with defense-in-depth by GrooveXlabs — Sovereign Digital Infrastructure for India.*

[![CI Status](https://img.shields.io/badge/CI-Passing-brightgreen?style=for-the-badge&logo=githubactions&logoColor=white)](https://github.com/GrooveXlabs/certin-sentinel)
[![License: MIT](https://img.shields.io/badge/License-MIT-black?style=for-the-badge)](https://opensource.org/licenses/MIT)
[![Python Version](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Compliance: CERT--In](https://img.shields.io/badge/Compliance-CERT--In%206--Hour-orange?style=for-the-badge)](https://www.cert-in.org.in/)
[![Compliance: DPDP Act](https://img.shields.io/badge/Compliance-DPDP%20Act%202023-purple?style=for-the-badge)](https://github.com/GrooveXlabs/certin-sentinel)

---

## ⚡ The Challenge
Under the **CERT-In Cyber Security Directions (April 2022)**, all Indian organizations, service providers, intermediaries, data centres, and government bodies **MUST report cybersecurity incidents within 6 hours** of detection.

Simultaneously, the **Digital Personal Data Protection (DPDP) Act 2023** mandates strict breach disclosure and forensic accountability with penalties reaching up to **₹250 Crore**.

During an active breach, security teams lose valuable hours manually sifting through raw syslog files, web server logs, mapping techniques to MITRE ATT&CK, and drafting regulatory disclosure forms.

---

## 🛡️ The Solution: CERT-In Sentinel
**CERT-In Sentinel** is a sovereign, 100% offline incident triage and compliance automation engine. It transforms raw log streams into structured, regulatory-compliant CERT-In reports in seconds.

* **Zero Cloud Dependencies:** Operates completely air-gapped on sovereign infrastructure. Sensitive log files, customer PII, and breach details never leave your perimeter.
* **Automated Log Parsing & Attack Detection:** Deterministic detection of SSH brute force, SQL injection, path traversal, webshell deployment, and privilege escalation.
* **Integrated MITRE ATT&CK v15 Mapping:** Automatically maps detected behaviors to standardized MITRE ATT&CK technique IDs and tactics.
* **Forensic Chain-of-Custody:** SHA-256 evidence hashing compatible with GrooveXlabs `forenchain` evidence standards.
* **Instant Regulatory Reports:** Generates professional markdown disclosure reports formatted for CERT-In incident reporting and DPDP Board notification.

```
   ┌──────────────────────────────────────────────┐
   │ Raw System Logs (auth.log, nginx, syslog)   │
   └──────────────────────┬───────────────────────┘
                          │
                          ▼
   ┌──────────────────────────────────────────────┐
   │             CERT-IN SENTINEL                 │
   │ ───────────────────────────────────────────  │
   │  [✔] Auth Analyzer (SSH brute, sudo, accts)  │
   │  [✔] Web Analyzer (SQLi, webshell, traversal)│
   │  [✔] Offline MITRE ATT&CK v15 Mapper         │
   │  [✔] Incident Classifier & DPDP Assessor     │
   │  [✔] SHA-256 Evidence Hasher & Verifier      │
   └──────────────────────┬───────────────────────┘
                          │
                          ▼
   ┌──────────────────────────────────────────────┐
   │  Structured CERT-In 6-Hour Disclosure Report │
   │  + DPDP Act Section 8 Remediation Roadmap    │
   └──────────────────────────────────────────────┘
```

---

## 🚀 Key Features

1. **Authentication Log Analyzer:**
   Identifies SSH/Windows brute-force attacks, unauthorized root privilege escalation, and suspicious user account creations:
   ```bash
   sentinel analyze-auth /var/log/auth.log --threshold 5
   ```
2. **Web Application Attack Analyzer:**
   Detects SQL injection queries, directory traversal sequences, webshell execution, and automated recon scanners in Apache/Nginx access logs:
   ```bash
   sentinel analyze-web /var/log/nginx/access.log
   ```
3. **Automated Incident Triage & Report Generation:**
   Classifies incident severity and outputs a complete CERT-In report:
   ```bash
   sentinel triage --title "Payment Gateway SQL Injection" \
     --summary "SQL injection exploited on checkout API leaking customer order details" \
     --systems "api-gateway,db-primary" \
     --iocs "203.0.113.10" \
     --output certin_disclosure.md
   ```
4. **Forensic Evidence Hasher:**
   Generates and verifies cryptographic hashes for logs, memory dumps, and disk images to preserve legal chain-of-custody:
   ```bash
   sentinel hash-evidence /var/log/auth.log --note "Original perimeter auth log snapshot"
   ```
5. **MITRE ATT&CK Offline Search:**
   Quickly query ATT&CK techniques, tactics, and data sources without internet access:
   ```bash
   sentinel mitre-search "brute force"
   ```

---

## 📦 Quickstart & Installation

```bash
# Clone the repository
git clone https://github.com/GrooveXlabs/certin-sentinel.git
cd certin-sentinel

# Install package
pip install -e .
```

### Quick Verification
```bash
sentinel --help
```

---

## ⚖️ Regulatory References
* **CERT-In Directions (April 2022):** Section 70B(6) of the Information Technology Act 2000.
* **DPDP Act 2023:** Digital Personal Data Protection Act, Sections 8(5) and 8(6).
* **MITRE ATT&CK:** Enterprise ATT&CK matrix v15.

---

## 📜 License
Licensed under the [MIT License](LICENSE).  
Copyright (c) 2026 GrooveXlabs.
