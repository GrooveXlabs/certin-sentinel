# CERT-In Sentinel: Technical Standard Operating Procedure (SOP)

## 1. Scope & Objective
This SOP defines the rapid incident triage, evidence preservation, and mandatory 6-hour regulatory disclosure process under CERT-In Directions 2022 and the DPDP Act 2023 using CERT-In Sentinel.

---

## 2. The 6-Hour Emergency Timeline

```
T+0:00 ── Incident Detected
T+0:15 ── Step 1: Snapshot and Hash Evidence Logs (EvidenceHasher)
T+0:30 ── Step 2: Run Automated Analyzers (Auth & Web Analyzers)
T+1:00 ── Step 3: Classify Incident & Map MITRE ATT&CK
T+2:00 ── Step 4: Generate CERT-In Disclosure Report
T+3:00 ── Step 5: Executive Review & Legal Counsel Signoff
T+5:00 ── Step 6: Dispatch Report to incident@cert-in.org.in
T+6:00 ── MANDATORY DEADLINE EXPIRES
```

---

## 3. Step-by-Step Incident Execution

### Step 1: Evidence Preservation (Chain-of-Custody)
Before parsing or altering any logs, freeze and hash the raw artifacts:
```bash
sentinel hash-evidence /var/log/auth.log --note "Perimeter bastion auth.log snapshot"
sentinel hash-evidence /var/log/nginx/access.log --note "Web access log snapshot"
```

### Step 2: Automated Analysis
Run the log analyzers to extract IOCs and attack patterns:
```bash
sentinel analyze-auth /var/log/auth.log --threshold 5 --output /tmp/auth_findings.md
sentinel analyze-web /var/log/nginx/access.log --output /tmp/web_findings.md
```

### Step 3: Triage & Report Generation
Execute manual or automated triage to compile the final CERT-In report:
```bash
sentinel triage \
  --title "SQL Injection & Unauthorized DB Access" \
  --summary "SQL injection exploited on checkout API resulting in customer record exfiltration" \
  --systems "prod-api-01,prod-db-primary" \
  --iocs "203.0.113.10,attacker-c2.net" \
  --org "GrooveXlabs" \
  --output certin_incident_report.md
```

### Step 4: Submission & Legal Tracking
1. Review `certin_incident_report.md`.
2. Submit via CERT-In portal ([https://www.cert-in.org.in/](https://www.cert-in.org.in/)) or email `incident@cert-in.org.in`.
3. If personal data was compromised, archive the report for Data Protection Board notification within 72 hours.
