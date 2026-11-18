"""
Incident Classification & Severity Engine.
Maps raw security events into structured CERT-In incident categories
per CERT-In Incident Reporting Guidelines (2022/2024).
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional
from certin_sentinel.core.mitre import MitreTechnique


class IncidentCategory(str, Enum):
    TARGETED_SCANNING = "Targeted scanning/probing of critical networks"
    COMPROMISE_OF_CRITICAL_SYSTEM = "Compromise of critical systems/information"
    UNAUTHORISED_ACCESS = "Unauthorised access of IT systems/data"
    WEBSITE_DEFACEMENT = "Defacement of website or intrusion into website"
    MALICIOUS_CODE_ATTACK = "Malicious code attacks (virus, worm, Trojan, bots, spyware)"
    ATTACK_ON_SERVERS = "Attack on servers (database, mail, DNS) and routers"
    IDENTITY_THEFT_PHISHING = "Identity theft, spoofing and phishing attacks"
    DENIAL_OF_SERVICE = "Denial of Service (DoS) and Distributed DoS attacks"
    ATTACK_ON_CRITICAL_INFRA = "Attacks on critical infrastructure (power, transport, finance)"
    DATA_BREACH = "Data breach / leak of personal or sensitive information"
    RANSOMWARE = "Ransomware attack on systems or networks"
    FAKE_MOBILE_APPS = "Attacks related to fake mobile apps"


class SeverityLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class DPDPClassification(str, Enum):
    NOT_APPLICABLE = "NOT_APPLICABLE"
    PERSONAL_DATA_BREACH = "PERSONAL_DATA_BREACH"
    SIGNIFICANT_DATA_BREACH = "SIGNIFICANT_DATA_BREACH"


@dataclass
class TriagedIncident:
    incident_id: str
    title: str
    summary: str
    category: IncidentCategory
    severity: SeverityLevel
    dpdp_classification: DPDPClassification
    affected_systems: List[str]
    indicators_of_compromise: List[str] = field(default_factory=list)
    mapped_techniques: List[MitreTechnique] = field(default_factory=list)
    recommended_actions: List[str] = field(default_factory=list)
    reporting_deadline_hours: int = 6
    evidence_hashes: List[str] = field(default_factory=list)
    raw_findings: List[Dict[str, Any]] = field(default_factory=list)


class IncidentClassifier:
    """Classifies raw findings into structured CERT-In incident categories."""

    # Keyword → (Category, base severity)
    CLASSIFICATION_RULES: List[tuple[List[str], IncidentCategory, SeverityLevel]] = [
        (
            ["ransomware", "encrypted for impact", "ransom note", "bitcoin", ".locked", ".encrypted"],
            IncidentCategory.RANSOMWARE,
            SeverityLevel.CRITICAL,
        ),
        (
            ["data breach", "data leak", "pii exposed", "customer data", "personal data"],
            IncidentCategory.DATA_BREACH,
            SeverityLevel.CRITICAL,
        ),
        (
            ["phishing", "spearphishing", "credential harvesting", "spoofing"],
            IncidentCategory.IDENTITY_THEFT_PHISHING,
            SeverityLevel.HIGH,
        ),
        (
            ["ddos", "denial of service", "dos attack", "syn flood", "amplification"],
            IncidentCategory.DENIAL_OF_SERVICE,
            SeverityLevel.HIGH,
        ),
        (
            ["defacement", "web shell", "index.html replaced", "defaced"],
            IncidentCategory.WEBSITE_DEFACEMENT,
            SeverityLevel.HIGH,
        ),
        (
            ["brute force", "password guess", "failed login", "account lockout"],
            IncidentCategory.UNAUTHORISED_ACCESS,
            SeverityLevel.HIGH,
        ),
        (
            ["malware", "trojan", "worm", "botnet", "spyware", "rat", "backdoor"],
            IncidentCategory.MALICIOUS_CODE_ATTACK,
            SeverityLevel.HIGH,
        ),
        (
            ["exploit", "vulnerability", "cve-", "rce", "remote code execution"],
            IncidentCategory.COMPROMISE_OF_CRITICAL_SYSTEM,
            SeverityLevel.CRITICAL,
        ),
        (
            ["lateral movement", "rdp", "ssh brute", "pivoting"],
            IncidentCategory.ATTACK_ON_SERVERS,
            SeverityLevel.HIGH,
        ),
        (
            ["port scan", "nmap", "recon", "enumeration", "scanning"],
            IncidentCategory.TARGETED_SCANNING,
            SeverityLevel.MEDIUM,
        ),
        (
            ["power grid", "scada", "ics", "plc", "transport", "banking"],
            IncidentCategory.ATTACK_ON_CRITICAL_INFRA,
            SeverityLevel.CRITICAL,
        ),
    ]

    def classify(
        self,
        incident_id: str,
        title: str,
        summary: str,
        affected_systems: List[str],
        iocs: Optional[List[str]] = None,
        techniques: Optional[List[MitreTechnique]] = None,
        raw_findings: Optional[List[Dict[str, Any]]] = None,
    ) -> TriagedIncident:
        combined_text = f"{title} {summary}".lower()

        # Match category
        matched_category = IncidentCategory.COMPROMISE_OF_CRITICAL_SYSTEM
        matched_severity = SeverityLevel.MEDIUM

        for keywords, category, severity in self.CLASSIFICATION_RULES:
            if any(kw in combined_text for kw in keywords):
                matched_category = category
                matched_severity = severity
                break

        # Escalate severity based on MITRE technique severity
        if techniques:
            for tech in techniques:
                if tech.severity == "CRITICAL":
                    matched_severity = SeverityLevel.CRITICAL
                    break

        # DPDP classification
        dpdp = DPDPClassification.NOT_APPLICABLE
        pii_keywords = ["personal data", "pii", "customer", "aadhaar", "pan card", "mobile number", "email address"]
        if any(kw in combined_text for kw in pii_keywords):
            dpdp = DPDPClassification.PERSONAL_DATA_BREACH
            if matched_severity == SeverityLevel.CRITICAL:
                dpdp = DPDPClassification.SIGNIFICANT_DATA_BREACH

        # Generate recommended actions
        actions = self._generate_actions(matched_category, matched_severity)

        return TriagedIncident(
            incident_id=incident_id,
            title=title,
            summary=summary,
            category=matched_category,
            severity=matched_severity,
            dpdp_classification=dpdp,
            affected_systems=affected_systems,
            indicators_of_compromise=iocs or [],
            mapped_techniques=techniques or [],
            recommended_actions=actions,
            reporting_deadline_hours=6,
            raw_findings=raw_findings or [],
        )

    def _generate_actions(self, category: IncidentCategory, severity: SeverityLevel) -> List[str]:
        base_actions = [
            "Isolate affected systems from the network immediately",
            "Preserve forensic evidence (memory dumps, disk images, log snapshots)",
            "File CERT-In incident report within 6-hour mandatory window",
        ]

        category_actions = {
            IncidentCategory.RANSOMWARE: [
                "Do NOT pay the ransom — engage law enforcement and CERT-In",
                "Identify ransomware variant and check for available decryption tools",
                "Restore systems from verified clean offline backups",
                "Conduct full Active Directory credential reset",
            ],
            IncidentCategory.DATA_BREACH: [
                "Identify scope of data exposure (record count, data categories)",
                "Notify Data Protection Board of India per DPDP Act Section 8",
                "Notify affected data principals without unreasonable delay",
                "Engage forensic investigators for root cause analysis",
            ],
            IncidentCategory.IDENTITY_THEFT_PHISHING: [
                "Block sender domains/IPs at email gateway",
                "Force password reset for all potentially compromised accounts",
                "Report phishing URLs to CERT-In and browser safe-browsing lists",
            ],
            IncidentCategory.DENIAL_OF_SERVICE: [
                "Enable DDoS mitigation (rate limiting, geo-blocking, CDN scrubbing)",
                "Contact upstream ISP for traffic filtering",
                "Document attack vectors and amplification sources",
            ],
            IncidentCategory.UNAUTHORISED_ACCESS: [
                "Revoke all sessions and rotate all credentials for affected accounts",
                "Audit access logs for lateral movement indicators",
                "Review IAM policies and enforce MFA across all privileged accounts",
            ],
        }

        specific = category_actions.get(category, [
            "Conduct thorough investigation of attack vector and timeline",
            "Review and harden security controls for affected assets",
        ])

        return base_actions + specific
