"""
MITRE ATT&CK Technique Mapper.
Maps detected attack indicators to MITRE ATT&CK technique IDs, tactics, and descriptions.
100% offline — zero data exfiltration by design.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass(frozen=True)
class MitreTechnique:
    technique_id: str
    name: str
    tactic: str
    description: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    data_sources: List[str] = field(default_factory=list)


# Curated subset of ATT&CK Enterprise v15 techniques for incident triage
MITRE_KNOWLEDGE_BASE: Dict[str, MitreTechnique] = {
    "T1110": MitreTechnique(
        technique_id="T1110",
        name="Brute Force",
        tactic="Credential Access",
        description="Adversary attempts to gain access by systematically guessing passwords or credentials.",
        severity="HIGH",
        data_sources=["Authentication logs", "Account lockout events"],
    ),
    "T1110.001": MitreTechnique(
        technique_id="T1110.001",
        name="Brute Force: Password Guessing",
        tactic="Credential Access",
        description="Adversary guesses passwords for user accounts without prior knowledge of credentials.",
        severity="HIGH",
        data_sources=["Authentication logs", "Failed login counters"],
    ),
    "T1078": MitreTechnique(
        technique_id="T1078",
        name="Valid Accounts",
        tactic="Persistence / Privilege Escalation",
        description="Adversary uses legitimate credentials to access systems, bypassing access controls.",
        severity="CRITICAL",
        data_sources=["Authentication logs", "Account usage anomalies"],
    ),
    "T1059": MitreTechnique(
        technique_id="T1059",
        name="Command and Scripting Interpreter",
        tactic="Execution",
        description="Adversary abuses command-line interpreters to execute commands or scripts.",
        severity="HIGH",
        data_sources=["Process logs", "Command-line audit logs"],
    ),
    "T1059.001": MitreTechnique(
        technique_id="T1059.001",
        name="Command and Scripting Interpreter: PowerShell",
        tactic="Execution",
        description="Adversary uses PowerShell for execution of commands and scripts.",
        severity="HIGH",
        data_sources=["PowerShell logs", "ScriptBlock logging"],
    ),
    "T1021.001": MitreTechnique(
        technique_id="T1021.001",
        name="Remote Services: Remote Desktop Protocol",
        tactic="Lateral Movement",
        description="Adversary uses RDP to pivot across the internal network.",
        severity="HIGH",
        data_sources=["RDP connection logs", "Network flow data"],
    ),
    "T1048": MitreTechnique(
        technique_id="T1048",
        name="Exfiltration Over Alternative Protocol",
        tactic="Exfiltration",
        description="Adversary exfiltrates data using a protocol different from the C2 channel.",
        severity="CRITICAL",
        data_sources=["Network traffic", "DNS query logs"],
    ),
    "T1486": MitreTechnique(
        technique_id="T1486",
        name="Data Encrypted for Impact",
        tactic="Impact",
        description="Adversary encrypts victim data to disrupt availability (ransomware).",
        severity="CRITICAL",
        data_sources=["File monitoring", "Process execution logs"],
    ),
    "T1190": MitreTechnique(
        technique_id="T1190",
        name="Exploit Public-Facing Application",
        tactic="Initial Access",
        description="Adversary exploits a vulnerability in an internet-facing application.",
        severity="CRITICAL",
        data_sources=["Application logs", "WAF logs", "Network traffic"],
    ),
    "T1566": MitreTechnique(
        technique_id="T1566",
        name="Phishing",
        tactic="Initial Access",
        description="Adversary sends targeted messages to gain access to victim systems.",
        severity="HIGH",
        data_sources=["Email gateway logs", "URL filtering logs"],
    ),
    "T1566.001": MitreTechnique(
        technique_id="T1566.001",
        name="Phishing: Spearphishing Attachment",
        tactic="Initial Access",
        description="Adversary sends targeted emails with malicious attachments.",
        severity="HIGH",
        data_sources=["Email logs", "Endpoint detection"],
    ),
    "T1098": MitreTechnique(
        technique_id="T1098",
        name="Account Manipulation",
        tactic="Persistence",
        description="Adversary manipulates accounts to maintain access to systems.",
        severity="HIGH",
        data_sources=["User account audit logs", "IAM change logs"],
    ),
    "T1070": MitreTechnique(
        technique_id="T1070",
        name="Indicator Removal",
        tactic="Defense Evasion",
        description="Adversary deletes or modifies artifacts to hide evidence of intrusion.",
        severity="HIGH",
        data_sources=["System logs", "File integrity monitoring"],
    ),
    "T1053": MitreTechnique(
        technique_id="T1053",
        name="Scheduled Task/Job",
        tactic="Persistence / Execution",
        description="Adversary schedules tasks for persistent execution of malicious code.",
        severity="MEDIUM",
        data_sources=["Scheduled task logs", "Cron logs"],
    ),
    "T1071": MitreTechnique(
        technique_id="T1071",
        name="Application Layer Protocol",
        tactic="Command and Control",
        description="Adversary uses standard application layer protocols (HTTP, DNS) for C2.",
        severity="MEDIUM",
        data_sources=["Network traffic", "Proxy logs"],
    ),
    "T1547.001": MitreTechnique(
        technique_id="T1547.001",
        name="Boot or Logon Autostart Execution: Registry Run Keys",
        tactic="Persistence",
        description="Adversary configures registry run keys to execute malware at boot/logon.",
        severity="HIGH",
        data_sources=["Registry audit logs", "Endpoint telemetry"],
    ),
    "T1105": MitreTechnique(
        technique_id="T1105",
        name="Ingress Tool Transfer",
        tactic="Command and Control",
        description="Adversary transfers tools or files from an external system into the network.",
        severity="MEDIUM",
        data_sources=["Network traffic", "File creation logs"],
    ),
    "T1027": MitreTechnique(
        technique_id="T1027",
        name="Obfuscated Files or Information",
        tactic="Defense Evasion",
        description="Adversary uses encoding, encryption, or packing to hide malicious content.",
        severity="MEDIUM",
        data_sources=["File analysis", "Process monitoring"],
    ),
}


class MitreMapper:
    """Maps raw log indicators to MITRE ATT&CK technique entries."""

    def __init__(self) -> None:
        self.kb = MITRE_KNOWLEDGE_BASE

    def lookup(self, technique_id: str) -> Optional[MitreTechnique]:
        return self.kb.get(technique_id)

    def search_by_tactic(self, tactic: str) -> List[MitreTechnique]:
        tactic_lower = tactic.lower()
        return [t for t in self.kb.values() if tactic_lower in t.tactic.lower()]

    def search_by_keyword(self, keyword: str) -> List[MitreTechnique]:
        kw = keyword.lower()
        return [
            t for t in self.kb.values()
            if kw in t.name.lower() or kw in t.description.lower()
        ]

    def all_techniques(self) -> List[MitreTechnique]:
        return list(self.kb.values())
