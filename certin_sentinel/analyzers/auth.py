"""
Auth Log Analyzer.
Parses syslog-style auth.log, Windows Security Event Log exports (CSV), and SSH logs.
Detects brute force attacks, privilege escalation, and suspicious account activity.
"""

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from certin_sentinel.core.mitre import MitreMapper, MitreTechnique


@dataclass
class AuthFinding:
    finding_type: str
    severity: str
    source_ip: Optional[str]
    username: Optional[str]
    count: int
    summary: str
    matched_techniques: List[MitreTechnique] = field(default_factory=list)
    raw_lines: List[str] = field(default_factory=list)


class AuthLogAnalyzer:
    """Deterministic pattern analysis engine for authentication logs."""

    # Failed SSH login pattern (OpenSSH syslog format)
    RE_SSH_FAIL = re.compile(
        r"Failed (?:password|publickey) for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)"
    )
    # Successful SSH login
    RE_SSH_OK = re.compile(
        r"Accepted (?:password|publickey) for (\S+) from (\d+\.\d+\.\d+\.\d+)"
    )
    # sudo / su privilege escalation
    RE_SUDO = re.compile(
        r"sudo:\s+(\S+)\s+:.*COMMAND=(.*)", re.IGNORECASE
    )
    # Account created
    RE_USERADD = re.compile(
        r"useradd.*new user: name=([a-zA-Z0-9_-]+)", re.IGNORECASE
    )
    # Windows-style failed logon (CSV export with EventID 4625)
    RE_WIN_FAIL = re.compile(
        r"4625.*Account Name:\s*(\S+).*Source Network Address:\s*(\d+\.\d+\.\d+\.\d+)", re.IGNORECASE
    )

    def __init__(self, brute_force_threshold: int = 5):
        self.brute_force_threshold = brute_force_threshold
        self.mapper = MitreMapper()

    def analyze(self, log_lines: List[str]) -> List[AuthFinding]:
        findings: List[AuthFinding] = []
        failed_by_ip: Dict[str, List[str]] = {}
        failed_by_user: Dict[str, int] = {}
        sudo_commands: List[tuple[str, str]] = []
        new_users: List[str] = []

        for line in log_lines:
            # SSH brute force detection
            m_fail = self.RE_SSH_FAIL.search(line)
            if m_fail:
                user, ip = m_fail.group(1), m_fail.group(2)
                failed_by_ip.setdefault(ip, []).append(line)
                failed_by_user[user] = failed_by_user.get(user, 0) + 1
                continue

            # Windows failed logon
            m_win = self.RE_WIN_FAIL.search(line)
            if m_win:
                user, ip = m_win.group(1), m_win.group(2)
                failed_by_ip.setdefault(ip, []).append(line)
                failed_by_user[user] = failed_by_user.get(user, 0) + 1
                continue

            # Privilege escalation via sudo
            m_sudo = self.RE_SUDO.search(line)
            if m_sudo:
                sudo_commands.append((m_sudo.group(1), m_sudo.group(2).strip()))
                continue

            # Account creation
            m_add = self.RE_USERADD.search(line)
            if m_add:
                new_users.append(m_add.group(1))
                continue

        # Generate brute force findings
        for ip, lines in failed_by_ip.items():
            if len(lines) >= self.brute_force_threshold:
                techniques = []
                t1110 = self.mapper.lookup("T1110")
                if t1110:
                    techniques.append(t1110)
                t1110_001 = self.mapper.lookup("T1110.001")
                if t1110_001:
                    techniques.append(t1110_001)

                findings.append(AuthFinding(
                    finding_type="BRUTE_FORCE_ATTACK",
                    severity="HIGH",
                    source_ip=ip,
                    username=None,
                    count=len(lines),
                    summary=f"Brute force attack detected from {ip}: {len(lines)} failed login attempts",
                    matched_techniques=techniques,
                    raw_lines=lines[:10],
                ))

        # Generate suspicious sudo findings
        for user, cmd in sudo_commands:
            dangerous_patterns = ["rm -rf", "chmod 777", "passwd", "useradd", "visudo", "shadow"]
            if any(p in cmd.lower() for p in dangerous_patterns):
                techniques = []
                t1059 = self.mapper.lookup("T1059")
                if t1059:
                    techniques.append(t1059)

                findings.append(AuthFinding(
                    finding_type="SUSPICIOUS_PRIVILEGE_ESCALATION",
                    severity="HIGH",
                    source_ip=None,
                    username=user,
                    count=1,
                    summary=f"Suspicious sudo command by '{user}': {cmd[:80]}",
                    matched_techniques=techniques,
                ))

        # Generate account creation findings
        for user in new_users:
            techniques = []
            t1098 = self.mapper.lookup("T1098")
            if t1098:
                techniques.append(t1098)

            findings.append(AuthFinding(
                finding_type="SUSPICIOUS_ACCOUNT_CREATION",
                severity="MEDIUM",
                source_ip=None,
                username=user,
                count=1,
                summary=f"New user account created: {user}",
                matched_techniques=techniques,
            ))

        return findings
