"""
Web / Application Log Analyzer.
Parses Apache, Nginx, and generic application logs to detect web attacks.
"""

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import unquote
from certin_sentinel.core.mitre import MitreMapper, MitreTechnique


@dataclass
class WebFinding:
    finding_type: str
    severity: str
    source_ip: Optional[str]
    target_path: Optional[str]
    count: int
    summary: str
    matched_techniques: List[MitreTechnique] = field(default_factory=list)
    raw_lines: List[str] = field(default_factory=list)


class WebLogAnalyzer:
    """Deterministic pattern analysis engine for web server and application logs."""

    # Common Log Format IP extraction
    RE_CLF_IP = re.compile(r"^(\d+\.\d+\.\d+\.\d+)")

    # SQL injection indicators
    SQL_INJECTION_PATTERNS = [
        re.compile(r"(?:UNION\s+SELECT|OR\s+1\s*=\s*1|'\s*OR\s*'|;\s*DROP\s+TABLE|SLEEP\s*\(|BENCHMARK\s*\()", re.IGNORECASE),
    ]

    # Path traversal
    PATH_TRAVERSAL_PATTERNS = [
        re.compile(r"(?:\.\./|\.\.\\|%2e%2e|%252e%252e)", re.IGNORECASE),
    ]

    # Web shell indicators
    WEBSHELL_PATTERNS = [
        re.compile(r"(?:cmd=|exec=|system\(|passthru\(|shell_exec|eval\(base64)", re.IGNORECASE),
    ]

    # Scanner / enumeration patterns
    SCANNER_PATHS = [
        re.compile(r"(?:wp-login|xmlrpc\.php|/admin|/phpmyadmin|/.env|/config\.php|/.git/HEAD|/actuator|/swagger)", re.IGNORECASE),
    ]

    def __init__(self, scan_threshold: int = 20):
        self.scan_threshold = scan_threshold
        self.mapper = MitreMapper()

    def analyze(self, log_lines: List[str]) -> List[WebFinding]:
        findings: List[WebFinding] = []
        sqli_hits: Dict[str, List[str]] = {}
        traversal_hits: Dict[str, List[str]] = {}
        webshell_hits: List[str] = []
        scanner_ips: Dict[str, int] = {}

        for line in log_lines:
            decoded_line = unquote(line)
            ip_match = self.RE_CLF_IP.match(line)
            ip = ip_match.group(1) if ip_match else "unknown"

            # SQL injection
            for pat in self.SQL_INJECTION_PATTERNS:
                if pat.search(decoded_line) or pat.search(line):
                    sqli_hits.setdefault(ip, []).append(line)
                    break

            # Path traversal
            for pat in self.PATH_TRAVERSAL_PATTERNS:
                if pat.search(decoded_line) or pat.search(line):
                    traversal_hits.setdefault(ip, []).append(line)
                    break

            # Web shell
            for pat in self.WEBSHELL_PATTERNS:
                if pat.search(decoded_line) or pat.search(line):
                    webshell_hits.append(line)
                    break

            # Scanner enumeration
            for pat in self.SCANNER_PATHS:
                if pat.search(decoded_line) or pat.search(line):
                    scanner_ips[ip] = scanner_ips.get(ip, 0) + 1
                    break

        # SQL injection findings
        for ip, lines in sqli_hits.items():
            techniques = []
            t1190 = self.mapper.lookup("T1190")
            if t1190:
                techniques.append(t1190)

            findings.append(WebFinding(
                finding_type="SQL_INJECTION_ATTEMPT",
                severity="CRITICAL",
                source_ip=ip,
                target_path=None,
                count=len(lines),
                summary=f"SQL injection attempts from {ip}: {len(lines)} malicious requests",
                matched_techniques=techniques,
                raw_lines=lines[:5],
            ))

        # Path traversal findings
        for ip, lines in traversal_hits.items():
            techniques = []
            t1190 = self.mapper.lookup("T1190")
            if t1190:
                techniques.append(t1190)

            findings.append(WebFinding(
                finding_type="PATH_TRAVERSAL_ATTEMPT",
                severity="HIGH",
                source_ip=ip,
                target_path=None,
                count=len(lines),
                summary=f"Path traversal attack from {ip}: {len(lines)} attempts",
                matched_techniques=techniques,
                raw_lines=lines[:5],
            ))

        # Web shell findings
        if webshell_hits:
            techniques = []
            t1059 = self.mapper.lookup("T1059")
            if t1059:
                techniques.append(t1059)

            findings.append(WebFinding(
                finding_type="WEBSHELL_DETECTED",
                severity="CRITICAL",
                source_ip=None,
                target_path=None,
                count=len(webshell_hits),
                summary=f"Web shell indicators detected in {len(webshell_hits)} log entries",
                matched_techniques=techniques,
                raw_lines=webshell_hits[:5],
            ))

        # Scanner findings
        for ip, count in scanner_ips.items():
            if count >= self.scan_threshold:
                findings.append(WebFinding(
                    finding_type="AUTOMATED_SCANNER",
                    severity="MEDIUM",
                    source_ip=ip,
                    target_path=None,
                    count=count,
                    summary=f"Automated scanner detected from {ip}: {count} enumeration hits",
                ))

        return findings
