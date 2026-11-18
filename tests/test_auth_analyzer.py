"""
Unit tests for Auth Log Analyzer.
"""

import pytest
from certin_sentinel.analyzers.auth import AuthLogAnalyzer


SAMPLE_AUTH_LOG = [
    "Nov 15 03:12:01 server01 sshd[12345]: Failed password for invalid user admin from 203.0.113.50 port 44112 ssh2",
    "Nov 15 03:12:03 server01 sshd[12346]: Failed password for invalid user admin from 203.0.113.50 port 44113 ssh2",
    "Nov 15 03:12:05 server01 sshd[12347]: Failed password for invalid user root from 203.0.113.50 port 44114 ssh2",
    "Nov 15 03:12:07 server01 sshd[12348]: Failed password for invalid user root from 203.0.113.50 port 44115 ssh2",
    "Nov 15 03:12:09 server01 sshd[12349]: Failed password for invalid user root from 203.0.113.50 port 44116 ssh2",
    "Nov 15 03:12:11 server01 sshd[12350]: Failed password for invalid user test from 203.0.113.50 port 44117 ssh2",
    "Nov 15 03:15:00 server01 sshd[12351]: Accepted password for deploy from 10.0.1.5 port 50443 ssh2",
    "Nov 15 04:01:00 server01 sudo: attacker : TTY=pts/0 ; PWD=/home ; USER=root ; COMMAND=rm -rf /var/log/*",
    "Nov 15 04:05:00 server01 useradd[12400]: new user: name=backdoor_user, UID=1050",
]


def test_detects_brute_force_from_single_ip():
    analyzer = AuthLogAnalyzer(brute_force_threshold=5)
    findings = analyzer.analyze(SAMPLE_AUTH_LOG)
    brute_force = [f for f in findings if f.finding_type == "BRUTE_FORCE_ATTACK"]
    assert len(brute_force) == 1
    assert brute_force[0].source_ip == "203.0.113.50"
    assert brute_force[0].count >= 5
    assert any(t.technique_id == "T1110" for t in brute_force[0].matched_techniques)


def test_detects_suspicious_sudo():
    analyzer = AuthLogAnalyzer()
    findings = analyzer.analyze(SAMPLE_AUTH_LOG)
    sudo_findings = [f for f in findings if f.finding_type == "SUSPICIOUS_PRIVILEGE_ESCALATION"]
    assert len(sudo_findings) == 1
    assert "rm -rf" in sudo_findings[0].summary


def test_detects_account_creation():
    analyzer = AuthLogAnalyzer()
    findings = analyzer.analyze(SAMPLE_AUTH_LOG)
    acct_findings = [f for f in findings if f.finding_type == "SUSPICIOUS_ACCOUNT_CREATION"]
    assert len(acct_findings) == 1
    assert acct_findings[0].username == "backdoor_user"
