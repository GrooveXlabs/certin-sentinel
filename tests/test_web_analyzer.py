"""
Unit tests for Web Log Analyzer.
"""

import pytest
from certin_sentinel.analyzers.web import WebLogAnalyzer


SAMPLE_WEB_LOG = [
    '203.0.113.10 - - [15/Nov/2026:04:12:01 +0530] "GET /products.php?id=1%20UNION%20SELECT%20username,password%20FROM%20users HTTP/1.1" 200 4521',
    '203.0.113.10 - - [15/Nov/2026:04:12:05 +0530] "GET /login.php?user=\' OR 1=1-- HTTP/1.1" 200 1250',
    '198.51.100.25 - - [15/Nov/2026:04:15:10 +0530] "GET /../../../../etc/passwd HTTP/1.1" 403 280',
    '198.51.100.25 - - [15/Nov/2026:04:15:12 +0530] "GET /download?file=..%2f..%2fconfig.php HTTP/1.1" 403 280',
    '192.0.2.80 - - [15/Nov/2026:05:01:00 +0530] "POST /uploads/shell.php?cmd=whoami HTTP/1.1" 200 15',
    '192.0.2.80 - - [15/Nov/2026:05:01:05 +0530] "POST /uploads/shell.php?cmd=cat%20/etc/shadow HTTP/1.1" 200 1024',
]


def test_detects_sql_injection():
    analyzer = WebLogAnalyzer()
    findings = analyzer.analyze(SAMPLE_WEB_LOG)
    sqli_findings = [f for f in findings if f.finding_type == "SQL_INJECTION_ATTEMPT"]
    assert len(sqli_findings) == 1
    assert sqli_findings[0].source_ip == "203.0.113.10"
    assert sqli_findings[0].count == 2
    assert sqli_findings[0].severity == "CRITICAL"
    assert any(t.technique_id == "T1190" for t in sqli_findings[0].matched_techniques)


def test_detects_path_traversal():
    analyzer = WebLogAnalyzer()
    findings = analyzer.analyze(SAMPLE_WEB_LOG)
    trav_findings = [f for f in findings if f.finding_type == "PATH_TRAVERSAL_ATTEMPT"]
    assert len(trav_findings) == 1
    assert trav_findings[0].source_ip == "198.51.100.25"
    assert trav_findings[0].count == 2
    assert trav_findings[0].severity == "HIGH"


def test_detects_webshell():
    analyzer = WebLogAnalyzer()
    findings = analyzer.analyze(SAMPLE_WEB_LOG)
    shell_findings = [f for f in findings if f.finding_type == "WEBSHELL_DETECTED"]
    assert len(shell_findings) == 1
    assert shell_findings[0].count == 2
    assert shell_findings[0].severity == "CRITICAL"
