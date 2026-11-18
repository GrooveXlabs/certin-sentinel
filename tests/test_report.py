"""
Unit tests for CERT-In Report Generator.
"""

import pytest
from certin_sentinel.core.classifier import IncidentClassifier
from certin_sentinel.reporters.certin_report import CertInReportGenerator


def test_report_generation():
    classifier = IncidentClassifier()
    incident = classifier.classify(
        incident_id="INC-RPT-001",
        title="Ransomware detection on payment cluster",
        summary="Payment cluster database encrypted by LockBit variant. 2 BTC demanded.",
        affected_systems=["pay-node-01", "pay-db-primary"],
        iocs=["198.51.100.99", "lockbit_sample.exe"],
    )

    reporter = CertInReportGenerator()
    markdown = reporter.generate(incident, organization_name="GrooveXlabs")

    assert "# 🚨 CERT-In Incident Report" in markdown
    assert "INC-RPT-001" in markdown
    assert "pay-node-01" in markdown
    assert "198.51.100.99" in markdown
    assert "6 hours from detection" in markdown
    assert "GrooveXlabs" in markdown
