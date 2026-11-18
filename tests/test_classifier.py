"""
Unit tests for Incident Classifier.
"""

import pytest
from certin_sentinel.core.classifier import (
    DPDPClassification,
    IncidentCategory,
    IncidentClassifier,
    SeverityLevel,
)


def test_ransomware_classification():
    classifier = IncidentClassifier()
    incident = classifier.classify(
        incident_id="INC-TEST001",
        title="Ransomware attack on file servers",
        summary="All shared drives have been encrypted. Ransom note demands 2 BTC.",
        affected_systems=["fileserver-01", "fileserver-02"],
    )
    assert incident.category == IncidentCategory.RANSOMWARE
    assert incident.severity == SeverityLevel.CRITICAL
    assert len(incident.recommended_actions) > 3


def test_data_breach_with_dpdp():
    classifier = IncidentClassifier()
    incident = classifier.classify(
        incident_id="INC-TEST002",
        title="Data breach exposing customer personal data",
        summary="PII of 50,000 customers including Aadhaar numbers leaked via misconfigured S3.",
        affected_systems=["s3-data-lake"],
    )
    assert incident.category == IncidentCategory.DATA_BREACH
    assert incident.dpdp_classification == DPDPClassification.SIGNIFICANT_DATA_BREACH


def test_brute_force_classification():
    classifier = IncidentClassifier()
    incident = classifier.classify(
        incident_id="INC-TEST003",
        title="Brute force login attempts on VPN gateway",
        summary="Multiple failed login attempts from external IP targeting admin accounts.",
        affected_systems=["vpn-gateway-01"],
    )
    assert incident.category == IncidentCategory.UNAUTHORISED_ACCESS
    assert incident.severity == SeverityLevel.HIGH


def test_phishing_classification():
    classifier = IncidentClassifier()
    incident = classifier.classify(
        incident_id="INC-TEST004",
        title="Spearphishing campaign targeting HR department",
        summary="Phishing emails with malicious attachments sent to 15 HR employees.",
        affected_systems=["email-gateway"],
    )
    assert incident.category == IncidentCategory.IDENTITY_THEFT_PHISHING
    assert incident.severity == SeverityLevel.HIGH


def test_reporting_deadline_is_6_hours():
    classifier = IncidentClassifier()
    incident = classifier.classify(
        incident_id="INC-DL",
        title="Port scanning detected",
        summary="Automated nmap scanning from external IP.",
        affected_systems=["perimeter-fw"],
    )
    assert incident.reporting_deadline_hours == 6
