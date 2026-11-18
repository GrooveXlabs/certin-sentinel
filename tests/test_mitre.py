"""
Unit tests for MITRE ATT&CK Mapper.
"""

import pytest
from certin_sentinel.core.mitre import MitreMapper


def test_lookup_existing_technique():
    mapper = MitreMapper()
    tech = mapper.lookup("T1110")
    assert tech is not None
    assert tech.name == "Brute Force"
    assert tech.tactic == "Credential Access"


def test_lookup_nonexistent_returns_none():
    mapper = MitreMapper()
    assert mapper.lookup("T9999") is None


def test_search_by_tactic():
    mapper = MitreMapper()
    results = mapper.search_by_tactic("Initial Access")
    assert len(results) >= 2
    assert any(t.technique_id == "T1190" for t in results)


def test_search_by_keyword():
    mapper = MitreMapper()
    results = mapper.search_by_keyword("ransomware")
    # T1486 description mentions ransomware
    assert any(t.technique_id == "T1486" for t in results)


def test_all_techniques_populated():
    mapper = MitreMapper()
    all_tech = mapper.all_techniques()
    assert len(all_tech) >= 15
