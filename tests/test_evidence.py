"""
Unit tests for Evidence Hasher and Chain-of-Custody.
"""

import os
import pytest
from certin_sentinel.core.evidence import EvidenceHasher


def test_hash_text():
    text = "CERT-In incident evidence sample"
    hash_val = EvidenceHasher.hash_text(text)
    assert len(hash_val) == 64
    assert hash_val == EvidenceHasher.hash_text(text)


def test_hash_file_and_verification(tmp_path):
    test_file = tmp_path / "syslog.log"
    content = b"Critical security alert: unauthorized root logon\n"
    test_file.write_bytes(content)

    record = EvidenceHasher.hash_file(str(test_file), analyst_note="Primary server syslog")
    assert record.file_size_bytes == len(content)
    assert len(record.sha256_hash) == 64
    assert record.analyst_note == "Primary server syslog"

    # Verify integrity
    is_valid, msg = EvidenceHasher.verify_file(str(test_file), record.sha256_hash)
    assert is_valid
    assert "verified" in msg.lower()

    # Tamper with file
    test_file.write_bytes(b"Tampered log content\n")
    is_valid_tampered, tamper_msg = EvidenceHasher.verify_file(str(test_file), record.sha256_hash)
    assert not is_valid_tampered
    assert "TAMPERING DETECTED" in tamper_msg
