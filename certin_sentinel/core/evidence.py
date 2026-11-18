"""
Evidence Hashing & Chain-of-Custody Engine.
Integrates with GrooveXlabs forenchain methodology for forensic-grade evidence integrity.
"""

import hashlib
import os
import time
from dataclasses import dataclass
from typing import List, Optional, Tuple


@dataclass(frozen=True)
class EvidenceRecord:
    filepath: str
    sha256_hash: str
    file_size_bytes: int
    hash_timestamp: str
    analyst_note: Optional[str] = None


class EvidenceHasher:
    """Hash evidence files for chain-of-custody immutability."""

    @staticmethod
    def hash_file(filepath: str, analyst_note: Optional[str] = None) -> EvidenceRecord:
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Evidence file not found: {filepath}")

        sha256 = hashlib.sha256()
        file_size = 0
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256.update(chunk)
                file_size += len(chunk)

        return EvidenceRecord(
            filepath=os.path.abspath(filepath),
            sha256_hash=sha256.hexdigest(),
            file_size_bytes=file_size,
            hash_timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            analyst_note=analyst_note,
        )

    @staticmethod
    def hash_text(text: str) -> str:
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    @staticmethod
    def verify_file(filepath: str, expected_hash: str) -> Tuple[bool, str]:
        if not os.path.exists(filepath):
            return False, f"File not found: {filepath}"

        sha256 = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256.update(chunk)

        actual_hash = sha256.hexdigest()
        if actual_hash == expected_hash:
            return True, "Evidence integrity verified — hash matches"
        else:
            return False, f"TAMPERING DETECTED — expected {expected_hash[:16]}..., got {actual_hash[:16]}..."
