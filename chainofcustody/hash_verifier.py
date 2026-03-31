"""
Hash Verification Engine for ChainOfCustody.

Computes and verifies MD5, SHA-1, and SHA-256 hashes for digital evidence files.
Supports streaming computation to handle large forensic images without exhausting RAM.

Author: Edward Marez
License: MIT
"""

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


# Chunk size for streaming hash computation (8 MB)
CHUNK_SIZE = 8 * 1024 * 1024


@dataclass
class HashResult:
    """Container for all forensic hashes of a file."""

    md5: str
    sha1: str
    sha256: str
    file_size: int

    def matches(self, other: "HashResult") -> bool:
        """Return True if all hashes match another HashResult."""
        return (
            self.md5 == other.md5
            and self.sha1 == other.sha1
            and self.sha256 == other.sha256
        )

    def to_dict(self) -> dict:
        return {
            "md5": self.md5,
            "sha1": self.sha1,
            "sha256": self.sha256,
            "file_size": self.file_size,
        }


@dataclass
class VerificationResult:
    """Result of verifying a file against stored acquisition hashes."""

    file_path: str
    is_valid: bool
    current_hashes: HashResult
    stored_md5: Optional[str]
    stored_sha1: Optional[str]
    stored_sha256: Optional[str]
    md5_match: bool
    sha1_match: bool
    sha256_match: bool
    error: Optional[str] = None

    @property
    def all_match(self) -> bool:
        return self.md5_match and self.sha1_match and self.sha256_match

    def integrity_status(self) -> str:
        if self.error:
            return f"ERROR: {self.error}"
        if self.all_match:
            return "VERIFIED - All hashes match"
        mismatches = []
        if not self.md5_match:
            mismatches.append("MD5")
        if not self.sha1_match:
            mismatches.append("SHA-1")
        if not self.sha256_match:
            mismatches.append("SHA-256")
        return f"INTEGRITY VIOLATION - Hash mismatch: {', '.join(mismatches)}"

    def to_dict(self) -> dict:
        return {
            "file_path": self.file_path,
            "is_valid": self.is_valid,
            "current_hashes": self.current_hashes.to_dict(),
            "stored_md5": self.stored_md5,
            "stored_sha1": self.stored_sha1,
            "stored_sha256": self.stored_sha256,
            "md5_match": self.md5_match,
            "sha1_match": self.sha1_match,
            "sha256_match": self.sha256_match,
            "integrity_status": self.integrity_status(),
        }


def compute_hashes(file_path: str) -> HashResult:
    """
    Compute MD5, SHA-1, and SHA-256 hashes for a file.

    Uses streaming I/O to handle forensic images of arbitrary size without
    loading the entire file into memory.

    Args:
        file_path: Absolute or relative path to the evidence file.

    Returns:
        HashResult containing all three hash digests and the file size.

    Raises:
        FileNotFoundError: If the file does not exist.
        PermissionError: If the file cannot be read.
        IOError: On other I/O errors.
    """
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Evidence file not found: {file_path}")
    if not path.is_file():
        raise ValueError(f"Path is not a regular file: {file_path}")

    md5_hash = hashlib.md5()
    sha1_hash = hashlib.sha1()
    sha256_hash = hashlib.sha256()
    file_size = 0

    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(CHUNK_SIZE)
            if not chunk:
                break
            md5_hash.update(chunk)
            sha1_hash.update(chunk)
            sha256_hash.update(chunk)
            file_size += len(chunk)

    return HashResult(
        md5=md5_hash.hexdigest(),
        sha1=sha1_hash.hexdigest(),
        sha256=sha256_hash.hexdigest(),
        file_size=file_size,
    )


def compute_hashes_from_bytes(data: bytes) -> HashResult:
    """
    Compute MD5, SHA-1, and SHA-256 hashes for raw bytes.

    Useful in tests and for hashing small in-memory evidence items.
    """
    return HashResult(
        md5=hashlib.md5(data).hexdigest(),
        sha1=hashlib.sha1(data).hexdigest(),
        sha256=hashlib.sha256(data).hexdigest(),
        file_size=len(data),
    )


def verify_file_integrity(
    file_path: str,
    stored_md5: Optional[str] = None,
    stored_sha1: Optional[str] = None,
    stored_sha256: Optional[str] = None,
) -> VerificationResult:
    """
    Verify that a file's current hashes match stored acquisition hashes.

    Any hash provided that is None is skipped (treated as matching).
    If no hashes are provided the verification is inconclusive.

    Returns:
        VerificationResult with per-algorithm match flags and overall status.
    """
    try:
        current = compute_hashes(file_path)
    except (FileNotFoundError, PermissionError, ValueError, IOError) as exc:
        # Create a placeholder HashResult for the error case
        placeholder = HashResult(md5="", sha1="", sha256="", file_size=0)
        return VerificationResult(
            file_path=file_path,
            is_valid=False,
            current_hashes=placeholder,
            stored_md5=stored_md5,
            stored_sha1=stored_sha1,
            stored_sha256=stored_sha256,
            md5_match=False,
            sha1_match=False,
            sha256_match=False,
            error=str(exc),
        )

    md5_match = (stored_md5 is None) or (current.md5 == stored_md5)
    sha1_match = (stored_sha1 is None) or (current.sha1 == stored_sha1)
    sha256_match = (stored_sha256 is None) or (current.sha256 == stored_sha256)

    is_valid = md5_match and sha1_match and sha256_match

    return VerificationResult(
        file_path=file_path,
        is_valid=is_valid,
        current_hashes=current,
        stored_md5=stored_md5,
        stored_sha1=stored_sha1,
        stored_sha256=stored_sha256,
        md5_match=md5_match,
        sha1_match=sha1_match,
        sha256_match=sha256_match,
    )


def hash_database_file(db_path: str) -> str:
    """
    Compute SHA-256 hash of the SQLite database file itself.

    Used by the integrity checker to detect external tampering of the database.

    Returns:
        Hex-encoded SHA-256 digest, or empty string if the file doesn't exist.
    """
    if not os.path.exists(db_path):
        return ""
    try:
        result = compute_hashes(db_path)
        return result.sha256
    except (IOError, OSError):
        return ""


def generate_event_hash(
    event_id: str,
    evidence_id: str,
    event_type: str,
    timestamp: str,
    from_custodian: Optional[str],
    to_custodian: Optional[str],
    verification_hash: Optional[str],
    previous_event_hash: Optional[str] = None,
) -> str:
    """
    Generate a hash that represents a custody event in a hash chain.

    Each event's hash includes the previous event's hash, creating a
    tamper-evident chain similar to a blockchain.  If the previous_event_hash
    is None (first event) the string "GENESIS" is used as the prior value.

    Returns:
        SHA-256 hex digest of the event.
    """
    prior = previous_event_hash or "GENESIS"
    payload = "|".join([
        event_id,
        evidence_id,
        event_type,
        timestamp,
        from_custodian or "",
        to_custodian or "",
        verification_hash or "",
        prior,
    ])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
