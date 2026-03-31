"""
Integrity Checker for ChainOfCustody.

Verifies database integrity, detects tampering, validates hash chains across
custody events, and provides detailed integrity reports.

Author: Edward Marez
License: MIT
"""

import hashlib
from dataclasses import dataclass, field
from typing import Optional

from .database import DatabaseManager
from .hash_verifier import (
    verify_file_integrity,
    generate_event_hash,
    hash_database_file,
)
from .utils import utc_now


@dataclass
class EvidenceIntegrityResult:
    """Integrity check result for a single evidence item."""

    evidence_id: str
    evidence_number: str
    description: str
    file_path: Optional[str]
    file_exists: bool
    hash_verified: bool
    chain_valid: bool
    violations: list[str] = field(default_factory=list)
    current_md5: Optional[str] = None
    current_sha1: Optional[str] = None
    current_sha256: Optional[str] = None
    stored_md5: Optional[str] = None
    stored_sha1: Optional[str] = None
    stored_sha256: Optional[str] = None
    event_count: int = 0

    @property
    def is_clean(self) -> bool:
        return len(self.violations) == 0

    def status_label(self) -> str:
        if self.is_clean:
            return "VERIFIED"
        return "INTEGRITY VIOLATION"


@dataclass
class CaseIntegrityReport:
    """Full integrity report for a case."""

    case_id: str
    case_number: str
    generated_at: str
    db_hash: str
    total_evidence: int
    verified_count: int
    violation_count: int
    evidence_results: list[EvidenceIntegrityResult]
    chain_breaks: list[str]
    overall_status: str  # "CLEAN" | "VIOLATIONS_DETECTED" | "CHAIN_BROKEN"

    def to_dict(self) -> dict:
        return {
            "case_id": self.case_id,
            "case_number": self.case_number,
            "generated_at": self.generated_at,
            "db_hash": self.db_hash,
            "total_evidence": self.total_evidence,
            "verified_count": self.verified_count,
            "violation_count": self.violation_count,
            "overall_status": self.overall_status,
            "evidence_results": [
                {
                    "evidence_id": r.evidence_id,
                    "evidence_number": r.evidence_number,
                    "description": r.description,
                    "status": r.status_label(),
                    "file_exists": r.file_exists,
                    "hash_verified": r.hash_verified,
                    "chain_valid": r.chain_valid,
                    "violations": r.violations,
                    "event_count": r.event_count,
                }
                for r in self.evidence_results
            ],
            "chain_breaks": self.chain_breaks,
        }


class IntegrityChecker:
    """
    Verifies the integrity of evidence items, custody event chains, and
    the database file itself.

    Methods:
        verify_case(case_id)        → CaseIntegrityReport
        verify_evidence(evidence_id) → EvidenceIntegrityResult
        verify_event_chain(evidence_id) → (bool, list[str])
        verify_database_hash(expected_hash) → bool
    """

    def __init__(self, db: DatabaseManager):
        self.db = db

    # ------------------------------------------------------------------
    # Case-level verification
    # ------------------------------------------------------------------

    def verify_case(self, case_id: str) -> CaseIntegrityReport:
        """
        Run a full integrity check on all evidence in a case.

        For each evidence item:
          1. If a file_path is recorded, recompute hashes and compare.
          2. Validate the custody event hash chain (tamper detection).

        Returns a CaseIntegrityReport with detailed findings.
        """
        case_rows = self.db.execute(
            "SELECT * FROM cases WHERE case_id = ?", (case_id,)
        )
        if not case_rows:
            raise ValueError(f"Case not found: {case_id}")
        case = dict(case_rows[0])

        evidence_rows = self.db.execute(
            "SELECT * FROM evidence WHERE case_id = ? ORDER BY evidence_number",
            (case_id,),
        )

        evidence_results: list[EvidenceIntegrityResult] = []
        chain_breaks: list[str] = []

        for ev in evidence_rows:
            ev_dict = dict(ev)
            result = self.verify_evidence(ev_dict["evidence_id"])
            evidence_results.append(result)
            if not result.chain_valid:
                chain_breaks.append(
                    f"{ev_dict['evidence_number']}: custody chain hash mismatch"
                )

        violation_count = sum(1 for r in evidence_results if not r.is_clean)
        verified_count = len(evidence_results) - violation_count

        if chain_breaks:
            overall = "CHAIN_BROKEN"
        elif violation_count > 0:
            overall = "VIOLATIONS_DETECTED"
        else:
            overall = "CLEAN"

        return CaseIntegrityReport(
            case_id=case_id,
            case_number=case["case_number"],
            generated_at=utc_now(),
            db_hash=self.db.current_db_hash(),
            total_evidence=len(evidence_results),
            verified_count=verified_count,
            violation_count=violation_count,
            evidence_results=evidence_results,
            chain_breaks=chain_breaks,
            overall_status=overall,
        )

    # ------------------------------------------------------------------
    # Evidence-level verification
    # ------------------------------------------------------------------

    def verify_evidence(self, evidence_id: str) -> EvidenceIntegrityResult:
        """
        Verify integrity for a single evidence item.

        Steps:
          1. Load evidence metadata from DB.
          2. Check file existence.
          3. Recompute hashes and compare to acquisition hashes.
          4. Validate custody event chain.
        """
        rows = self.db.execute(
            "SELECT * FROM evidence WHERE evidence_id = ?", (evidence_id,)
        )
        if not rows:
            return EvidenceIntegrityResult(
                evidence_id=evidence_id,
                evidence_number="UNKNOWN",
                description="Evidence not found",
                file_path=None,
                file_exists=False,
                hash_verified=False,
                chain_valid=False,
                violations=[f"Evidence ID {evidence_id} not found in database"],
            )

        ev = dict(rows[0])
        violations: list[str] = []

        file_path = ev.get("file_path")
        file_exists = False
        current_md5 = current_sha1 = current_sha256 = None
        hash_verified = False

        if file_path:
            import os
            file_exists = os.path.isfile(file_path)
            if not file_exists:
                violations.append(f"Evidence file missing: {file_path}")
            else:
                vr = verify_file_integrity(
                    file_path=file_path,
                    stored_md5=ev.get("md5_hash"),
                    stored_sha1=ev.get("sha1_hash"),
                    stored_sha256=ev.get("sha256_hash"),
                )
                current_md5 = vr.current_hashes.md5
                current_sha1 = vr.current_hashes.sha1
                current_sha256 = vr.current_hashes.sha256
                hash_verified = vr.is_valid

                if not vr.md5_match:
                    violations.append(
                        f"MD5 mismatch: stored={ev.get('md5_hash')} current={current_md5}"
                    )
                if not vr.sha1_match:
                    violations.append(
                        f"SHA-1 mismatch: stored={ev.get('sha1_hash')} current={current_sha1}"
                    )
                if not vr.sha256_match:
                    violations.append(
                        f"SHA-256 mismatch: stored={ev.get('sha256_hash')} current={current_sha256}"
                    )
        else:
            # No file path — check if hashes are present at all
            if ev.get("sha256_hash"):
                hash_verified = True  # Hashes were recorded at acquisition
            else:
                violations.append("No file path and no stored hashes — evidence integrity cannot be verified")

        # Validate custody event chain
        chain_valid, chain_violations = self.verify_event_chain(evidence_id)
        if not chain_valid:
            violations.extend(chain_violations)

        event_count_rows = self.db.execute(
            "SELECT COUNT(*) AS n FROM custody_events WHERE evidence_id = ?",
            (evidence_id,),
        )
        event_count = event_count_rows[0]["n"] if event_count_rows else 0

        return EvidenceIntegrityResult(
            evidence_id=evidence_id,
            evidence_number=ev["evidence_number"],
            description=ev["description"],
            file_path=file_path,
            file_exists=file_exists,
            hash_verified=hash_verified,
            chain_valid=chain_valid,
            violations=violations,
            current_md5=current_md5,
            current_sha1=current_sha1,
            current_sha256=current_sha256,
            stored_md5=ev.get("md5_hash"),
            stored_sha1=ev.get("sha1_hash"),
            stored_sha256=ev.get("sha256_hash"),
            event_count=event_count,
        )

    # ------------------------------------------------------------------
    # Event chain verification
    # ------------------------------------------------------------------

    def verify_event_chain(self, evidence_id: str) -> tuple[bool, list[str]]:
        """
        Validate the cryptographic hash chain across all custody events
        for an evidence item.

        Each event's chain_hash must match what we would compute from its
        own fields plus the previous event's chain_hash.  A mismatch
        indicates that a record was modified or deleted.

        Returns:
            (is_valid: bool, violations: list[str])
        """
        rows = self.db.execute(
            """
            SELECT * FROM custody_events
            WHERE evidence_id = ?
            ORDER BY timestamp ASC
            """,
            (evidence_id,),
        )
        events = [dict(r) for r in rows]

        if not events:
            return True, []  # No events — nothing to verify

        violations: list[str] = []
        previous_hash: Optional[str] = None

        for event in events:
            expected_hash = generate_event_hash(
                event_id=event["event_id"],
                evidence_id=event["evidence_id"],
                event_type=event["event_type"],
                timestamp=event["timestamp"],
                from_custodian=event.get("from_custodian"),
                to_custodian=event.get("to_custodian"),
                verification_hash=event.get("verification_hash"),
                previous_event_hash=previous_hash,
            )

            stored_hash = event.get("chain_hash")
            if stored_hash != expected_hash:
                violations.append(
                    f"Chain hash mismatch at event {event['event_id']} "
                    f"({event['event_type']} @ {event['timestamp']}): "
                    f"expected={expected_hash[:16]}... stored={str(stored_hash)[:16]}..."
                )

            previous_hash = stored_hash  # Use stored hash to continue chain

        is_valid = len(violations) == 0
        return is_valid, violations

    # ------------------------------------------------------------------
    # Database-level verification
    # ------------------------------------------------------------------

    def compute_current_db_hash(self) -> str:
        """Return the SHA-256 hash of the database file at this moment."""
        return hash_database_file(self.db.db_path)

    def verify_database_hash(self, expected_hash: str) -> bool:
        """
        Compare the database file's current hash against an expected value.

        Used after restoring from backup or when checking whether the database
        was externally modified since the last known-good snapshot.
        """
        return self.compute_current_db_hash() == expected_hash

    def get_audit_trail(self, case_id: Optional[str] = None) -> list[dict]:
        """
        Return the full audit trail, optionally filtered to a case.

        For a case filter, joins audit_log against entities belonging to the case.
        """
        if case_id is None:
            rows = self.db.execute(
                "SELECT * FROM audit_log ORDER BY timestamp ASC"
            )
            return [dict(r) for r in rows]

        # Get all entity IDs for this case
        case_rows = self.db.execute(
            "SELECT case_id FROM cases WHERE case_id = ?", (case_id,)
        )
        if not case_rows:
            return []

        evidence_rows = self.db.execute(
            "SELECT evidence_id FROM evidence WHERE case_id = ?", (case_id,)
        )
        entity_ids = {case_id}
        for r in evidence_rows:
            entity_ids.add(r["evidence_id"])

        # Get custody event IDs for this case's evidence
        if evidence_rows:
            ev_ids = tuple(r["evidence_id"] for r in evidence_rows)
            placeholders = ",".join("?" * len(ev_ids))
            event_rows = self.db.execute(
                f"SELECT event_id FROM custody_events WHERE evidence_id IN ({placeholders})",
                ev_ids,
            )
            for r in event_rows:
                entity_ids.add(r["event_id"])

        # Fetch matching audit entries
        placeholders = ",".join("?" * len(entity_ids))
        rows = self.db.execute(
            f"SELECT * FROM audit_log WHERE entity_id IN ({placeholders}) ORDER BY timestamp ASC",
            tuple(entity_ids),
        )
        return [dict(r) for r in rows]
