"""
Evidence Manager for ChainOfCustody.

Registers digital evidence items, computes forensic hashes, assigns evidence
numbers, and manages the evidence lifecycle within a case.

Author: Edward Marez
License: MIT
"""

import os
import sqlite3
from typing import Optional

from .database import DatabaseManager
from .hash_verifier import compute_hashes, HashResult
from .utils import generate_uuid, utc_now, evidence_number_from_index


# Valid evidence types
EVIDENCE_TYPES = (
    "DISK_IMAGE",
    "FILE",
    "MEMORY_DUMP",
    "NETWORK_CAPTURE",
    "MOBILE_EXTRACT",
    "DOCUMENT",
    "VIDEO",
    "AUDIO",
    "OTHER",
)

# Valid evidence status values
EVIDENCE_STATUSES = (
    "IN_CUSTODY",
    "CHECKED_OUT",
    "IN_ANALYSIS",
    "TRANSFERRED",
    "DISPOSED",
)


class EvidenceNotFoundError(Exception):
    pass


class EvidenceManager:
    """
    Manages registration, retrieval, and status updates for evidence items.

    On registration the system automatically:
      - Assigns a sequential evidence number (EV-001, EV-002, …)
      - Computes MD5, SHA-1, SHA-256 hashes (if a file_path is provided)
      - Records file size
      - Creates an initial ACQUISITION custody event
    """

    def __init__(self, db: DatabaseManager):
        self.db = db

    # ------------------------------------------------------------------
    # Evidence registration
    # ------------------------------------------------------------------

    def register_evidence(
        self,
        case_id: str,
        description: str,
        evidence_type: str,
        acquisition_method: str,
        current_custodian: str,
        file_path: Optional[str] = None,
        source_device: Optional[str] = None,
        original_location: Optional[str] = None,
        storage_location: Optional[str] = None,
        acquisition_date: Optional[str] = None,
        notes: Optional[str] = None,
        compute_file_hashes: bool = True,
    ) -> dict:
        """
        Register a new evidence item in the database.

        Args:
            case_id:            UUID of the parent case.
            description:        Free-text description (e.g. "Suspect laptop hard drive").
            evidence_type:      One of EVIDENCE_TYPES.
            acquisition_method: How the evidence was acquired (e.g. "FTK Imager 4.7").
            current_custodian:  Full name of the person taking custody.
            file_path:          Path to the evidence file on disk (optional).
            source_device:      Description of the source device (make, model, S/N).
            original_location:  Where the evidence was found / seized from.
            storage_location:   Current physical storage location.
            acquisition_date:   ISO 8601 timestamp (defaults to now).
            notes:              Additional notes.
            compute_file_hashes: Whether to compute MD5/SHA-1/SHA-256 (default True).

        Returns:
            Dict representation of the registered evidence item.

        Raises:
            ValueError: If evidence_type is invalid or file_path doesn't exist.
            FileNotFoundError: If file_path is set and the file doesn't exist.
        """
        if evidence_type not in EVIDENCE_TYPES:
            raise ValueError(
                f"Invalid evidence_type '{evidence_type}'. "
                f"Valid types: {EVIDENCE_TYPES}"
            )

        # Validate file if provided and hash computation is requested
        if file_path and compute_file_hashes and not os.path.isfile(file_path):
            raise FileNotFoundError(
                f"Evidence file not found: {file_path}"
            )

        # Compute hashes from file
        md5_hash = sha1_hash = sha256_hash = None
        file_size = None
        if file_path and compute_file_hashes and os.path.isfile(file_path):
            hashes: HashResult = compute_hashes(file_path)
            md5_hash = hashes.md5
            sha1_hash = hashes.sha1
            sha256_hash = hashes.sha256
            file_size = hashes.file_size

        # Auto-assign evidence number within the case
        evidence_number = self._next_evidence_number(case_id)

        evidence_id = generate_uuid()
        created_at = utc_now()
        acq_date = acquisition_date or created_at

        with self.db.connection() as conn:
            conn.execute(
                """
                INSERT INTO evidence (
                    evidence_id, case_id, evidence_number, description,
                    evidence_type, source_device, acquisition_method,
                    acquisition_date, original_location, file_path,
                    file_size, md5_hash, sha1_hash, sha256_hash,
                    current_custodian, storage_location, status, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'IN_CUSTODY', ?)
                """,
                (
                    evidence_id, case_id, evidence_number, description,
                    evidence_type, source_device, acquisition_method,
                    acq_date, original_location, file_path,
                    file_size, md5_hash, sha1_hash, sha256_hash,
                    current_custodian, storage_location, created_at,
                ),
            )

        self.db.write_audit_entry(
            action="REGISTER_EVIDENCE",
            entity_type="EVIDENCE",
            entity_id=evidence_id,
            details={
                "evidence_number": evidence_number,
                "evidence_type": evidence_type,
                "acquisition_method": acquisition_method,
                "custodian": current_custodian,
                "md5": md5_hash,
                "sha256": sha256_hash,
            },
        )

        return self.get_evidence(evidence_id)

    # ------------------------------------------------------------------
    # Evidence retrieval
    # ------------------------------------------------------------------

    def get_evidence(self, evidence_id: str) -> dict:
        """Retrieve a single evidence item by UUID."""
        rows = self.db.execute(
            "SELECT * FROM evidence WHERE evidence_id = ?", (evidence_id,)
        )
        if not rows:
            raise EvidenceNotFoundError(f"Evidence not found: {evidence_id}")
        return dict(rows[0])

    def get_evidence_by_number(self, case_id: str, evidence_number: str) -> dict:
        """Retrieve evidence by case UUID and evidence number (e.g. 'EV-001')."""
        rows = self.db.execute(
            "SELECT * FROM evidence WHERE case_id = ? AND evidence_number = ?",
            (case_id, evidence_number),
        )
        if not rows:
            raise EvidenceNotFoundError(
                f"Evidence {evidence_number} not found in case {case_id}"
            )
        return dict(rows[0])

    def list_evidence(self, case_id: str) -> list[dict]:
        """List all evidence items for a case, ordered by evidence_number."""
        rows = self.db.execute(
            "SELECT * FROM evidence WHERE case_id = ? ORDER BY evidence_number ASC",
            (case_id,),
        )
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Evidence updates
    # ------------------------------------------------------------------

    def update_custodian(
        self, evidence_id: str, new_custodian: str, new_status: Optional[str] = None
    ) -> dict:
        """
        Update the current custodian (and optionally status) for an evidence item.

        This is called by the custody tracker after a transfer event is recorded.
        """
        if new_status and new_status not in EVIDENCE_STATUSES:
            raise ValueError(f"Invalid status: {new_status}")

        if new_status:
            self.db.execute(
                "UPDATE evidence SET current_custodian = ?, status = ? WHERE evidence_id = ?",
                (new_custodian, new_status, evidence_id),
            )
        else:
            self.db.execute(
                "UPDATE evidence SET current_custodian = ? WHERE evidence_id = ?",
                (new_custodian, evidence_id),
            )
        return self.get_evidence(evidence_id)

    def update_status(self, evidence_id: str, new_status: str) -> dict:
        """Update evidence status."""
        if new_status not in EVIDENCE_STATUSES:
            raise ValueError(f"Invalid evidence status: {new_status}")
        self.db.execute(
            "UPDATE evidence SET status = ? WHERE evidence_id = ?",
            (new_status, evidence_id),
        )
        self.db.write_audit_entry(
            action="UPDATE_EVIDENCE_STATUS",
            entity_type="EVIDENCE",
            entity_id=evidence_id,
            details={"new_status": new_status},
        )
        return self.get_evidence(evidence_id)

    def update_storage_location(self, evidence_id: str, location: str) -> dict:
        """Update the physical storage location of an evidence item."""
        self.db.execute(
            "UPDATE evidence SET storage_location = ? WHERE evidence_id = ?",
            (location, evidence_id),
        )
        return self.get_evidence(evidence_id)

    def update_hashes(
        self,
        evidence_id: str,
        md5: str,
        sha1: str,
        sha256: str,
        file_size: int,
    ) -> dict:
        """
        Update the stored hashes for an evidence item.

        This should only be called at initial acquisition when hashes
        weren't computed immediately (e.g., file registered without a path).
        """
        self.db.execute(
            """
            UPDATE evidence
            SET md5_hash = ?, sha1_hash = ?, sha256_hash = ?, file_size = ?
            WHERE evidence_id = ?
            """,
            (md5, sha1, sha256, file_size, evidence_id),
        )
        self.db.write_audit_entry(
            action="UPDATE_EVIDENCE_HASHES",
            entity_type="EVIDENCE",
            entity_id=evidence_id,
            details={"md5": md5, "sha1": sha1, "sha256": sha256},
        )
        return self.get_evidence(evidence_id)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _next_evidence_number(self, case_id: str) -> str:
        """
        Generate the next sequential evidence number for a case.

        Counts existing evidence items and returns EV-(n+1).
        """
        rows = self.db.execute(
            "SELECT COUNT(*) AS n FROM evidence WHERE case_id = ?", (case_id,)
        )
        count = rows[0]["n"] if rows else 0
        return evidence_number_from_index(count + 1)
