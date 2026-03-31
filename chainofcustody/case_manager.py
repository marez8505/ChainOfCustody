"""
Case Manager for ChainOfCustody.

Creates and manages forensic investigation cases.  Each case is the top-level
container for evidence items and has its own metadata, status lifecycle, and
classification level.

Author: Edward Marez
License: MIT
"""

import sqlite3
from typing import Optional

from .database import DatabaseManager
from .utils import generate_uuid, utc_now


# Valid case status values
CASE_STATUSES = ("OPEN", "ACTIVE", "CLOSED", "ARCHIVED")

# Valid classification levels (using DoD/IC standard labels)
CLASSIFICATION_LEVELS = (
    "UNCLASSIFIED",
    "CUI",               # Controlled Unclassified Information
    "CONFIDENTIAL",
    "SECRET",
    "TOP SECRET",
)


class CaseNotFoundError(Exception):
    pass


class DuplicateCaseError(Exception):
    pass


class CaseManager:
    """
    CRUD operations and lifecycle management for investigation cases.

    All methods that modify data also write to the audit_log table so that
    every case change is traceable.
    """

    def __init__(self, db: DatabaseManager):
        self.db = db

    # ------------------------------------------------------------------
    # Case creation
    # ------------------------------------------------------------------

    def create_case(
        self,
        case_number: str,
        case_name: str,
        examiner_name: str,
        examiner_badge: Optional[str] = None,
        agency: Optional[str] = None,
        description: Optional[str] = None,
        classification: str = "UNCLASSIFIED",
        notes: Optional[str] = None,
    ) -> dict:
        """
        Create a new investigation case.

        Args:
            case_number: Unique case identifier (e.g. "2026-CF-0042").
            case_name:   Human-readable case name.
            examiner_name: Full name of the lead examiner.
            examiner_badge: Badge/employee ID (optional).
            agency:      Investigating agency (e.g. "FBI CART").
            description: Narrative description of the case.
            classification: Classification level (default UNCLASSIFIED).
            notes:       Additional notes.

        Returns:
            Dict representation of the newly created case.

        Raises:
            DuplicateCaseError: If case_number already exists.
            ValueError: If classification is not a valid level.
        """
        if classification not in CLASSIFICATION_LEVELS:
            raise ValueError(
                f"Invalid classification '{classification}'. "
                f"Valid values: {CLASSIFICATION_LEVELS}"
            )

        case_id = generate_uuid()
        created_at = utc_now()

        try:
            with self.db.connection() as conn:
                conn.execute(
                    """
                    INSERT INTO cases
                        (case_id, case_number, case_name, examiner_name,
                         examiner_badge, agency, created_at, status,
                         description, classification, notes)
                    VALUES (?, ?, ?, ?, ?, ?, ?, 'OPEN', ?, ?, ?)
                    """,
                    (
                        case_id, case_number, case_name, examiner_name,
                        examiner_badge, agency, created_at,
                        description, classification, notes,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise DuplicateCaseError(
                f"Case number '{case_number}' already exists."
            ) from exc

        self.db.write_audit_entry(
            action="CREATE_CASE",
            entity_type="CASE",
            entity_id=case_id,
            details={
                "case_number": case_number,
                "case_name": case_name,
                "examiner_name": examiner_name,
                "agency": agency,
            },
        )

        return self.get_case(case_id)

    # ------------------------------------------------------------------
    # Case retrieval
    # ------------------------------------------------------------------

    def get_case(self, case_id: str) -> dict:
        """Retrieve a case by its UUID. Raises CaseNotFoundError if missing."""
        rows = self.db.execute(
            "SELECT * FROM cases WHERE case_id = ?", (case_id,)
        )
        if not rows:
            raise CaseNotFoundError(f"Case not found: {case_id}")
        return dict(rows[0])

    def get_case_by_number(self, case_number: str) -> dict:
        """Retrieve a case by its case number. Raises CaseNotFoundError if missing."""
        rows = self.db.execute(
            "SELECT * FROM cases WHERE case_number = ?", (case_number,)
        )
        if not rows:
            raise CaseNotFoundError(f"Case number not found: {case_number}")
        return dict(rows[0])

    def list_cases(
        self,
        status: Optional[str] = None,
        agency: Optional[str] = None,
    ) -> list[dict]:
        """
        List all cases, optionally filtered by status and/or agency.

        Returns:
            List of case dicts ordered by created_at descending.
        """
        sql = "SELECT * FROM cases WHERE 1=1"
        params: list = []
        if status:
            sql += " AND status = ?"
            params.append(status)
        if agency:
            sql += " AND agency = ?"
            params.append(agency)
        sql += " ORDER BY created_at DESC"
        rows = self.db.execute(sql, tuple(params))
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Case updates
    # ------------------------------------------------------------------

    def update_status(self, case_id: str, new_status: str, notes: Optional[str] = None) -> dict:
        """
        Transition a case to a new status.

        Valid transitions:
            OPEN → ACTIVE → CLOSED → ARCHIVED
        Any backward transition is allowed for correction purposes.

        Raises:
            ValueError: If new_status is not a valid status.
            CaseNotFoundError: If case does not exist.
        """
        if new_status not in CASE_STATUSES:
            raise ValueError(
                f"Invalid status '{new_status}'. Valid: {CASE_STATUSES}"
            )
        case = self.get_case(case_id)  # raises CaseNotFoundError if missing

        update_sql = "UPDATE cases SET status = ? WHERE case_id = ?"
        params: list = [new_status, case_id]
        if notes:
            update_sql = "UPDATE cases SET status = ?, notes = ? WHERE case_id = ?"
            params = [new_status, notes, case_id]

        self.db.execute(update_sql, tuple(params))

        self.db.write_audit_entry(
            action="UPDATE_CASE_STATUS",
            entity_type="CASE",
            entity_id=case_id,
            details={
                "old_status": case["status"],
                "new_status": new_status,
            },
        )
        return self.get_case(case_id)

    def update_notes(self, case_id: str, notes: str) -> dict:
        """Append or replace case notes."""
        self.get_case(case_id)  # validate existence
        self.db.execute(
            "UPDATE cases SET notes = ? WHERE case_id = ?", (notes, case_id)
        )
        self.db.write_audit_entry(
            action="UPDATE_CASE_NOTES",
            entity_type="CASE",
            entity_id=case_id,
            details={"notes_updated": True},
        )
        return self.get_case(case_id)

    # ------------------------------------------------------------------
    # Case summary
    # ------------------------------------------------------------------

    def get_case_summary(self, case_id: str) -> dict:
        """
        Return a full summary of a case including evidence count and status.

        Used by the report generator.
        """
        case = self.get_case(case_id)
        evidence_rows = self.db.execute(
            "SELECT evidence_id, evidence_number, description, status, current_custodian "
            "FROM evidence WHERE case_id = ? ORDER BY evidence_number ASC",
            (case_id,),
        )
        event_count = self.db.execute(
            """
            SELECT COUNT(*) AS n FROM custody_events ce
            JOIN evidence e ON ce.evidence_id = e.evidence_id
            WHERE e.case_id = ?
            """,
            (case_id,),
        )[0]["n"]

        return {
            **case,
            "evidence_items": [dict(r) for r in evidence_rows],
            "evidence_count": len(evidence_rows),
            "total_custody_events": event_count,
        }
