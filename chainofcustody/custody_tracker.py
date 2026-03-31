"""
Custody Tracker for ChainOfCustody.

Records immutable custody events that form the legal chain of custody.
Every transfer, checkout, return, and verification is permanently logged
with a tamper-evident hash chain.

Author: Edward Marez
License: MIT
"""

from typing import Optional

from .database import DatabaseManager
from .evidence_manager import EvidenceManager, EVIDENCE_STATUSES
from .hash_verifier import (
    verify_file_integrity,
    generate_event_hash,
    VerificationResult,
)
from .utils import generate_uuid, utc_now, generate_signature


# All valid event types — these map to real forensic lab procedures
EVENT_TYPES = (
    "ACQUISITION",      # Initial evidence collection
    "TRANSFER",         # Change of custodian
    "CHECKOUT",         # Evidence removed from storage for analysis
    "RETURN",           # Evidence returned to secure storage
    "ANALYSIS_START",   # Formal analysis period begins
    "ANALYSIS_END",     # Formal analysis period ends
    "VERIFICATION",     # Periodic integrity check
    "STORAGE",          # Evidence placed into long-term storage
    "DISPOSAL",         # Evidence destroyed per legal authorization
)

# Event type → resulting evidence status mapping
EVENT_STATUS_MAP = {
    "ACQUISITION":    "IN_CUSTODY",
    "TRANSFER":       "IN_CUSTODY",
    "CHECKOUT":       "CHECKED_OUT",
    "RETURN":         "IN_CUSTODY",
    "ANALYSIS_START": "IN_ANALYSIS",
    "ANALYSIS_END":   "IN_CUSTODY",
    "VERIFICATION":   "IN_CUSTODY",
    "STORAGE":        "IN_CUSTODY",
    "DISPOSAL":       "DISPOSED",
}


class CustodyTracker:
    """
    Records and retrieves custody events for evidence items.

    Maintains a hash chain across all events for each evidence item so that
    any deletion or modification of an event is detectable during an integrity
    check.
    """

    def __init__(self, db: DatabaseManager, evidence_manager: EvidenceManager):
        self.db = db
        self.em = evidence_manager

    # ------------------------------------------------------------------
    # High-level helpers (most callers should use these)
    # ------------------------------------------------------------------

    def log_acquisition(
        self,
        evidence_id: str,
        custodian: str,
        location: str,
        reason: str,
        notes: Optional[str] = None,
    ) -> dict:
        """Record the initial acquisition of an evidence item."""
        return self._log_event(
            evidence_id=evidence_id,
            event_type="ACQUISITION",
            from_custodian=None,
            to_custodian=custodian,
            location=location,
            reason=reason,
            notes=notes,
        )

    def log_transfer(
        self,
        evidence_id: str,
        from_custodian: str,
        to_custodian: str,
        location: str,
        reason: str,
        notes: Optional[str] = None,
    ) -> dict:
        """Record a transfer of custody between examiners."""
        event = self._log_event(
            evidence_id=evidence_id,
            event_type="TRANSFER",
            from_custodian=from_custodian,
            to_custodian=to_custodian,
            location=location,
            reason=reason,
            notes=notes,
        )
        # Update the evidence record with the new custodian
        self.em.update_custodian(
            evidence_id, to_custodian, new_status="IN_CUSTODY"
        )
        return event

    def log_checkout(
        self,
        evidence_id: str,
        custodian: str,
        location: str,
        reason: str,
        notes: Optional[str] = None,
    ) -> dict:
        """Record checkout of evidence for analysis."""
        ev = self.em.get_evidence(evidence_id)
        event = self._log_event(
            evidence_id=evidence_id,
            event_type="CHECKOUT",
            from_custodian=ev["current_custodian"],
            to_custodian=custodian,
            location=location,
            reason=reason,
            notes=notes,
        )
        self.em.update_status(evidence_id, "CHECKED_OUT")
        return event

    def log_return(
        self,
        evidence_id: str,
        from_custodian: str,
        to_custodian: str,
        location: str,
        reason: str,
        notes: Optional[str] = None,
    ) -> dict:
        """Record return of evidence to secure storage."""
        event = self._log_event(
            evidence_id=evidence_id,
            event_type="RETURN",
            from_custodian=from_custodian,
            to_custodian=to_custodian,
            location=location,
            reason=reason,
            notes=notes,
        )
        self.em.update_custodian(evidence_id, to_custodian, new_status="IN_CUSTODY")
        return event

    def log_analysis_start(
        self,
        evidence_id: str,
        analyst: str,
        location: str,
        reason: str,
        notes: Optional[str] = None,
    ) -> dict:
        """Record the start of a formal analysis period."""
        event = self._log_event(
            evidence_id=evidence_id,
            event_type="ANALYSIS_START",
            from_custodian=None,
            to_custodian=analyst,
            location=location,
            reason=reason,
            notes=notes,
        )
        self.em.update_status(evidence_id, "IN_ANALYSIS")
        return event

    def log_analysis_end(
        self,
        evidence_id: str,
        analyst: str,
        location: str,
        reason: str,
        notes: Optional[str] = None,
    ) -> dict:
        """Record the end of a formal analysis period."""
        event = self._log_event(
            evidence_id=evidence_id,
            event_type="ANALYSIS_END",
            from_custodian=analyst,
            to_custodian=None,
            location=location,
            reason=reason,
            notes=notes,
        )
        self.em.update_status(evidence_id, "IN_CUSTODY")
        return event

    def log_verification(
        self,
        evidence_id: str,
        custodian: str,
        location: str,
        reason: str = "Periodic integrity verification",
        notes: Optional[str] = None,
        file_path: Optional[str] = None,
    ) -> dict:
        """
        Record a hash verification event.

        If file_path is provided, computes current hashes and compares to the
        stored acquisition hashes.  The result is stored in hash_verified.
        """
        ev = self.em.get_evidence(evidence_id)
        verification_hash = None
        hash_verified = None

        if file_path or ev.get("file_path"):
            path = file_path or ev["file_path"]
            result: VerificationResult = verify_file_integrity(
                file_path=path,
                stored_md5=ev.get("md5_hash"),
                stored_sha1=ev.get("sha1_hash"),
                stored_sha256=ev.get("sha256_hash"),
            )
            verification_hash = result.current_hashes.sha256
            hash_verified = 1 if result.is_valid else 0
            if notes is None:
                notes = result.integrity_status()
            else:
                notes = f"{notes} | {result.integrity_status()}"

        return self._log_event(
            evidence_id=evidence_id,
            event_type="VERIFICATION",
            from_custodian=custodian,
            to_custodian=custodian,
            location=location,
            reason=reason,
            notes=notes,
            verification_hash=verification_hash,
            hash_verified=hash_verified,
        )

    def log_storage(
        self,
        evidence_id: str,
        custodian: str,
        location: str,
        reason: str,
        notes: Optional[str] = None,
    ) -> dict:
        """Record placement of evidence into long-term storage."""
        event = self._log_event(
            evidence_id=evidence_id,
            event_type="STORAGE",
            from_custodian=custodian,
            to_custodian=custodian,
            location=location,
            reason=reason,
            notes=notes,
        )
        self.em.update_storage_location(evidence_id, location)
        return event

    def log_disposal(
        self,
        evidence_id: str,
        custodian: str,
        location: str,
        reason: str,
        notes: Optional[str] = None,
    ) -> dict:
        """Record evidence disposal (destruction or return to owner)."""
        event = self._log_event(
            evidence_id=evidence_id,
            event_type="DISPOSAL",
            from_custodian=custodian,
            to_custodian=None,
            location=location,
            reason=reason,
            notes=notes,
        )
        self.em.update_status(evidence_id, "DISPOSED")
        return event

    # ------------------------------------------------------------------
    # Generic event logging
    # ------------------------------------------------------------------

    def _log_event(
        self,
        evidence_id: str,
        event_type: str,
        from_custodian: Optional[str],
        to_custodian: Optional[str],
        location: Optional[str],
        reason: str,
        notes: Optional[str] = None,
        verification_hash: Optional[str] = None,
        hash_verified: Optional[int] = None,
    ) -> dict:
        """
        Core method that writes a custody event to the database.

        The chain_hash field links each event to the previous event for
        the same evidence item, creating a tamper-evident audit chain.
        """
        if event_type not in EVENT_TYPES:
            raise ValueError(f"Invalid event_type: {event_type}")

        event_id = generate_uuid()
        timestamp = utc_now()

        # Generate signature: SHA-256(custodian | timestamp | event_id)
        signing_party = to_custodian or from_custodian or "SYSTEM"
        signature = generate_signature(signing_party, timestamp, event_id)

        # Find previous chain_hash for this evidence item
        previous_hash = self._get_last_chain_hash(evidence_id)

        chain_hash = generate_event_hash(
            event_id=event_id,
            evidence_id=evidence_id,
            event_type=event_type,
            timestamp=timestamp,
            from_custodian=from_custodian,
            to_custodian=to_custodian,
            verification_hash=verification_hash,
            previous_event_hash=previous_hash,
        )

        with self.db.connection() as conn:
            conn.execute(
                """
                INSERT INTO custody_events (
                    event_id, evidence_id, event_type, from_custodian,
                    to_custodian, timestamp, location, reason,
                    verification_hash, hash_verified, notes, signature, chain_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id, evidence_id, event_type, from_custodian,
                    to_custodian, timestamp, location, reason,
                    verification_hash, hash_verified, notes, signature, chain_hash,
                ),
            )

        self.db.write_audit_entry(
            action=f"LOG_{event_type}",
            entity_type="CUSTODY_EVENT",
            entity_id=event_id,
            details={
                "evidence_id": evidence_id,
                "from": from_custodian,
                "to": to_custodian,
                "location": location,
            },
        )

        return self.get_event(event_id)

    # ------------------------------------------------------------------
    # Retrieval
    # ------------------------------------------------------------------

    def get_event(self, event_id: str) -> dict:
        """Retrieve a single custody event by UUID."""
        rows = self.db.execute(
            "SELECT * FROM custody_events WHERE event_id = ?", (event_id,)
        )
        if not rows:
            raise ValueError(f"Custody event not found: {event_id}")
        return dict(rows[0])

    def get_custody_chain(self, evidence_id: str) -> list[dict]:
        """
        Return all custody events for an evidence item in chronological order.
        """
        rows = self.db.execute(
            "SELECT * FROM custody_events WHERE evidence_id = ? ORDER BY timestamp ASC",
            (evidence_id,),
        )
        return [dict(r) for r in rows]

    def get_case_custody_events(self, case_id: str) -> list[dict]:
        """Return all custody events for all evidence in a case."""
        rows = self.db.execute(
            """
            SELECT ce.*, e.evidence_number, e.description AS evidence_description
            FROM custody_events ce
            JOIN evidence e ON ce.evidence_id = e.evidence_id
            WHERE e.case_id = ?
            ORDER BY ce.timestamp ASC
            """,
            (case_id,),
        )
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _get_last_chain_hash(self, evidence_id: str) -> Optional[str]:
        """Return the chain_hash of the most recent event for this evidence item."""
        rows = self.db.execute(
            """
            SELECT chain_hash FROM custody_events
            WHERE evidence_id = ?
            ORDER BY timestamp DESC
            LIMIT 1
            """,
            (evidence_id,),
        )
        if rows and rows[0]["chain_hash"]:
            return rows[0]["chain_hash"]
        return None
