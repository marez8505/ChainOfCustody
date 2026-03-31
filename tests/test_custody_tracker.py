"""
Tests for chainofcustody.custody_tracker.CustodyTracker and
chainofcustody.integrity_checker.IntegrityChecker

Author: Edward Marez
License: MIT
"""

import hashlib
import os
import tempfile
import time
import unittest

from chainofcustody.database import DatabaseManager
from chainofcustody.case_manager import CaseManager
from chainofcustody.evidence_manager import EvidenceManager
from chainofcustody.custody_tracker import CustodyTracker, EVENT_TYPES
from chainofcustody.integrity_checker import IntegrityChecker


class TestCustodyTrackerBase(unittest.TestCase):
    """Base class with temp DB, case, evidence, and tracker wired up."""

    def setUp(self):
        self.tmp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp_db.close()
        self.db = DatabaseManager(self.tmp_db.name)
        self.cm = CaseManager(self.db)
        self.em = EvidenceManager(self.db)
        self.ct = CustodyTracker(self.db, self.em)
        self.ic = IntegrityChecker(self.db)

        # Create a case
        self.case = self.cm.create_case(
            case_number="CT-TEST-001",
            case_name="Custody Tracker Test Case",
            examiner_name="Edward Marez",
            examiner_badge="TEST-999",
            agency="Test Lab",
        )
        self.case_id = self.case["case_id"]

        # Create a real evidence file
        self.tmp_ev = tempfile.NamedTemporaryFile(delete=False, suffix=".dd")
        self.tmp_ev.write(b"Digital evidence file content" * 1000)
        self.tmp_ev.close()
        self.ev_path = self.tmp_ev.name

        # Register evidence
        self.ev = self.em.register_evidence(
            case_id=self.case_id,
            description="Test disk image",
            evidence_type="DISK_IMAGE",
            acquisition_method="Test Tool",
            current_custodian="Edward Marez",
            file_path=self.ev_path,
            compute_file_hashes=True,
        )
        self.ev_id = self.ev["evidence_id"]

    def tearDown(self):
        if os.path.exists(self.tmp_db.name):
            os.unlink(self.tmp_db.name)
        if os.path.exists(self.ev_path):
            os.unlink(self.ev_path)


class TestCustodyEventLogging(TestCustodyTrackerBase):

    def test_log_acquisition(self):
        event = self.ct.log_acquisition(
            evidence_id=self.ev_id,
            custodian="Edward Marez",
            location="Evidence Lab 1",
            reason="Initial acquisition",
        )
        self.assertEqual(event["event_type"], "ACQUISITION")
        self.assertEqual(event["to_custodian"], "Edward Marez")
        self.assertIsNotNone(event["event_id"])

    def test_log_transfer_updates_custodian(self):
        self.ct.log_acquisition(self.ev_id, "Edward Marez", "Lab", "Initial acq")
        time.sleep(0.01)
        self.ct.log_transfer(
            evidence_id=self.ev_id,
            from_custodian="Edward Marez",
            to_custodian="Jane Smith",
            location="Transfer Room",
            reason="Transfer to senior examiner",
        )
        ev = self.em.get_evidence(self.ev_id)
        self.assertEqual(ev["current_custodian"], "Jane Smith")

    def test_log_checkout_updates_status(self):
        self.ct.log_checkout(
            evidence_id=self.ev_id,
            custodian="Edward Marez",
            location="Analysis Room",
            reason="Checkout for analysis",
        )
        ev = self.em.get_evidence(self.ev_id)
        self.assertEqual(ev["status"], "CHECKED_OUT")

    def test_log_return_updates_status(self):
        self.ct.log_checkout(self.ev_id, "Alice", "Lab", "Checkout")
        time.sleep(0.01)
        self.ct.log_return(
            evidence_id=self.ev_id,
            from_custodian="Alice",
            to_custodian="Edward Marez",
            location="Evidence Locker A",
            reason="Returning after analysis",
        )
        ev = self.em.get_evidence(self.ev_id)
        self.assertEqual(ev["status"], "IN_CUSTODY")

    def test_log_analysis_start_end(self):
        self.ct.log_analysis_start(
            self.ev_id, "Alice", "Analysis Lab", "Starting full forensic exam"
        )
        ev = self.em.get_evidence(self.ev_id)
        self.assertEqual(ev["status"], "IN_ANALYSIS")
        time.sleep(0.01)
        self.ct.log_analysis_end(
            self.ev_id, "Alice", "Analysis Lab", "Analysis complete"
        )
        ev = self.em.get_evidence(self.ev_id)
        self.assertEqual(ev["status"], "IN_CUSTODY")

    def test_log_disposal_updates_status(self):
        event = self.ct.log_disposal(
            evidence_id=self.ev_id,
            custodian="Edward Marez",
            location="Destruction Facility",
            reason="Evidence disposed per court order",
        )
        ev = self.em.get_evidence(self.ev_id)
        self.assertEqual(ev["status"], "DISPOSED")
        self.assertEqual(event["event_type"], "DISPOSAL")

    def test_log_storage_updates_location(self):
        self.ct.log_storage(
            evidence_id=self.ev_id,
            custodian="Edward Marez",
            location="Vault B, Shelf 7",
            reason="Long-term secure storage",
        )
        ev = self.em.get_evidence(self.ev_id)
        self.assertEqual(ev["storage_location"], "Vault B, Shelf 7")

    def test_log_verification_with_file(self):
        """Verification with a file path should compute hashes and set hash_verified."""
        event = self.ct.log_verification(
            evidence_id=self.ev_id,
            custodian="Edward Marez",
            location="Lab",
            file_path=self.ev_path,
        )
        self.assertEqual(event["event_type"], "VERIFICATION")
        self.assertEqual(event["hash_verified"], 1)  # SQLite bool = 1

    def test_invalid_event_type_raises(self):
        with self.assertRaises(ValueError):
            self.ct._log_event(
                evidence_id=self.ev_id,
                event_type="INVALID_EVENT",
                from_custodian=None,
                to_custodian="Alice",
                location="Lab",
                reason="Bad type test",
            )


class TestCustodyChain(TestCustodyTrackerBase):

    def test_get_custody_chain_order(self):
        """Events should be returned in chronological order."""
        self.ct.log_acquisition(self.ev_id, "Edward Marez", "Lab", "Acquisition")
        time.sleep(0.01)
        self.ct.log_transfer(self.ev_id, "Edward Marez", "Alice", "Lab", "Transfer 1")
        time.sleep(0.01)
        self.ct.log_transfer(self.ev_id, "Alice", "Bob", "Lab", "Transfer 2")

        chain = self.ct.get_custody_chain(self.ev_id)
        self.assertGreaterEqual(len(chain), 3)
        timestamps = [e["timestamp"] for e in chain]
        self.assertEqual(timestamps, sorted(timestamps))

    def test_get_custody_chain_empty(self):
        """New evidence with no events should return empty chain."""
        ev2 = self.em.register_evidence(
            case_id=self.case_id,
            description="No events evidence",
            evidence_type="FILE",
            acquisition_method="Manual",
            current_custodian="Edward Marez",
            compute_file_hashes=False,
        )
        chain = self.ct.get_custody_chain(ev2["evidence_id"])
        self.assertEqual(chain, [])

    def test_hash_chain_links_events(self):
        """Each event's chain_hash should differ from the previous."""
        self.ct.log_acquisition(self.ev_id, "Edward Marez", "Lab", "Acquisition")
        time.sleep(0.01)
        self.ct.log_transfer(self.ev_id, "Edward Marez", "Alice", "Lab", "Transfer")

        chain = self.ct.get_custody_chain(self.ev_id)
        self.assertGreaterEqual(len(chain), 2)

        hashes = [e["chain_hash"] for e in chain]
        # All hashes should be non-None
        for h in hashes:
            self.assertIsNotNone(h)
            self.assertEqual(len(h), 64)  # SHA-256

        # Hashes should be unique (different events → different hashes)
        self.assertEqual(len(hashes), len(set(hashes)))

    def test_signature_is_generated(self):
        """Each event should have a non-empty signature."""
        event = self.ct.log_acquisition(
            self.ev_id, "Edward Marez", "Lab", "Acquisition"
        )
        self.assertIsNotNone(event.get("signature"))
        self.assertEqual(len(event["signature"]), 64)  # SHA-256 hex

    def test_get_case_custody_events(self):
        """get_case_custody_events should return events across all evidence."""
        ev2 = self.em.register_evidence(
            case_id=self.case_id,
            description="Second item",
            evidence_type="FILE",
            acquisition_method="Manual",
            current_custodian="E. Marez",
            compute_file_hashes=False,
        )
        self.ct.log_acquisition(self.ev_id, "E. Marez", "Lab", "Acq 1")
        time.sleep(0.01)
        self.ct.log_acquisition(ev2["evidence_id"], "E. Marez", "Lab", "Acq 2")

        events = self.ct.get_case_custody_events(self.case_id)
        ev_ids_in_events = {e["evidence_id"] for e in events}
        self.assertIn(self.ev_id, ev_ids_in_events)
        self.assertIn(ev2["evidence_id"], ev_ids_in_events)


class TestIntegrityChecker(TestCustodyTrackerBase):

    def test_verify_evidence_clean(self):
        """Evidence with matching hashes and intact chain should be clean."""
        self.ct.log_acquisition(self.ev_id, "E. Marez", "Lab", "Acquisition")
        result = self.ic.verify_evidence(self.ev_id)
        self.assertTrue(result.hash_verified, "Acquisition hashes should match file")
        self.assertTrue(result.chain_valid, "Chain should be valid")
        self.assertTrue(result.is_clean)

    def test_verify_evidence_missing_file(self):
        """Evidence pointing to a missing file should report a violation."""
        ev = self.em.register_evidence(
            case_id=self.case_id,
            description="Evidence with bad path",
            evidence_type="FILE",
            acquisition_method="Manual",
            current_custodian="E. Marez",
            file_path="/nonexistent/path.dd",
            compute_file_hashes=False,
        )
        # Manually set stored hashes to force a real check
        self.em.update_hashes(ev["evidence_id"], "md5", "sha1", "sha256", 100)
        result = self.ic.verify_evidence(ev["evidence_id"])
        self.assertFalse(result.file_exists)
        self.assertFalse(result.is_clean)
        self.assertTrue(len(result.violations) > 0)

    def test_verify_event_chain_valid(self):
        """Intact chain should pass verification."""
        self.ct.log_acquisition(self.ev_id, "E. Marez", "Lab", "Acq")
        time.sleep(0.01)
        self.ct.log_transfer(self.ev_id, "E. Marez", "Alice", "Lab", "Transfer")
        is_valid, violations = self.ic.verify_event_chain(self.ev_id)
        self.assertTrue(is_valid)
        self.assertEqual(violations, [])

    def test_verify_event_chain_tampered(self):
        """Modifying a chain_hash should cause chain verification to fail."""
        self.ct.log_acquisition(self.ev_id, "E. Marez", "Lab", "Acq")
        # Tamper with the chain_hash directly
        with self.db.connection() as conn:
            conn.execute(
                "UPDATE custody_events SET chain_hash = 'tampered' WHERE evidence_id = ?",
                (self.ev_id,),
            )
        is_valid, violations = self.ic.verify_event_chain(self.ev_id)
        self.assertFalse(is_valid)
        self.assertGreater(len(violations), 0)

    def test_verify_case_clean(self):
        """A case with no violations should report CLEAN."""
        self.ct.log_acquisition(self.ev_id, "E. Marez", "Lab", "Acq")
        report = self.ic.verify_case(self.case_id)
        self.assertEqual(report.overall_status, "CLEAN")
        self.assertEqual(report.violation_count, 0)

    def test_verify_case_returns_per_evidence_results(self):
        """Case integrity report should include a result for every evidence item."""
        ev2 = self.em.register_evidence(
            case_id=self.case_id,
            description="Second evidence",
            evidence_type="FILE",
            acquisition_method="Manual",
            current_custodian="E. Marez",
            compute_file_hashes=False,
        )
        report = self.ic.verify_case(self.case_id)
        result_ids = {r.evidence_id for r in report.evidence_results}
        self.assertIn(self.ev_id, result_ids)
        self.assertIn(ev2["evidence_id"], result_ids)

    def test_get_audit_trail_case_filtered(self):
        """Audit trail filtered by case_id should not include other cases' entries."""
        other_case = self.cm.create_case(
            case_number="OTHER-CASE-001",
            case_name="Other Case",
            examiner_name="Other Examiner",
        )
        self.db.write_audit_entry(
            action="TEST_OTHER",
            entity_type="CASE",
            entity_id=other_case["case_id"],
        )
        trail = self.ic.get_audit_trail(self.case_id)
        entity_ids = {e["entity_id"] for e in trail}
        self.assertNotIn(other_case["case_id"], entity_ids)

    def test_compute_current_db_hash_non_empty(self):
        h = self.ic.compute_current_db_hash()
        self.assertTrue(len(h) == 64)

    def test_verify_database_hash_correct(self):
        h = self.ic.compute_current_db_hash()
        # Adding a write changes the hash
        self.db.write_audit_entry("TEST", "CASE", "fake-id")
        h2 = self.ic.compute_current_db_hash()
        # Old hash no longer matches
        self.assertFalse(self.ic.verify_database_hash(h))
        # New hash matches
        self.assertTrue(self.ic.verify_database_hash(h2))


if __name__ == "__main__":
    unittest.main()
