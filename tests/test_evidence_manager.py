"""
Tests for chainofcustody.evidence_manager.EvidenceManager

Author: Edward Marez
License: MIT
"""

import os
import tempfile
import unittest

from chainofcustody.database import DatabaseManager
from chainofcustody.case_manager import CaseManager
from chainofcustody.evidence_manager import EvidenceManager, EvidenceNotFoundError, EVIDENCE_TYPES


class TestEvidenceManagerBase(unittest.TestCase):
    """Base class that sets up a temp DB, a case, and an EvidenceManager."""

    def setUp(self):
        self.tmp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp_db.close()
        self.db = DatabaseManager(self.tmp_db.name)
        self.cm = CaseManager(self.db)
        self.em = EvidenceManager(self.db)

        # Create a test case
        self.case = self.cm.create_case(
            case_number="TEST-EV-001",
            case_name="Evidence Manager Test Case",
            examiner_name="Edward Marez",
            examiner_badge="TEST-001",
            agency="Test Agency",
        )
        self.case_id = self.case["case_id"]

        # Create a temporary evidence file
        self.tmp_ev = tempfile.NamedTemporaryFile(delete=False, suffix=".dd")
        self.tmp_ev.write(b"Simulated disk image content" * 1000)
        self.tmp_ev.close()
        self.ev_path = self.tmp_ev.name

    def tearDown(self):
        if os.path.exists(self.tmp_db.name):
            os.unlink(self.tmp_db.name)
        if os.path.exists(self.ev_path):
            os.unlink(self.ev_path)

    def _register(self, **kwargs):
        """Helper to register evidence with sensible defaults."""
        defaults = dict(
            case_id=self.case_id,
            description="Test evidence item",
            evidence_type="DISK_IMAGE",
            acquisition_method="Test acquisition",
            current_custodian="Edward Marez",
            compute_file_hashes=False,
        )
        defaults.update(kwargs)
        return self.em.register_evidence(**defaults)


class TestEvidenceRegistration(TestEvidenceManagerBase):

    def test_register_basic(self):
        """Basic registration should return a valid evidence dict."""
        ev = self._register()
        self.assertIn("evidence_id", ev)
        self.assertIn("evidence_number", ev)
        self.assertEqual(ev["evidence_type"], "DISK_IMAGE")
        self.assertEqual(ev["current_custodian"], "Edward Marez")
        self.assertEqual(ev["status"], "IN_CUSTODY")

    def test_evidence_number_sequential(self):
        """Evidence numbers must be assigned sequentially per case."""
        ev1 = self._register(description="First evidence item")
        ev2 = self._register(description="Second evidence item")
        ev3 = self._register(description="Third evidence item")
        self.assertEqual(ev1["evidence_number"], "EV-001")
        self.assertEqual(ev2["evidence_number"], "EV-002")
        self.assertEqual(ev3["evidence_number"], "EV-003")

    def test_evidence_numbers_independent_per_case(self):
        """Evidence numbering should restart at EV-001 for each case."""
        case2 = self.cm.create_case(
            case_number="TEST-EV-002",
            case_name="Second Test Case",
            examiner_name="Another Examiner",
        )
        ev_case1 = self._register(description="Case 1 evidence")
        ev_case2 = self.em.register_evidence(
            case_id=case2["case_id"],
            description="Case 2 evidence",
            evidence_type="FILE",
            acquisition_method="Manual",
            current_custodian="Another Examiner",
            compute_file_hashes=False,
        )
        self.assertEqual(ev_case1["evidence_number"], "EV-001")
        self.assertEqual(ev_case2["evidence_number"], "EV-001")

    def test_hash_computation_with_file(self):
        """Hash computation should work when a valid file path is provided."""
        ev = self.em.register_evidence(
            case_id=self.case_id,
            description="Evidence with hashes",
            evidence_type="DISK_IMAGE",
            acquisition_method="FTK Imager",
            current_custodian="Edward Marez",
            file_path=self.ev_path,
            compute_file_hashes=True,
        )
        self.assertIsNotNone(ev["md5_hash"])
        self.assertIsNotNone(ev["sha1_hash"])
        self.assertIsNotNone(ev["sha256_hash"])
        self.assertIsNotNone(ev["file_size"])
        self.assertGreater(ev["file_size"], 0)

    def test_no_hashes_without_file(self):
        """Evidence registered without a file should have no hash values."""
        ev = self._register()
        self.assertIsNone(ev["md5_hash"])
        self.assertIsNone(ev["sha1_hash"])
        self.assertIsNone(ev["sha256_hash"])

    def test_invalid_evidence_type_raises(self):
        with self.assertRaises(ValueError):
            self._register(evidence_type="INVALID_TYPE")

    def test_nonexistent_file_raises(self):
        with self.assertRaises(FileNotFoundError):
            self.em.register_evidence(
                case_id=self.case_id,
                description="Bad path",
                evidence_type="FILE",
                acquisition_method="Manual",
                current_custodian="E. Marez",
                file_path="/nonexistent/evidence.dd",
                compute_file_hashes=True,
            )

    def test_all_evidence_types_valid(self):
        """Every EVIDENCE_TYPES value should be accepted."""
        for i, ev_type in enumerate(EVIDENCE_TYPES):
            ev = self._register(
                description=f"Test {ev_type}",
                evidence_type=ev_type,
            )
            self.assertEqual(ev["evidence_type"], ev_type)


class TestEvidenceRetrieval(TestEvidenceManagerBase):

    def test_get_evidence_by_id(self):
        ev = self._register()
        retrieved = self.em.get_evidence(ev["evidence_id"])
        self.assertEqual(retrieved["evidence_id"], ev["evidence_id"])

    def test_get_evidence_not_found(self):
        from chainofcustody.utils import generate_uuid
        with self.assertRaises(EvidenceNotFoundError):
            self.em.get_evidence(generate_uuid())

    def test_get_evidence_by_number(self):
        ev = self._register()
        retrieved = self.em.get_evidence_by_number(self.case_id, ev["evidence_number"])
        self.assertEqual(retrieved["evidence_id"], ev["evidence_id"])

    def test_get_evidence_by_number_not_found(self):
        with self.assertRaises(EvidenceNotFoundError):
            self.em.get_evidence_by_number(self.case_id, "EV-999")

    def test_list_evidence_returns_all(self):
        n = 5
        for i in range(n):
            self._register(description=f"Item {i}")
        items = self.em.list_evidence(self.case_id)
        self.assertEqual(len(items), n)

    def test_list_evidence_ordered_by_number(self):
        for i in range(3):
            self._register(description=f"Item {i}")
        items = self.em.list_evidence(self.case_id)
        numbers = [item["evidence_number"] for item in items]
        self.assertEqual(numbers, sorted(numbers))

    def test_list_evidence_empty_case(self):
        case2 = self.cm.create_case(
            case_number="EMPTY-CASE-001",
            case_name="Empty Case",
            examiner_name="E. Marez",
        )
        items = self.em.list_evidence(case2["case_id"])
        self.assertEqual(items, [])


class TestEvidenceUpdates(TestEvidenceManagerBase):

    def test_update_custodian(self):
        ev = self._register()
        updated = self.em.update_custodian(ev["evidence_id"], "Jane Smith")
        self.assertEqual(updated["current_custodian"], "Jane Smith")

    def test_update_status_valid(self):
        ev = self._register()
        updated = self.em.update_status(ev["evidence_id"], "CHECKED_OUT")
        self.assertEqual(updated["status"], "CHECKED_OUT")

    def test_update_status_invalid_raises(self):
        ev = self._register()
        with self.assertRaises(ValueError):
            self.em.update_status(ev["evidence_id"], "NONEXISTENT_STATUS")

    def test_update_storage_location(self):
        ev = self._register()
        updated = self.em.update_storage_location(ev["evidence_id"], "Locker B, Shelf 2")
        self.assertEqual(updated["storage_location"], "Locker B, Shelf 2")

    def test_update_hashes(self):
        ev = self._register()
        updated = self.em.update_hashes(
            ev["evidence_id"],
            md5="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            sha1="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            sha256="c" * 64,
            file_size=9999,
        )
        self.assertEqual(updated["md5_hash"], "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        self.assertEqual(updated["sha256_hash"], "c" * 64)
        self.assertEqual(updated["file_size"], 9999)


if __name__ == "__main__":
    unittest.main()
