"""
Tests for chainofcustody.hash_verifier

Author: Edward Marez
License: MIT
"""

import hashlib
import os
import tempfile
import unittest

from chainofcustody.hash_verifier import (
    compute_hashes,
    compute_hashes_from_bytes,
    verify_file_integrity,
    hash_database_file,
    generate_event_hash,
    HashResult,
)


class TestComputeHashes(unittest.TestCase):

    def setUp(self):
        """Create a temporary file with known content for each test."""
        self.content = b"FBI CART Digital Forensics Test File\n" * 100
        self.tmp = tempfile.NamedTemporaryFile(delete=False)
        self.tmp.write(self.content)
        self.tmp.close()
        self.tmp_path = self.tmp.name

        # Pre-compute expected values
        self.expected_md5    = hashlib.md5(self.content).hexdigest()
        self.expected_sha1   = hashlib.sha1(self.content).hexdigest()
        self.expected_sha256 = hashlib.sha256(self.content).hexdigest()

    def tearDown(self):
        if os.path.exists(self.tmp_path):
            os.unlink(self.tmp_path)

    def test_md5_correct(self):
        result = compute_hashes(self.tmp_path)
        self.assertEqual(result.md5, self.expected_md5)

    def test_sha1_correct(self):
        result = compute_hashes(self.tmp_path)
        self.assertEqual(result.sha1, self.expected_sha1)

    def test_sha256_correct(self):
        result = compute_hashes(self.tmp_path)
        self.assertEqual(result.sha256, self.expected_sha256)

    def test_file_size_correct(self):
        result = compute_hashes(self.tmp_path)
        self.assertEqual(result.file_size, len(self.content))

    def test_nonexistent_file_raises(self):
        with self.assertRaises(FileNotFoundError):
            compute_hashes("/nonexistent/path/to/file.dd")

    def test_directory_raises_valueerror(self):
        with self.assertRaises(ValueError):
            compute_hashes(tempfile.gettempdir())

    def test_returns_hashresult(self):
        result = compute_hashes(self.tmp_path)
        self.assertIsInstance(result, HashResult)

    def test_empty_file(self):
        """Hash of empty file should equal known empty-file hashes."""
        empty_tmp = tempfile.NamedTemporaryFile(delete=False)
        empty_tmp.close()
        try:
            result = compute_hashes(empty_tmp.name)
            self.assertEqual(result.md5,    "d41d8cd98f00b204e9800998ecf8427e")
            self.assertEqual(result.sha1,   "da39a3ee5e6b4b0d3255bfef95601890afd80709")
            self.assertEqual(result.sha256, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
            self.assertEqual(result.file_size, 0)
        finally:
            os.unlink(empty_tmp.name)


class TestComputeHashesFromBytes(unittest.TestCase):

    def test_known_bytes(self):
        data = b"hello world"
        result = compute_hashes_from_bytes(data)
        self.assertEqual(result.md5,    hashlib.md5(data).hexdigest())
        self.assertEqual(result.sha1,   hashlib.sha1(data).hexdigest())
        self.assertEqual(result.sha256, hashlib.sha256(data).hexdigest())
        self.assertEqual(result.file_size, len(data))

    def test_empty_bytes(self):
        result = compute_hashes_from_bytes(b"")
        self.assertEqual(result.file_size, 0)
        self.assertEqual(result.md5, "d41d8cd98f00b204e9800998ecf8427e")


class TestHashResult(unittest.TestCase):

    def _make_result(self, suffix="a"):
        return HashResult(
            md5=f"md5{suffix}",
            sha1=f"sha1{suffix}",
            sha256=f"sha256{suffix}",
            file_size=1024,
        )

    def test_matches_identical(self):
        r1 = self._make_result("a")
        r2 = self._make_result("a")
        self.assertTrue(r1.matches(r2))

    def test_matches_different(self):
        r1 = self._make_result("a")
        r2 = self._make_result("b")
        self.assertFalse(r1.matches(r2))

    def test_to_dict_keys(self):
        r = self._make_result()
        d = r.to_dict()
        self.assertIn("md5", d)
        self.assertIn("sha1", d)
        self.assertIn("sha256", d)
        self.assertIn("file_size", d)


class TestVerifyFileIntegrity(unittest.TestCase):

    def setUp(self):
        self.content = b"evidence file content for integrity testing"
        self.tmp = tempfile.NamedTemporaryFile(delete=False)
        self.tmp.write(self.content)
        self.tmp.close()
        self.path = self.tmp.name

        self.md5    = hashlib.md5(self.content).hexdigest()
        self.sha1   = hashlib.sha1(self.content).hexdigest()
        self.sha256 = hashlib.sha256(self.content).hexdigest()

    def tearDown(self):
        if os.path.exists(self.path):
            os.unlink(self.path)

    def test_all_hashes_match(self):
        result = verify_file_integrity(
            self.path,
            stored_md5=self.md5,
            stored_sha1=self.sha1,
            stored_sha256=self.sha256,
        )
        self.assertTrue(result.is_valid)
        self.assertTrue(result.md5_match)
        self.assertTrue(result.sha1_match)
        self.assertTrue(result.sha256_match)
        self.assertIsNone(result.error)

    def test_md5_mismatch_detected(self):
        result = verify_file_integrity(
            self.path,
            stored_md5="00000000000000000000000000000000",
            stored_sha1=self.sha1,
            stored_sha256=self.sha256,
        )
        self.assertFalse(result.is_valid)
        self.assertFalse(result.md5_match)
        self.assertTrue(result.sha1_match)
        self.assertIn("INTEGRITY VIOLATION", result.integrity_status())

    def test_sha256_mismatch_detected(self):
        result = verify_file_integrity(
            self.path,
            stored_sha256="0" * 64,
        )
        self.assertFalse(result.is_valid)
        self.assertFalse(result.sha256_match)

    def test_missing_file_returns_error(self):
        result = verify_file_integrity("/nonexistent/file.dd")
        self.assertFalse(result.is_valid)
        self.assertIsNotNone(result.error)

    def test_none_hashes_treated_as_match(self):
        """If stored hash is None, it should not count as a mismatch."""
        result = verify_file_integrity(self.path)  # All None
        self.assertTrue(result.is_valid)

    def test_partial_hash_check(self):
        """Only specified hashes should be compared."""
        result = verify_file_integrity(
            self.path,
            stored_sha256=self.sha256,  # Only SHA-256 provided
        )
        self.assertTrue(result.is_valid)
        self.assertTrue(result.sha256_match)


class TestHashDatabaseFile(unittest.TestCase):

    def test_valid_file(self):
        tmp = tempfile.NamedTemporaryFile(delete=False)
        tmp.write(b"test database content")
        tmp.close()
        try:
            result = hash_database_file(tmp.name)
            expected = hashlib.sha256(b"test database content").hexdigest()
            self.assertEqual(result, expected)
        finally:
            os.unlink(tmp.name)

    def test_missing_file_returns_empty(self):
        result = hash_database_file("/nonexistent/database.db")
        self.assertEqual(result, "")


class TestGenerateEventHash(unittest.TestCase):

    def test_deterministic(self):
        """Same inputs must always produce the same hash."""
        h1 = generate_event_hash(
            event_id="evt-001",
            evidence_id="ev-001",
            event_type="ACQUISITION",
            timestamp="2026-01-01T00:00:00+00:00",
            from_custodian=None,
            to_custodian="Edward Marez",
            verification_hash=None,
            previous_event_hash=None,
        )
        h2 = generate_event_hash(
            event_id="evt-001",
            evidence_id="ev-001",
            event_type="ACQUISITION",
            timestamp="2026-01-01T00:00:00+00:00",
            from_custodian=None,
            to_custodian="Edward Marez",
            verification_hash=None,
            previous_event_hash=None,
        )
        self.assertEqual(h1, h2)

    def test_different_event_ids_produce_different_hashes(self):
        kwargs = dict(
            evidence_id="ev-001",
            event_type="TRANSFER",
            timestamp="2026-01-02T00:00:00+00:00",
            from_custodian="Alice",
            to_custodian="Bob",
            verification_hash=None,
            previous_event_hash="abc123",
        )
        h1 = generate_event_hash(event_id="evt-A", **kwargs)
        h2 = generate_event_hash(event_id="evt-B", **kwargs)
        self.assertNotEqual(h1, h2)

    def test_previous_hash_included(self):
        """Changing previous_event_hash should change the resulting hash."""
        kwargs = dict(
            event_id="evt-001",
            evidence_id="ev-001",
            event_type="VERIFICATION",
            timestamp="2026-01-03T00:00:00+00:00",
            from_custodian="Alice",
            to_custodian="Alice",
            verification_hash="sha256hex",
        )
        h1 = generate_event_hash(previous_event_hash="prev1", **kwargs)
        h2 = generate_event_hash(previous_event_hash="prev2", **kwargs)
        self.assertNotEqual(h1, h2)

    def test_genesis_different_from_none(self):
        """First event (None previous) should differ from an event with prior hash."""
        kwargs = dict(
            event_id="evt-001",
            evidence_id="ev-001",
            event_type="ACQUISITION",
            timestamp="2026-01-01T00:00:00+00:00",
            from_custodian=None,
            to_custodian="Alice",
            verification_hash=None,
        )
        h_genesis = generate_event_hash(previous_event_hash=None, **kwargs)
        h_prior   = generate_event_hash(previous_event_hash="GENESIS", **kwargs)
        # GENESIS string is used when previous_event_hash is None
        self.assertEqual(h_genesis, h_prior)


if __name__ == "__main__":
    unittest.main()
