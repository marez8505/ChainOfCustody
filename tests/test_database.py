"""
Tests for chainofcustody.database.DatabaseManager

Author: Edward Marez
License: MIT
"""

import os
import tempfile
import unittest

from chainofcustody.database import DatabaseManager, SCHEMA_VERSION


class TestDatabaseManager(unittest.TestCase):

    def setUp(self):
        """Create a temporary database for each test."""
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.db_path = self.tmp.name
        self.db = DatabaseManager(self.db_path)

    def tearDown(self):
        """Remove the temporary database."""
        if os.path.exists(self.db_path):
            os.unlink(self.db_path)

    # ------------------------------------------------------------------
    # Schema initialization
    # ------------------------------------------------------------------

    def test_schema_created(self):
        """All expected tables must be created on first init."""
        tables = {
            row["name"]
            for row in self.db.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        self.assertIn("cases", tables)
        self.assertIn("evidence", tables)
        self.assertIn("custody_events", tables)
        self.assertIn("audit_log", tables)
        self.assertIn("schema_meta", tables)

    def test_schema_version(self):
        """Schema version should match the module constant."""
        self.assertEqual(self.db.get_schema_version(), SCHEMA_VERSION)

    def test_idempotent_init(self):
        """Re-initializing with the same file should not raise or duplicate meta rows."""
        db2 = DatabaseManager(self.db_path)
        self.assertEqual(db2.get_schema_version(), SCHEMA_VERSION)
        rows = db2.execute(
            "SELECT COUNT(*) AS n FROM schema_meta WHERE key='schema_version'"
        )
        self.assertEqual(rows[0]["n"], 1)

    # ------------------------------------------------------------------
    # Connection context manager
    # ------------------------------------------------------------------

    def test_connection_commit(self):
        """Data inserted inside connection() context is committed on success."""
        from chainofcustody.utils import generate_uuid, utc_now
        case_id = generate_uuid()
        with self.db.connection() as conn:
            conn.execute(
                """
                INSERT INTO cases
                    (case_id, case_number, case_name, examiner_name, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (case_id, "TEST-001", "Test Case", "Examiner A", utc_now()),
            )
        rows = self.db.execute(
            "SELECT * FROM cases WHERE case_id = ?", (case_id,)
        )
        self.assertEqual(len(rows), 1)

    def test_connection_rollback_on_error(self):
        """An exception inside connection() should roll back the transaction."""
        from chainofcustody.utils import generate_uuid, utc_now
        case_id = generate_uuid()
        try:
            with self.db.connection() as conn:
                conn.execute(
                    """
                    INSERT INTO cases
                        (case_id, case_number, case_name, examiner_name, created_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (case_id, "FAIL-001", "Should Roll Back", "Examiner B", utc_now()),
                )
                raise RuntimeError("Deliberate failure")
        except RuntimeError:
            pass
        rows = self.db.execute(
            "SELECT * FROM cases WHERE case_id = ?", (case_id,)
        )
        self.assertEqual(len(rows), 0, "Rolled-back row should not exist")

    # ------------------------------------------------------------------
    # Audit log
    # ------------------------------------------------------------------

    def test_write_audit_entry(self):
        """Audit entries should be written and retrievable."""
        from chainofcustody.utils import generate_uuid
        entity_id = generate_uuid()
        log_id = self.db.write_audit_entry(
            action="TEST_ACTION",
            entity_type="CASE",
            entity_id=entity_id,
            details={"key": "value"},
        )
        self.assertIsNotNone(log_id)
        entries = self.db.get_audit_log(entity_id)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["action"], "TEST_ACTION")
        self.assertEqual(entries[0]["entity_type"], "CASE")

    def test_audit_log_all(self):
        """Calling get_audit_log without entity_id returns all entries."""
        from chainofcustody.utils import generate_uuid
        for _ in range(3):
            self.db.write_audit_entry("ACTION", "CASE", generate_uuid())
        entries = self.db.get_audit_log()
        self.assertGreaterEqual(len(entries), 3)

    # ------------------------------------------------------------------
    # Database hash
    # ------------------------------------------------------------------

    def test_db_hash_non_empty(self):
        """current_db_hash() should return a non-empty hex string."""
        db_hash = self.db.current_db_hash()
        self.assertTrue(len(db_hash) == 64, f"Expected 64-char SHA-256, got: {db_hash!r}")

    def test_db_hash_changes_after_write(self):
        """Database hash should change after new data is written."""
        hash1 = self.db.current_db_hash()
        from chainofcustody.utils import generate_uuid, utc_now
        with self.db.connection() as conn:
            conn.execute(
                """
                INSERT INTO cases
                    (case_id, case_number, case_name, examiner_name, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (generate_uuid(), "HASH-CHG-001", "Hash Change Test", "E. Marez", utc_now()),
            )
        hash2 = self.db.current_db_hash()
        self.assertNotEqual(hash1, hash2)

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def test_get_stats_structure(self):
        """get_stats() must return a dict with expected keys."""
        stats = self.db.get_stats()
        for key in ("cases", "evidence_items", "custody_events", "audit_entries",
                    "db_file_size_bytes", "db_path", "schema_version"):
            self.assertIn(key, stats)

    def test_get_stats_initial_zeroes(self):
        """New database should report zero cases/evidence/events."""
        stats = self.db.get_stats()
        self.assertEqual(stats["cases"], 0)
        self.assertEqual(stats["evidence_items"], 0)
        self.assertEqual(stats["custody_events"], 0)

    # ------------------------------------------------------------------
    # Directory creation
    # ------------------------------------------------------------------

    def test_creates_nested_directory(self):
        """DatabaseManager should create nested directories for the DB path."""
        tmp_base = tempfile.mkdtemp()
        nested_path = os.path.join(tmp_base, "a", "b", "c", "evidence.db")
        db = DatabaseManager(nested_path)
        self.assertTrue(os.path.exists(nested_path))
        os.unlink(nested_path)
        import shutil
        shutil.rmtree(tmp_base, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
