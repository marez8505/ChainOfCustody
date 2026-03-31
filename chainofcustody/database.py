"""
SQLite Database Manager for ChainOfCustody.

Handles schema creation, migrations, connection management, and database-level
integrity verification.  All tables use UUIDs as primary keys and ISO 8601
timestamps stored as TEXT for portability and readability.

Author: Edward Marez
License: MIT
"""

import sqlite3
import os
import hashlib
import json
from contextlib import contextmanager
from pathlib import Path
from typing import Optional

from .utils import utc_now, generate_uuid

# Current schema version — increment on any structural change.
SCHEMA_VERSION = 1

DDL_STATEMENTS = [
    """
    CREATE TABLE IF NOT EXISTS schema_meta (
        key   TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS cases (
        case_id        TEXT PRIMARY KEY,
        case_number    TEXT UNIQUE NOT NULL,
        case_name      TEXT NOT NULL,
        examiner_name  TEXT NOT NULL,
        examiner_badge TEXT,
        agency         TEXT,
        created_at     TEXT NOT NULL,
        status         TEXT DEFAULT 'OPEN',
        description    TEXT,
        classification TEXT DEFAULT 'UNCLASSIFIED',
        notes          TEXT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS evidence (
        evidence_id        TEXT PRIMARY KEY,
        case_id            TEXT NOT NULL REFERENCES cases(case_id),
        evidence_number    TEXT NOT NULL,
        description        TEXT NOT NULL,
        evidence_type      TEXT NOT NULL,
        source_device      TEXT,
        acquisition_method TEXT,
        acquisition_date   TEXT NOT NULL,
        original_location  TEXT,
        file_path          TEXT,
        file_size          INTEGER,
        md5_hash           TEXT,
        sha1_hash          TEXT,
        sha256_hash        TEXT,
        current_custodian  TEXT NOT NULL,
        storage_location   TEXT,
        status             TEXT DEFAULT 'IN_CUSTODY',
        created_at         TEXT NOT NULL,
        UNIQUE(case_id, evidence_number)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS custody_events (
        event_id          TEXT PRIMARY KEY,
        evidence_id       TEXT NOT NULL REFERENCES evidence(evidence_id),
        event_type        TEXT NOT NULL,
        from_custodian    TEXT,
        to_custodian      TEXT,
        timestamp         TEXT NOT NULL,
        location          TEXT,
        reason            TEXT NOT NULL,
        verification_hash TEXT,
        hash_verified     INTEGER,
        notes             TEXT,
        signature         TEXT,
        chain_hash        TEXT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS audit_log (
        log_id      TEXT PRIMARY KEY,
        timestamp   TEXT NOT NULL,
        action      TEXT NOT NULL,
        entity_type TEXT NOT NULL,
        entity_id   TEXT NOT NULL,
        details     TEXT,
        db_hash     TEXT
    )
    """,
    # Indexes for common query patterns
    "CREATE INDEX IF NOT EXISTS idx_evidence_case ON evidence(case_id)",
    "CREATE INDEX IF NOT EXISTS idx_events_evidence ON custody_events(evidence_id)",
    "CREATE INDEX IF NOT EXISTS idx_audit_entity ON audit_log(entity_id)",
    "CREATE INDEX IF NOT EXISTS idx_events_type ON custody_events(event_type)",
]


class DatabaseManager:
    """
    Manages the SQLite database connection and schema lifecycle.

    Usage:
        db = DatabaseManager("/path/to/evidence.db")
        with db.connection() as conn:
            conn.execute("SELECT ...")
    """

    def __init__(self, db_path: str):
        self.db_path = str(Path(db_path).resolve())
        self._ensure_directory()
        self._initialize()

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    @contextmanager
    def connection(self):
        """
        Yield a SQLite connection with WAL mode and foreign key enforcement.

        The connection is committed on clean exit or rolled back on exception.
        Row factory is set to sqlite3.Row for dict-style column access.
        """
        conn = sqlite3.connect(self.db_path, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def execute(self, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
        """Execute a single statement and return all rows."""
        with self.connection() as conn:
            cursor = conn.execute(sql, params)
            return cursor.fetchall()

    def insert(self, sql: str, params: tuple = ()) -> Optional[int]:
        """Execute an INSERT statement and return lastrowid."""
        with self.connection() as conn:
            cursor = conn.execute(sql, params)
            return cursor.lastrowid

    def current_db_hash(self) -> str:
        """
        Compute SHA-256 of the database file at this instant.

        Because SQLite flushes WAL on connection close, we open and close a
        connection with a checkpoint before hashing.
        """
        # Force WAL checkpoint so file reflects latest state
        try:
            conn = sqlite3.connect(self.db_path, timeout=10)
            conn.execute("PRAGMA wal_checkpoint(FULL)")
            conn.close()
        except sqlite3.Error:
            pass

        sha256 = hashlib.sha256()
        try:
            with open(self.db_path, "rb") as fh:
                while True:
                    chunk = fh.read(8 * 1024 * 1024)
                    if not chunk:
                        break
                    sha256.update(chunk)
            return sha256.hexdigest()
        except (IOError, OSError):
            return ""

    def write_audit_entry(
        self,
        action: str,
        entity_type: str,
        entity_id: str,
        details: Optional[dict] = None,
    ) -> str:
        """
        Write a tamper-evident audit log entry.

        Each entry captures a hash of the database at the moment of writing,
        making it detectable if the database is modified externally.

        Returns:
            The new log_id UUID.
        """
        log_id = generate_uuid()
        timestamp = utc_now()
        db_hash = self.current_db_hash()
        details_str = json.dumps(details, default=str) if details else None

        with self.connection() as conn:
            conn.execute(
                """
                INSERT INTO audit_log
                    (log_id, timestamp, action, entity_type, entity_id, details, db_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (log_id, timestamp, action, entity_type, entity_id, details_str, db_hash),
            )
        return log_id

    def get_audit_log(self, entity_id: Optional[str] = None) -> list[sqlite3.Row]:
        """Retrieve audit log entries, optionally filtered by entity_id."""
        if entity_id:
            return self.execute(
                "SELECT * FROM audit_log WHERE entity_id = ? ORDER BY timestamp ASC",
                (entity_id,),
            )
        return self.execute("SELECT * FROM audit_log ORDER BY timestamp ASC")

    # ------------------------------------------------------------------
    # Schema lifecycle
    # ------------------------------------------------------------------

    def _ensure_directory(self) -> None:
        directory = os.path.dirname(self.db_path)
        if directory:
            os.makedirs(directory, exist_ok=True)

    def _initialize(self) -> None:
        """Create tables and set schema version if this is a new database."""
        with self.connection() as conn:
            for ddl in DDL_STATEMENTS:
                conn.execute(ddl)

            # Record schema version if not already set
            row = conn.execute(
                "SELECT value FROM schema_meta WHERE key = 'schema_version'"
            ).fetchone()
            if row is None:
                conn.execute(
                    "INSERT INTO schema_meta (key, value) VALUES ('schema_version', ?)",
                    (str(SCHEMA_VERSION),),
                )
                conn.execute(
                    "INSERT INTO schema_meta (key, value) VALUES ('created_at', ?)",
                    (utc_now(),),
                )

    def get_schema_version(self) -> int:
        rows = self.execute(
            "SELECT value FROM schema_meta WHERE key = 'schema_version'"
        )
        return int(rows[0]["value"]) if rows else 0

    def get_stats(self) -> dict:
        """Return basic database statistics."""
        cases = self.execute("SELECT COUNT(*) AS n FROM cases")[0]["n"]
        evidence = self.execute("SELECT COUNT(*) AS n FROM evidence")[0]["n"]
        events = self.execute("SELECT COUNT(*) AS n FROM custody_events")[0]["n"]
        audit = self.execute("SELECT COUNT(*) AS n FROM audit_log")[0]["n"]
        file_size = os.path.getsize(self.db_path) if os.path.exists(self.db_path) else 0
        return {
            "cases": cases,
            "evidence_items": evidence,
            "custody_events": events,
            "audit_entries": audit,
            "db_file_size_bytes": file_size,
            "db_path": self.db_path,
            "schema_version": self.get_schema_version(),
        }
