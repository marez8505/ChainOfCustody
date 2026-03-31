"""
ChainOfCustody — Digital Evidence Chain of Custody Management System.

A production-quality forensic evidence management system designed for
federal law enforcement and digital forensics professionals.

Supports:
  - Multi-case evidence tracking with full metadata
  - Forensic hash computation and verification (MD5, SHA-1, SHA-256)
  - Tamper-evident custody event logging with cryptographic hash chains
  - Court-ready HTML report generation
  - SQLite database with integrity verification

Author: Edward Marez
License: MIT
"""

__version__ = "1.0.0"
__author__ = "Edward Marez"
__license__ = "MIT"

from .database import DatabaseManager
from .case_manager import CaseManager
from .evidence_manager import EvidenceManager
from .custody_tracker import CustodyTracker
from .integrity_checker import IntegrityChecker
from .report_generator import ReportGenerator
from .hash_verifier import compute_hashes, verify_file_integrity


def create_system(db_path: str) -> tuple:
    """
    Convenience factory: create and wire all system components.

    Returns:
        (db, case_manager, evidence_manager, custody_tracker,
         integrity_checker, report_generator)
    """
    db = DatabaseManager(db_path)
    case_mgr = CaseManager(db)
    ev_mgr = EvidenceManager(db)
    ct = CustodyTracker(db, ev_mgr)
    ic = IntegrityChecker(db)
    rg = ReportGenerator(db, case_mgr, ev_mgr, ct, ic)
    return db, case_mgr, ev_mgr, ct, ic, rg


__all__ = [
    "DatabaseManager",
    "CaseManager",
    "EvidenceManager",
    "CustodyTracker",
    "IntegrityChecker",
    "ReportGenerator",
    "compute_hashes",
    "verify_file_integrity",
    "create_system",
]
