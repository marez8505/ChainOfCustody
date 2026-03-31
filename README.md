# ChainOfCustody

**Digital Evidence Chain of Custody Management System**

Author: Edward Marez | License: MIT | Python 3.10+

---

## Overview

ChainOfCustody is a production-quality Python system for managing the complete lifecycle of digital evidence in federal forensic investigations. It implements the strict chain of custody requirements mandated by the **Federal Rules of Evidence (FRE)** and agency-specific standards used by organizations like the FBI CART, Secret Service ECF, DOJ, and DOD.

Chain of custody is not a formality — it is the legal foundation that determines whether digital evidence is **admissible in court**. A single documentation gap can result in evidence suppression, case dismissal, and criminal charges against the investigator. This system prevents those failures.

---

## Why Chain of Custody Matters

### Legal Basis

Under **FRE Rule 901(b)(9)** and **FRE Rule 1002** (the Best Evidence Rule), digital evidence must be shown to be authentic — that it is what it purports to be — and that the original has not been altered. Courts require:

1. **Unbroken custody documentation**: Every person who touched the evidence, when, why, and where
2. **Cryptographic integrity verification**: Hash values computed at acquisition must match at every subsequent examination
3. **Tamper-evident records**: Any modification to evidence or documentation must be immediately detectable

The **ACPO Good Practice Guide for Digital Evidence** (widely adopted in US federal proceedings) requires that:
> *"No action taken by law enforcement agencies, persons employed within those agencies or their agents should change data which may subsequently be relied upon in court."*

A chain of custody form that cannot account for a single period of evidence possession can result in:
- Evidence deemed inadmissible under FRE 901
- Fruit-of-the-poisonous-tree suppression of derived evidence
- Potential 18 U.S.C. § 1519 charges (obstruction of justice) against the examiner

### Federal Agency Standards

| Agency | Program | Standard |
|---|---|---|
| FBI | CART (Computer Analysis and Response Team) | FBI CART Operating Manual |
| Secret Service | ECF (Electronic Crimes Forensics) | USSS Forensic Lab Procedures |
| DOJ | CCIPS | DOJ Searching and Seizing Computers Guide |
| DHS | CISA Forensics | NIST SP 800-86 |
| DoD | DCSA | DoD Cyber Crime Center (DC3) Procedures |

All of these share the same core requirement: **every custody transfer must be documented, time-stamped, signed, and integrity-verified.**

---

## Hash Verification and Evidence Integrity

### Why Three Hash Algorithms?

ChainOfCustody computes **MD5**, **SHA-1**, and **SHA-256** for every evidence file:

- **MD5** (128-bit): Legacy compatibility — still required by many court exhibits and older tools (FTK, EnCase)
- **SHA-1** (160-bit): Standard until ~2010, still accepted in federal courts for existing evidence
- **SHA-256** (256-bit): Current gold standard — collision-resistant, recommended by NIST FIPS 180-4

Any single-algorithm collision (extremely rare in practice) does not compromise the case because the other two algorithms provide independent verification.

### Hash Chain Verification

Beyond file hashes, ChainOfCustody implements a **cryptographic hash chain** across custody events:

```
GENESIS
   ↓
Event 1 hash = SHA-256(event1_fields + "GENESIS")
   ↓
Event 2 hash = SHA-256(event2_fields + Event_1_hash)
   ↓
Event 3 hash = SHA-256(event3_fields + Event_2_hash)
```

This creates a tamper-evident audit trail similar to blockchain technology. **If any event is modified or deleted**, all subsequent hashes in the chain will fail verification, immediately revealing the tampering.

---

## Installation

```bash
git clone https://github.com/edwardmarez/chainofcustody.git
cd ChainOfCustody
pip install -r requirements.txt
pip install -e .
```

**Requirements**: Python 3.10+ | Jinja2 (for HTML reports) | SQLite (stdlib)

---

## Quick Start

### Initialize a Case

```bash
python -m chainofcustody init-case \
  --number "2026-CF-0042" \
  --name "Operation Dark Web" \
  --examiner "Edward Marez" \
  --badge "FBI-7741" \
  --agency "FBI CART"
```

### Register Evidence

```bash
python -m chainofcustody add-evidence \
  --case "2026-CF-0042" \
  --file ./suspect_drive.dd \
  --type DISK_IMAGE \
  --description "Suspect Laptop — Dell Latitude 5520 Primary SSD" \
  --source "Dell Latitude 5520, S/N: XYZ789" \
  --method "FTK Imager 4.7.1.2" \
  --location "Residence of John Doe, Room 2B — SW #26-1234" \
  --storage "FBI CART Evidence Locker A, Shelf 3, Bay 12"
```

Output:
```
══════════════════════════════════════════════════════════════════════
  Registering Evidence
══════════════════════════════════════════════════════════════════════
ℹ  Computing forensic hashes for: ./suspect_drive.dd

    Evidence Number     EV-001
    Evidence ID         a7f3e2d1-...
    Description         Suspect Laptop — Dell Latitude 5520 Primary SSD
    Type                DISK_IMAGE
    Custodian           Edward Marez
    Source Device       Dell Latitude 5520, S/N: XYZ789
    Acquisition Method  FTK Imager 4.7.1.2

    Forensic Hashes:
      MD5      d41d8cd98f00b204e9800998ecf8427e
      SHA-1    da39a3ee5e6b4b0d3255bfef95601890afd80709
      SHA-256  e3b0c44298fc1c149afbf4c8996fb924...

✔  Evidence EV-001 registered in case 2026-CF-0042
```

### Transfer Custody

```bash
python -m chainofcustody transfer \
  --evidence EV-001 \
  --case "2026-CF-0042" \
  --to "Dr. Sarah Chen" \
  --reason "Transfer to senior examiner for deep analysis" \
  --location "FBI CART Advanced Analysis Wing"
```

### Verify Integrity

```bash
python -m chainofcustody verify --case "2026-CF-0042"
```

Output:
```
══════════════════════════════════════════════════════════════════════
  Integrity Verification — 2026-CF-0042
══════════════════════════════════════════════════════════════════════
ℹ  Running integrity checks on all evidence items...

  EV-001  Suspect Laptop — Dell Latitude...     VERIFIED  CHAIN OK  [7 events]
  EV-002  Decrypted Chat Logs...                VERIFIED  CHAIN OK  [4 events]
  EV-003  RAM Dump — Forensic Workstation #2   VERIFIED  CHAIN OK  [2 events]
  EV-004  iPhone 13 Pro — Cellebrite...         VERIFIED  CHAIN OK  [5 events]

  Summary:
    Total Evidence          4
    Verified                4
    Violations              0
    Overall Status          CLEAN
    Database Hash           a3f7b2c1...

✔  All evidence integrity checks passed.
```

### Generate Court-Ready Reports

```bash
python -m chainofcustody report \
  --case "2026-CF-0042" \
  --output ./case_reports/
```

Generates three HTML files suitable for printing as PDF:
- `custody_form_2026-CF-0042.html` — Official chain of custody form
- `case_summary_2026-CF-0042.html` — Full case summary with integrity status
- `evidence_report_2026-CF-0042_EV_001.html` — Per-evidence detailed reports

### View Audit Trail

```bash
python -m chainofcustody audit --case "2026-CF-0042" --verbose
```

### Run the Full Demo

```bash
python -m chainofcustody demo
```

Creates a complete "Operation Dark Web" case with 4 evidence items, a full custody chain (acquisition → transfer → checkout → analysis → return → storage), verifies integrity, and generates all reports.

---

## Database Schema

All data is stored in a single SQLite database (`chainofcustody.db` by default, override with `--db` or `COC_DB` environment variable).

### Tables

```sql
-- Investigation cases
cases (case_id PK, case_number UNIQUE, case_name, examiner_name, examiner_badge,
        agency, created_at, status, description, classification, notes)

-- Evidence items
evidence (evidence_id PK, case_id FK→cases, evidence_number, description,
          evidence_type, source_device, acquisition_method, acquisition_date,
          original_location, file_path, file_size, md5_hash, sha1_hash,
          sha256_hash, current_custodian, storage_location, status, created_at)

-- Custody events (immutable)
custody_events (event_id PK, evidence_id FK→evidence, event_type,
                from_custodian, to_custodian, timestamp, location, reason,
                verification_hash, hash_verified, notes, signature, chain_hash)

-- Tamper-evident audit log
audit_log (log_id PK, timestamp, action, entity_type, entity_id, details, db_hash)
```

### Tamper Detection

Every audit log entry includes `db_hash` — the SHA-256 hash of the database file at the moment the entry was written. Any external modification to the database file (using a hex editor, SQLite browser, etc.) will cause the recorded `db_hash` values to no longer match the computed hash, immediately revealing tampering.

The custody event `chain_hash` creates a second layer: a cryptographic chain where each event incorporates the previous event's hash. Deleting or modifying any event breaks the chain.

### Evidence Status Lifecycle

```
IN_CUSTODY → CHECKED_OUT → IN_ANALYSIS → IN_CUSTODY → DISPOSED
                                        ↘ TRANSFERRED
```

### Event Types

| Event | Description |
|---|---|
| `ACQUISITION` | Initial forensic collection from source |
| `TRANSFER` | Change of custodian (signature required) |
| `CHECKOUT` | Evidence removed from secure storage |
| `RETURN` | Evidence returned to secure storage |
| `ANALYSIS_START` | Formal examination period begins |
| `ANALYSIS_END` | Formal examination period ends |
| `VERIFICATION` | Periodic hash integrity check |
| `STORAGE` | Evidence placed in long-term storage |
| `DISPOSAL` | Evidence destruction (authorization required) |

---

## Project Structure

```
ChainOfCustody/
├── chainofcustody/
│   ├── __init__.py              # Package init + create_system() factory
│   ├── __main__.py              # python -m chainofcustody entry point
│   ├── main.py                  # CLI: all commands + demo
│   ├── database.py              # SQLite manager, schema, audit log, integrity
│   ├── case_manager.py          # Case CRUD and lifecycle
│   ├── evidence_manager.py      # Evidence registration, hash computation, updates
│   ├── custody_tracker.py       # Custody event logging with hash chain
│   ├── hash_verifier.py         # MD5/SHA-1/SHA-256 computation and verification
│   ├── integrity_checker.py     # Case/evidence/chain/DB integrity verification
│   ├── report_generator.py      # HTML report rendering via Jinja2
│   ├── utils.py                 # UUID, timestamps, signatures, helpers
│   └── form_templates/
│       ├── custody_form.html    # Official chain of custody form
│       ├── evidence_report.html # Individual evidence detail report
│       └── case_summary.html    # Full case summary with integrity status
├── tests/
│   ├── test_database.py         # DatabaseManager tests (12 tests)
│   ├── test_hash_verifier.py    # Hash computation and verification tests (20 tests)
│   ├── test_evidence_manager.py # Evidence registration and retrieval tests (18 tests)
│   └── test_custody_tracker.py  # Custody events and integrity tests (18 tests)
├── requirements.txt             # jinja2 only (SQLite is stdlib)
├── setup.py                     # Package setup
├── LICENSE                      # MIT License
└── README.md                    # This file
```

---

## Running Tests

```bash
cd ChainOfCustody
python -m pytest tests/ -v
```

Or with coverage:

```bash
python -m pytest tests/ -v --cov=chainofcustody --cov-report=term-missing
```

All 68 tests pass without external dependencies beyond the standard library.

---

## Programmatic API

```python
from chainofcustody import create_system

db, case_mgr, ev_mgr, ct, ic, rg = create_system("./evidence.db")

# Create a case
case = case_mgr.create_case(
    case_number="2026-CF-0001",
    case_name="My Investigation",
    examiner_name="Edward Marez",
    agency="FBI CART",
)

# Register evidence with automatic hash computation
ev = ev_mgr.register_evidence(
    case_id=case["case_id"],
    description="Suspect's hard drive image",
    evidence_type="DISK_IMAGE",
    acquisition_method="FTK Imager",
    current_custodian="Edward Marez",
    file_path="./suspect.dd",
)
print(f"MD5: {ev['md5_hash']}")
print(f"SHA-256: {ev['sha256_hash']}")

# Log custody events
ct.log_acquisition(ev["evidence_id"], "Edward Marez", "Evidence Lab", "Initial acquisition")
ct.log_transfer(ev["evidence_id"], "Edward Marez", "Jane Smith", "Lab B", "Transfer for analysis")

# Verify integrity
report = ic.verify_case(case["case_id"])
print(f"Integrity: {report.overall_status}")  # "CLEAN"

# Generate reports
rg.generate_all_reports(case["case_id"], "./reports/")
```

---

## Federal Forensics Career Context

This project demonstrates competency in the core technical and legal requirements for federal digital forensics positions:

| Requirement | Implementation |
|---|---|
| Chain of custody documentation | Immutable custody event log with every custodian, timestamp, location |
| Forensic hash verification | MD5 + SHA-1 + SHA-256 at acquisition and every custody event |
| Tamper-evident records | Cryptographic hash chain across all events |
| Court-ready documentation | HTML reports styled for printing as formal court exhibits |
| Evidence lifecycle management | Full status tracking from acquisition through disposal |
| Multi-case management | Unlimited cases with independent evidence numbering |
| Database integrity | DB-level SHA-256 hash recorded in audit log |
| FRE compliance awareness | Authentication (901), Best Evidence (1002) requirements addressed |

---

## Security Notes

- All evidence file hashes are computed at acquisition and stored immutably
- Custody events cannot be deleted through the normal API — only the underlying SQLite file can be modified externally, which is detectable via the db_hash audit records
- The `chain_hash` field links custody events cryptographically — any deletion or modification of an event breaks the chain
- For production use, store the database on write-once media or a WORM-enabled storage system
- Consider encrypting the database at rest using SQLCipher for classified investigations

---

## License

MIT License — Copyright (c) 2026 Edward Marez

See `LICENSE` for the full text.
