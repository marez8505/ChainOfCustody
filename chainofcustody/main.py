"""
ChainOfCustody CLI — Digital Evidence Chain of Custody Management System.

Commands:
    init-case     Create a new investigation case
    add-evidence  Register a new evidence item
    transfer      Transfer custody of evidence
    checkout      Check evidence out for analysis
    return-ev     Return evidence to storage
    analysis      Log analysis start/end
    verify        Verify evidence integrity
    report        Generate court-ready HTML reports
    audit         Display audit trail
    list-cases    List all cases
    list-evidence List evidence in a case
    show-case     Show full case details
    show-evidence Show full evidence details
    demo          Create a complete sample case with full custody chain

Usage:
    python -m chainofcustody <command> [options]

Author: Edward Marez
License: MIT
"""

import argparse
import json
import os
import sys
import tempfile
import time
from pathlib import Path

from . import create_system
from .case_manager import DuplicateCaseError, CaseNotFoundError
from .evidence_manager import EvidenceNotFoundError
from .utils import format_timestamp, human_file_size, utc_now


# ── Default database path ──────────────────────────────────────────────────
DEFAULT_DB = os.environ.get("COC_DB", "chainofcustody.db")


# ── ANSI color helpers ─────────────────────────────────────────────────────
def _supports_color() -> bool:
    return sys.stdout.isatty() and os.name != "nt"


RESET = "\033[0m" if _supports_color() else ""
BOLD  = "\033[1m" if _supports_color() else ""
RED   = "\033[31m" if _supports_color() else ""
GREEN = "\033[32m" if _supports_color() else ""
YELLOW= "\033[33m" if _supports_color() else ""
CYAN  = "\033[36m" if _supports_color() else ""
GRAY  = "\033[90m" if _supports_color() else ""
WHITE = "\033[97m" if _supports_color() else ""


def ok(msg: str) -> None:
    print(f"{GREEN}✔{RESET}  {msg}")


def err(msg: str) -> None:
    print(f"{RED}✖{RESET}  {msg}", file=sys.stderr)


def info(msg: str) -> None:
    print(f"{CYAN}ℹ{RESET}  {msg}")


def warn(msg: str) -> None:
    print(f"{YELLOW}⚠{RESET}  {msg}")


def header(title: str) -> None:
    width = 70
    print()
    print(f"{BOLD}{WHITE}{'═' * width}{RESET}")
    print(f"{BOLD}{WHITE}  {title}{RESET}")
    print(f"{BOLD}{WHITE}{'═' * width}{RESET}")


def subheader(title: str) -> None:
    print(f"\n{BOLD}{CYAN}── {title} {'─' * max(0, 60 - len(title))}{RESET}")


def kv(key: str, value: str, indent: int = 4) -> None:
    pad = " " * indent
    print(f"{pad}{GRAY}{key:<24}{RESET}{value}")


# ── Shared argument setup ──────────────────────────────────────────────────

def add_db_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--db", default=DEFAULT_DB,
        help=f"Path to ChainOfCustody SQLite database (default: {DEFAULT_DB})"
    )


# ── Command handlers ────────────────────────────────────────────────────────

def cmd_init_case(args: argparse.Namespace) -> int:
    db, cm, em, ct, ic, rg = create_system(args.db)
    try:
        case = cm.create_case(
            case_number=args.number,
            case_name=args.name,
            examiner_name=args.examiner,
            examiner_badge=args.badge,
            agency=args.agency,
            description=args.description,
            classification=args.classification,
            notes=args.notes,
        )
    except DuplicateCaseError as exc:
        err(str(exc))
        return 1

    header("Case Created Successfully")
    kv("Case ID (UUID)", case["case_id"])
    kv("Case Number", case["case_number"])
    kv("Case Name", case["case_name"])
    kv("Lead Examiner", case["examiner_name"])
    if case["examiner_badge"]:
        kv("Badge / ID", case["examiner_badge"])
    if case["agency"]:
        kv("Agency", case["agency"])
    kv("Status", case["status"])
    kv("Classification", case["classification"])
    kv("Created At", format_timestamp(case["created_at"]))
    print()
    ok(f"Case {case['case_number']} initialized in database: {args.db}")
    return 0


def cmd_add_evidence(args: argparse.Namespace) -> int:
    db, cm, em, ct, ic, rg = create_system(args.db)

    # Resolve case
    try:
        case = cm.get_case_by_number(args.case)
    except CaseNotFoundError as exc:
        err(str(exc))
        return 1

    # Compute hashes info
    compute_hashes = True
    if args.file and not os.path.isfile(args.file):
        warn(f"File not found at path '{args.file}' — registering without hashes.")
        compute_hashes = False

    header("Registering Evidence")
    if args.file:
        info(f"Computing forensic hashes for: {args.file}")

    try:
        evidence = em.register_evidence(
            case_id=case["case_id"],
            description=args.description,
            evidence_type=args.type,
            acquisition_method=args.method or "Manual Collection",
            current_custodian=args.custodian or case["examiner_name"],
            file_path=args.file if (args.file and os.path.isfile(args.file)) else None,
            source_device=args.source,
            original_location=args.location,
            storage_location=args.storage,
            notes=args.notes,
            compute_file_hashes=compute_hashes,
        )
    except (ValueError, FileNotFoundError) as exc:
        err(str(exc))
        return 1

    # Log acquisition event
    ct.log_acquisition(
        evidence_id=evidence["evidence_id"],
        custodian=evidence["current_custodian"],
        location=args.storage or "Evidence Locker",
        reason=f"Initial acquisition via {evidence['acquisition_method']}",
        notes=args.notes,
    )

    print()
    kv("Evidence Number", evidence["evidence_number"])
    kv("Evidence ID", evidence["evidence_id"])
    kv("Description", evidence["description"])
    kv("Type", evidence["evidence_type"])
    kv("Custodian", evidence["current_custodian"])
    if evidence["source_device"]:
        kv("Source Device", evidence["source_device"])
    if evidence["acquisition_method"]:
        kv("Acquisition Method", evidence["acquisition_method"])
    if evidence["file_size"]:
        kv("File Size", human_file_size(evidence["file_size"]))
    if evidence["md5_hash"]:
        print()
        print(f"    {BOLD}Forensic Hashes:{RESET}")
        kv("MD5", evidence["md5_hash"], indent=6)
        kv("SHA-1", evidence["sha1_hash"], indent=6)
        kv("SHA-256", evidence["sha256_hash"], indent=6)
    print()
    ok(f"Evidence {evidence['evidence_number']} registered in case {args.case}")
    return 0


def cmd_transfer(args: argparse.Namespace) -> int:
    db, cm, em, ct, ic, rg = create_system(args.db)

    # Resolve evidence — by evidence number within case or by UUID
    evidence = _resolve_evidence(db, em, cm, args)
    if evidence is None:
        return 1

    from_custodian = evidence["current_custodian"]
    header(f"Custody Transfer — {evidence['evidence_number']}")
    kv("Evidence", f"{evidence['evidence_number']}: {evidence['description']}")
    kv("From", from_custodian)
    kv("To", args.to)
    kv("Location", args.location or "Not specified")
    kv("Reason", args.reason)

    event = ct.log_transfer(
        evidence_id=evidence["evidence_id"],
        from_custodian=from_custodian,
        to_custodian=args.to,
        location=args.location or "Not specified",
        reason=args.reason,
        notes=args.notes,
    )

    print()
    ok(f"Transfer logged. Event ID: {event['event_id']}")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    db, cm, em, ct, ic, rg = create_system(args.db)

    try:
        case = cm.get_case_by_number(args.case)
    except CaseNotFoundError as exc:
        err(str(exc))
        return 1

    header(f"Integrity Verification — {case['case_number']}")
    info("Running integrity checks on all evidence items...")
    print()

    report = ic.verify_case(case["case_id"])

    # Print per-evidence results
    for result in report.evidence_results:
        status_str = f"{GREEN}VERIFIED{RESET}" if result.is_clean else f"{RED}VIOLATION{RESET}"
        chain_str  = f"{GREEN}CHAIN OK{RESET}" if result.chain_valid else f"{RED}CHAIN BROKEN{RESET}"
        print(f"  {BOLD}{result.evidence_number}{RESET}  {result.description[:40]:<42} "
              f"{status_str}  {chain_str}  [{result.event_count} events]")
        if result.violations:
            for v in result.violations:
                print(f"       {RED}→{RESET} {v}")

    print()
    print(f"  {BOLD}Summary:{RESET}")
    kv("Total Evidence", str(report.total_evidence))
    kv("Verified", str(report.verified_count))
    kv("Violations", str(report.violation_count))
    kv("Overall Status", report.overall_status)
    kv("Database Hash", (report.db_hash or "N/A")[:64])

    print()
    if report.overall_status == "CLEAN":
        ok("All evidence integrity checks passed.")
    elif report.overall_status == "CHAIN_BROKEN":
        err("CRITICAL: Custody event hash chain is broken — possible tampering!")
        return 2
    else:
        err(f"{report.violation_count} integrity violation(s) detected.")
        return 2
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    db, cm, em, ct, ic, rg = create_system(args.db)

    try:
        case = cm.get_case_by_number(args.case)
    except CaseNotFoundError as exc:
        err(str(exc))
        return 1

    output_dir = args.output or f"./reports/{case['case_number']}"
    header(f"Generating Reports — {case['case_number']}")
    info(f"Output directory: {output_dir}")

    try:
        generated = rg.generate_all_reports(case["case_id"], output_dir)
    except ImportError as exc:
        err(str(exc))
        return 1

    print()
    for path in generated:
        ok(f"Generated: {path}")
    print()
    info("Open the HTML files in a browser and use Print → Save as PDF for court submission.")
    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    db, cm, em, ct, ic, rg = create_system(args.db)

    try:
        case = cm.get_case_by_number(args.case)
    except CaseNotFoundError as exc:
        err(str(exc))
        return 1

    header(f"Audit Trail — {case['case_number']}")
    entries = ic.get_audit_trail(case["case_id"])

    if not entries:
        info("No audit entries found.")
        return 0

    limit = args.limit or 50
    display = entries[-limit:]
    print(f"  Showing last {len(display)} of {len(entries)} audit entries.\n")

    for entry in display:
        ts = format_timestamp(entry["timestamp"])
        print(f"  {GRAY}{ts}{RESET}  {CYAN}{entry['action']:<30}{RESET}  "
              f"{YELLOW}{entry['entity_type']:<16}{RESET}  "
              f"{entry['entity_id'][:36]}")
        if entry.get("details") and args.verbose:
            print(f"    {GRAY}{entry['details']}{RESET}")

    print()
    ok(f"{len(entries)} total audit entries for case {case['case_number']}")
    return 0


def cmd_list_cases(args: argparse.Namespace) -> int:
    db, cm, em, ct, ic, rg = create_system(args.db)
    cases = cm.list_cases()

    if not cases:
        info("No cases found. Use 'init-case' to create one.")
        return 0

    header(f"All Cases ({len(cases)} total)")
    print(f"  {'Number':<20} {'Name':<30} {'Examiner':<20} {'Status':<10} {'Agency'}")
    print(f"  {'─'*20} {'─'*30} {'─'*20} {'─'*10} {'─'*20}")
    for case in cases:
        print(
            f"  {case['case_number']:<20} "
            f"{case['case_name'][:29]:<30} "
            f"{case['examiner_name'][:19]:<20} "
            f"{case['status']:<10} "
            f"{case['agency'] or '—'}"
        )
    print()
    return 0


def cmd_list_evidence(args: argparse.Namespace) -> int:
    db, cm, em, ct, ic, rg = create_system(args.db)

    try:
        case = cm.get_case_by_number(args.case)
    except CaseNotFoundError as exc:
        err(str(exc))
        return 1

    evidence_items = em.list_evidence(case["case_id"])
    if not evidence_items:
        info(f"No evidence items in case {args.case}.")
        return 0

    header(f"Evidence — Case {case['case_number']}: {case['case_name']}")
    print(f"  {'#':<8} {'Description':<35} {'Type':<18} {'Custodian':<22} {'Status'}")
    print(f"  {'─'*8} {'─'*35} {'─'*18} {'─'*22} {'─'*15}")
    for ev in evidence_items:
        print(
            f"  {ev['evidence_number']:<8} "
            f"{ev['description'][:34]:<35} "
            f"{ev['evidence_type'][:17]:<18} "
            f"{ev['current_custodian'][:21]:<22} "
            f"{ev['status']}"
        )
    print()
    return 0


def cmd_show_evidence(args: argparse.Namespace) -> int:
    db, cm, em, ct, ic, rg = create_system(args.db)

    evidence = _resolve_evidence(db, em, cm, args)
    if evidence is None:
        return 1

    case = cm.get_case(evidence["case_id"])
    events = ct.get_custody_chain(evidence["evidence_id"])
    ir = ic.verify_evidence(evidence["evidence_id"])

    header(f"Evidence Detail — {evidence['evidence_number']}")

    subheader("Identification")
    kv("Evidence Number", evidence["evidence_number"])
    kv("Evidence ID", evidence["evidence_id"])
    kv("Description", evidence["description"])
    kv("Type", evidence["evidence_type"])
    kv("Status", evidence["status"])
    kv("Current Custodian", evidence["current_custodian"])
    if evidence["storage_location"]:
        kv("Storage Location", evidence["storage_location"])

    subheader("Acquisition")
    kv("Source Device", evidence["source_device"] or "N/A")
    kv("Method", evidence["acquisition_method"] or "N/A")
    kv("Date", format_timestamp(evidence["acquisition_date"]))
    kv("Original Location", evidence["original_location"] or "N/A")

    if evidence["md5_hash"]:
        subheader("Forensic Hashes (Acquisition)")
        kv("MD5", evidence["md5_hash"])
        kv("SHA-1", evidence["sha1_hash"])
        kv("SHA-256", evidence["sha256_hash"])
        if evidence["file_size"]:
            kv("File Size", human_file_size(evidence["file_size"]))

    subheader(f"Integrity Status")
    hash_status = f"{GREEN}VERIFIED{RESET}" if ir.hash_verified else f"{YELLOW}UNCHECKED{RESET}"
    chain_status = f"{GREEN}VALID{RESET}" if ir.chain_valid else f"{RED}BROKEN{RESET}"
    kv("Hash Verification", hash_status)
    kv("Event Chain", chain_status)
    if ir.violations:
        for v in ir.violations:
            print(f"       {RED}→{RESET} {v}")

    subheader(f"Custody Chain ({len(events)} events)")
    for i, ev in enumerate(events, 1):
        ts = format_timestamp(ev["timestamp"])
        frm = ev["from_custodian"] or "—"
        to  = ev["to_custodian"] or "—"
        print(f"    {GRAY}{i:>3}.{RESET} {CYAN}{ev['event_type']:<16}{RESET} "
              f"{ts}  {frm} → {to}")
        print(f"          {GRAY}Reason: {ev['reason']}{RESET}")
        if ev.get("notes"):
            print(f"          {GRAY}Notes:  {ev['notes']}{RESET}")

    print()
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    """
    Create a complete sample case with multiple evidence items and a full
    custody chain, then generate all reports.

    This demonstrates the system's capabilities for portfolio review.
    """
    import tempfile
    import hashlib

    header("ChainOfCustody — Demo Mode")
    info("Creating sample federal forensics case: Operation Dark Web")
    print()

    db, cm, em, ct, ic, rg = create_system(args.db)

    # ── Step 1: Create Case ──────────────────────────────────────────────
    print(f"{BOLD}[1/7] Initializing case...{RESET}")
    try:
        case = cm.create_case(
            case_number="2026-CF-0042",
            case_name="Operation Dark Web",
            examiner_name="Edward Marez",
            examiner_badge="FBI-7741",
            agency="FBI CART (Computer Analysis and Response Team)",
            description=(
                "Investigation into alleged dark web marketplace operating within the district. "
                "Subjects acquired and distributed controlled substances via encrypted channels. "
                "Digital forensic examination of seized computing devices ordered by AUSA."
            ),
            classification="UNCLASSIFIED",
            notes="Priority case — trial date set. All evidence must be court-ready.",
        )
        ok(f"Case created: {case['case_number']} — {case['case_name']}")
    except DuplicateCaseError:
        case = cm.get_case_by_number("2026-CF-0042")
        warn("Case already exists — using existing case.")

    case_id = case["case_id"]

    # ── Step 2: Create Temporary Evidence Files ──────────────────────────
    print(f"\n{BOLD}[2/7] Creating sample evidence files...{RESET}")
    tmp_dir = tempfile.mkdtemp(prefix="coc_demo_")

    # Disk image (simulated 4 MB)
    disk_image_path = os.path.join(tmp_dir, "suspect_drive.dd")
    with open(disk_image_path, "wb") as f:
        # Write a realistic-looking header then random-ish data
        f.write(b"MZ" + b"\x90" * 512)  # Fake MBR signature
        f.write(os.urandom(4 * 1024 * 1024 - 514))
    ok(f"Sample disk image: {disk_image_path} ({human_file_size(os.path.getsize(disk_image_path))})")

    # Chat log document
    chat_log_path = os.path.join(tmp_dir, "chat_logs_decrypted.txt")
    with open(chat_log_path, "w") as f:
        f.write(
            "=== DECRYPTED CHAT LOG — EXHIBIT A ===\n"
            "Timestamp: 2026-01-15 02:41:33 UTC\n"
            "User: d4rkn0de_777 → r3d_m4rk3t: '50 units ready for drop'\n"
            "Timestamp: 2026-01-15 02:42:01 UTC\n"
            "User: r3d_m4rk3t → d4rkn0de_777: 'confirmed. BTC escrow locked'\n"
            "[... 847 additional message records redacted for demo ...]\n"
        )
    ok(f"Sample chat log: {chat_log_path}")

    # Memory dump (simulated 1 MB)
    memory_dump_path = os.path.join(tmp_dir, "ram_dump_workstation2.mem")
    with open(memory_dump_path, "wb") as f:
        f.write(b"PAGE" + os.urandom(1 * 1024 * 1024 - 4))
    ok(f"Sample memory dump: {memory_dump_path}")

    # Mobile extraction
    mobile_extract_path = os.path.join(tmp_dir, "cellebrite_iphone13.ufdr")
    with open(mobile_extract_path, "wb") as f:
        f.write(b"UFDR" + os.urandom(512 * 1024))
    ok(f"Sample mobile extraction: {mobile_extract_path}")

    # ── Step 3: Register Evidence ────────────────────────────────────────
    print(f"\n{BOLD}[3/7] Registering evidence items with forensic hashes...{RESET}")

    ev1 = em.register_evidence(
        case_id=case_id,
        description="Suspect Laptop — Dell Latitude 5520 Primary Hard Drive (512 GB SSD)",
        evidence_type="DISK_IMAGE",
        acquisition_method="FTK Imager 4.7.1.2 (write-blocked via Tableau T356789iu)",
        current_custodian="Edward Marez",
        file_path=disk_image_path,
        source_device="Dell Latitude 5520, S/N: DL55-XYZ789, Asset #: FBI-LAP-0042",
        original_location="Residence of John Doe, 1234 Elm Street, Room 2B — Seized pursuant to SW #26-1234",
        storage_location="FBI CART Evidence Locker A, Shelf 3, Bay 12",
    )
    ok(f"Registered {ev1['evidence_number']}: {ev1['description'][:60]}")
    print(f"    {GRAY}MD5:    {ev1['md5_hash']}{RESET}")
    print(f"    {GRAY}SHA-1:  {ev1['sha1_hash']}{RESET}")
    print(f"    {GRAY}SHA-256:{ev1['sha256_hash']}{RESET}")

    ev2 = em.register_evidence(
        case_id=case_id,
        description="Decrypted Chat Logs — Signal Desktop Application (1,847 messages)",
        evidence_type="DOCUMENT",
        acquisition_method="Manual extraction from FTK Imager case file",
        current_custodian="Edward Marez",
        file_path=chat_log_path,
        source_device="Dell Latitude 5520 (same as EV-001)",
        original_location="Extracted from disk image EV-001, path: /Users/jdoe/AppData/Signal/",
        storage_location="FBI CART Evidence Locker A, Shelf 3, Bay 12",
    )
    ok(f"Registered {ev2['evidence_number']}: {ev2['description'][:60]}")

    ev3 = em.register_evidence(
        case_id=case_id,
        description="RAM Dump — Forensic Workstation #2 (captured live during search)",
        evidence_type="MEMORY_DUMP",
        acquisition_method="DumpIt v3.5 — Live Memory Capture",
        current_custodian="Edward Marez",
        file_path=memory_dump_path,
        source_device="Custom Mining Rig, No S/N, MAC: 00:1A:2B:3C:4D:5E",
        original_location="Basement server room, 1234 Elm Street — active at time of warrant execution",
        storage_location="FBI CART Evidence Locker A, Shelf 3, Bay 13",
    )
    ok(f"Registered {ev3['evidence_number']}: {ev3['description'][:60]}")

    ev4 = em.register_evidence(
        case_id=case_id,
        description="iPhone 13 Pro — UFED Cellebrite Full File System Extraction",
        evidence_type="MOBILE_EXTRACT",
        acquisition_method="Cellebrite UFED 4PC v7.69.0.150 — Full File System",
        current_custodian="Edward Marez",
        file_path=mobile_extract_path,
        source_device="Apple iPhone 13 Pro, IMEI: 358240051111110, S/N: DNQXYZ123456",
        original_location="Subject's person at time of arrest — John Doe DOB: 1990-01-01",
        storage_location="FBI CART Evidence Locker A, Shelf 4, Bay 1",
    )
    ok(f"Registered {ev4['evidence_number']}: {ev4['description'][:60]}")

    # ── Step 4: Log Acquisition Events ──────────────────────────────────
    print(f"\n{BOLD}[4/7] Logging acquisition custody events...{RESET}")

    for ev in [ev1, ev2, ev3, ev4]:
        ct.log_acquisition(
            evidence_id=ev["evidence_id"],
            custodian="Edward Marez",
            location="FBI Field Office — Digital Forensics Lab, Room 114",
            reason=f"Initial forensic acquisition of {ev['evidence_number']} per search warrant #26-1234",
        )
        ok(f"  Acquisition event logged for {ev['evidence_number']}")

    # ── Step 5: Simulate Full Custody Chain ─────────────────────────────
    print(f"\n{BOLD}[5/7] Simulating complete custody chain...{RESET}")
    time.sleep(0.05)  # Ensure distinct timestamps

    # Transfer EV-001 to senior examiner
    ct.log_transfer(
        evidence_id=ev1["evidence_id"],
        from_custodian="Edward Marez",
        to_custodian="Dr. Sarah Chen",
        location="FBI CART Lab — Advanced Analysis Wing",
        reason="Transfer to Senior Forensic Examiner for deep-dive disk analysis",
    )
    ok("  EV-001 transferred to Dr. Sarah Chen (Senior Examiner)")
    time.sleep(0.05)

    # Check out EV-001 for analysis
    ct.log_checkout(
        evidence_id=ev1["evidence_id"],
        custodian="Dr. Sarah Chen",
        location="FBI CART Lab — FTK Workstation 4",
        reason="Beginning forensic analysis of disk image — file system reconstruction",
    )
    ok("  EV-001 checked out for analysis")
    time.sleep(0.05)

    # Analysis start
    ct.log_analysis_start(
        evidence_id=ev1["evidence_id"],
        analyst="Dr. Sarah Chen",
        location="FBI CART Lab — FTK Workstation 4",
        reason="Full forensic examination: deleted file recovery, timeline analysis, artifact extraction",
    )
    ok("  EV-001 analysis started")
    time.sleep(0.05)

    # Verification during analysis
    ct.log_verification(
        evidence_id=ev1["evidence_id"],
        custodian="Dr. Sarah Chen",
        location="FBI CART Lab — FTK Workstation 4",
        reason="Mid-analysis integrity check — confirming evidence has not been modified",
        file_path=disk_image_path,
    )
    ok("  EV-001 verification check passed")
    time.sleep(0.05)

    # Analysis end
    ct.log_analysis_end(
        evidence_id=ev1["evidence_id"],
        analyst="Dr. Sarah Chen",
        location="FBI CART Lab — FTK Workstation 4",
        reason="Forensic analysis complete — 23 exhibits extracted, timeline reconstructed",
        notes="See FE Report #2026-CF-0042-A for full findings",
    )
    ok("  EV-001 analysis completed")
    time.sleep(0.05)

    # Return to storage
    ct.log_return(
        evidence_id=ev1["evidence_id"],
        from_custodian="Dr. Sarah Chen",
        to_custodian="Edward Marez",
        location="FBI CART Evidence Locker A, Shelf 3, Bay 12",
        reason="Returning evidence to primary custodian after analysis",
    )
    ok("  EV-001 returned to storage")
    time.sleep(0.05)

    # Checkout EV-002 for trial prep
    ct.log_checkout(
        evidence_id=ev2["evidence_id"],
        custodian="AUSA Maria Rodriguez",
        location="U.S. Attorney's Office, Room 312",
        reason="Trial preparation — attorney review of chat log exhibits",
    )
    ok("  EV-002 checked out by AUSA")
    time.sleep(0.05)

    ct.log_return(
        evidence_id=ev2["evidence_id"],
        from_custodian="AUSA Maria Rodriguez",
        to_custodian="Edward Marez",
        location="FBI CART Evidence Locker A, Shelf 3, Bay 12",
        reason="Evidence returned by AUSA after trial preparation review",
    )
    ok("  EV-002 returned after attorney review")
    time.sleep(0.05)

    # Analysis start on mobile
    ct.log_checkout(
        evidence_id=ev4["evidence_id"],
        custodian="Special Agent Liu Wei",
        location="FBI CART Lab — Mobile Analysis Station",
        reason="Mobile device analysis — cryptocurrency wallet, messaging apps, GPS data",
    )
    ct.log_analysis_start(
        evidence_id=ev4["evidence_id"],
        analyst="Special Agent Liu Wei",
        location="FBI CART Lab — Mobile Analysis Station",
        reason="Cellebrite Physical Analyzer — full artifact extraction from UFDR",
    )
    ok("  EV-004 mobile analysis started")
    time.sleep(0.05)

    ct.log_analysis_end(
        evidence_id=ev4["evidence_id"],
        analyst="Special Agent Liu Wei",
        location="FBI CART Lab — Mobile Analysis Station",
        reason="Mobile analysis complete — 47 BTC transactions identified, 1,200+ messages extracted",
    )
    ct.log_return(
        evidence_id=ev4["evidence_id"],
        from_custodian="Special Agent Liu Wei",
        to_custodian="Edward Marez",
        location="FBI CART Evidence Locker A, Shelf 4, Bay 1",
        reason="Evidence returned to primary custodian after mobile analysis",
    )
    ok("  EV-004 mobile analysis complete and returned")
    time.sleep(0.05)

    # Final storage with verification
    for ev in [ev1, ev2, ev3, ev4]:
        ct.log_storage(
            evidence_id=ev["evidence_id"],
            custodian="Edward Marez",
            location="FBI CART Secure Evidence Vault — Climate Controlled",
            reason="Long-term secure storage pending trial — case #2026-CF-0042",
        )

    ok("  All evidence items stored in secure vault")

    # ── Step 6: Integrity Verification ──────────────────────────────────
    print(f"\n{BOLD}[6/7] Running full integrity verification...{RESET}")
    report = ic.verify_case(case_id)

    for result in report.evidence_results:
        status_icon = f"{GREEN}✔{RESET}" if result.is_clean else f"{RED}✖{RESET}"
        chain_icon  = f"{GREEN}✔{RESET}" if result.chain_valid else f"{RED}✖{RESET}"
        print(f"    {result.evidence_number}: Hash {status_icon}  Chain {chain_icon}  "
              f"({result.event_count} custody events)")

    print(f"\n  Overall Status: {GREEN if report.overall_status == 'CLEAN' else RED}"
          f"{report.overall_status}{RESET}")
    ok("Integrity verification passed" if report.overall_status == "CLEAN"
       else "Integrity violations detected")

    # ── Step 7: Generate Reports ─────────────────────────────────────────
    print(f"\n{BOLD}[7/7] Generating court-ready HTML reports...{RESET}")
    output_dir = args.output or "./demo_reports/2026-CF-0042"

    try:
        generated = rg.generate_all_reports(case_id, output_dir)
        for path in generated:
            ok(f"  Report: {path}")
    except ImportError as exc:
        warn(f"Jinja2 not available — skipping report generation. ({exc})")
        warn("Install with: pip install jinja2")

    # ── Summary ──────────────────────────────────────────────────────────
    stats = db.get_stats()
    header("Demo Complete — Summary")
    kv("Database", args.db)
    kv("Total Cases", str(stats["cases"]))
    kv("Total Evidence Items", str(stats["evidence_items"]))
    kv("Total Custody Events", str(stats["custody_events"]))
    kv("Total Audit Entries", str(stats["audit_entries"]))
    kv("Database Hash (SHA-256)", (db.current_db_hash() or "N/A")[:64])
    print()
    ok("Demo case fully created. Open the HTML reports in a browser to see court-ready output.")
    info("Tip: python -m chainofcustody list-cases")
    info("Tip: python -m chainofcustody verify --case 2026-CF-0042")
    return 0


# ── Shared evidence resolution helper ─────────────────────────────────────

def _resolve_evidence(db, em, cm, args):
    """
    Resolve an evidence item from args.  Supports:
      --evidence EV-001 --case 2026-CF-0042
      --evidence <uuid>
    """
    if hasattr(args, 'evidence_id') and args.evidence_id:
        # UUID lookup
        try:
            return em.get_evidence(args.evidence_id)
        except EvidenceNotFoundError as exc:
            err(str(exc))
            return None

    # Number + case
    if not hasattr(args, 'evidence') or not args.evidence:
        err("Specify --evidence EV-001 (and --case CASE_NUMBER for number lookup)")
        return None

    ev_num = args.evidence.upper()
    if not ev_num.startswith("EV-"):
        # Try UUID
        try:
            return em.get_evidence(ev_num)
        except EvidenceNotFoundError:
            pass

    if not hasattr(args, 'case') or not args.case:
        err("Use --case CASE_NUMBER with --evidence EV-001")
        return None

    try:
        case = cm.get_case_by_number(args.case)
    except CaseNotFoundError as exc:
        err(str(exc))
        return None

    try:
        return em.get_evidence_by_number(case["case_id"], ev_num)
    except EvidenceNotFoundError as exc:
        err(str(exc))
        return None


# ── CLI entry point ────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="chainofcustody",
        description=(
            "ChainOfCustody — Digital Evidence Chain of Custody Management System\n"
            "Author: Edward Marez | MIT License"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    add_db_arg(parser)
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    # ── init-case ──────────────────────────────────────────────────────
    p_init = sub.add_parser("init-case", help="Create a new investigation case")
    p_init.add_argument("--number", required=True, help="Unique case number (e.g. 2026-CF-0042)")
    p_init.add_argument("--name", required=True, help="Case name (e.g. 'Operation Dark Web')")
    p_init.add_argument("--examiner", required=True, help="Lead examiner full name")
    p_init.add_argument("--badge", help="Examiner badge/employee ID")
    p_init.add_argument("--agency", help="Investigating agency (e.g. 'FBI CART')")
    p_init.add_argument("--description", help="Case description")
    p_init.add_argument("--classification", default="UNCLASSIFIED",
                        choices=["UNCLASSIFIED","CUI","CONFIDENTIAL","SECRET","TOP SECRET"])
    p_init.add_argument("--notes", help="Additional notes")
    add_db_arg(p_init)

    # ── add-evidence ───────────────────────────────────────────────────
    p_ev = sub.add_parser("add-evidence", help="Register a new evidence item")
    p_ev.add_argument("--case", required=True, help="Case number")
    p_ev.add_argument("--description", required=True, help="Evidence description")
    p_ev.add_argument("--type", required=True,
                      choices=["DISK_IMAGE","FILE","MEMORY_DUMP","NETWORK_CAPTURE",
                               "MOBILE_EXTRACT","DOCUMENT","VIDEO","AUDIO","OTHER"],
                      help="Evidence type")
    p_ev.add_argument("--file", help="Path to evidence file (for hash computation)")
    p_ev.add_argument("--source", help="Source device description (make, model, S/N)")
    p_ev.add_argument("--method", help="Acquisition method (e.g. 'FTK Imager 4.7')")
    p_ev.add_argument("--location", help="Original location where evidence was found")
    p_ev.add_argument("--storage", help="Current storage location")
    p_ev.add_argument("--custodian", help="Initial custodian (default: case examiner)")
    p_ev.add_argument("--notes", help="Additional notes")
    add_db_arg(p_ev)

    # ── transfer ────────────────────────────────────────────────────────
    p_tr = sub.add_parser("transfer", help="Transfer custody of evidence")
    p_tr.add_argument("--evidence", required=True, help="Evidence number (e.g. EV-001) or UUID")
    p_tr.add_argument("--case", help="Case number (required with evidence number)")
    p_tr.add_argument("--to", required=True, help="Name of new custodian")
    p_tr.add_argument("--reason", required=True, help="Reason for transfer")
    p_tr.add_argument("--location", help="Transfer location")
    p_tr.add_argument("--notes", help="Additional notes")
    add_db_arg(p_tr)

    # ── verify ─────────────────────────────────────────────────────────
    p_ver = sub.add_parser("verify", help="Verify evidence integrity for a case")
    p_ver.add_argument("--case", required=True, help="Case number")
    add_db_arg(p_ver)

    # ── report ─────────────────────────────────────────────────────────
    p_rep = sub.add_parser("report", help="Generate court-ready HTML reports")
    p_rep.add_argument("--case", required=True, help="Case number")
    p_rep.add_argument("--format", default="html", choices=["html"], help="Output format (html)")
    p_rep.add_argument("--output", help="Output directory (default: ./reports/<case_number>)")
    add_db_arg(p_rep)

    # ── audit ──────────────────────────────────────────────────────────
    p_aud = sub.add_parser("audit", help="Display tamper-evident audit trail")
    p_aud.add_argument("--case", required=True, help="Case number")
    p_aud.add_argument("--limit", type=int, default=50, help="Max entries to show")
    p_aud.add_argument("--verbose", action="store_true", help="Show full details")
    add_db_arg(p_aud)

    # ── list-cases ─────────────────────────────────────────────────────
    p_lc = sub.add_parser("list-cases", help="List all cases")
    add_db_arg(p_lc)

    # ── list-evidence ──────────────────────────────────────────────────
    p_le = sub.add_parser("list-evidence", help="List evidence in a case")
    p_le.add_argument("--case", required=True, help="Case number")
    add_db_arg(p_le)

    # ── show-evidence ──────────────────────────────────────────────────
    p_se = sub.add_parser("show-evidence", help="Show full evidence details and custody chain")
    p_se.add_argument("--evidence", required=True, help="Evidence number (EV-001) or UUID")
    p_se.add_argument("--case", help="Case number (required with evidence number)")
    add_db_arg(p_se)

    # ── demo ───────────────────────────────────────────────────────────
    p_demo = sub.add_parser(
        "demo",
        help="Create a complete sample case with full custody chain and generate reports"
    )
    p_demo.add_argument("--output", help="Output directory for reports (default: ./demo_reports/)")
    add_db_arg(p_demo)

    return parser


COMMAND_MAP = {
    "init-case":     cmd_init_case,
    "add-evidence":  cmd_add_evidence,
    "transfer":      cmd_transfer,
    "verify":        cmd_verify,
    "report":        cmd_report,
    "audit":         cmd_audit,
    "list-cases":    cmd_list_cases,
    "list-evidence": cmd_list_evidence,
    "show-evidence": cmd_show_evidence,
    "demo":          cmd_demo,
}


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return 0

    handler = COMMAND_MAP.get(args.command)
    if handler is None:
        err(f"Unknown command: {args.command}")
        return 1

    try:
        return handler(args)
    except KeyboardInterrupt:
        print()
        err("Interrupted.")
        return 130
    except Exception as exc:
        err(f"Unexpected error: {exc}")
        if os.environ.get("COC_DEBUG"):
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
