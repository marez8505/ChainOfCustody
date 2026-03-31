"""
Report Generator for ChainOfCustody.

Renders court-ready HTML reports using Jinja2 templates.  Output files are
suitable for printing to PDF from any modern browser.

Author: Edward Marez
License: MIT
"""

import os
from pathlib import Path
from typing import Optional

try:
    from jinja2 import Environment, FileSystemLoader, select_autoescape
    JINJA2_AVAILABLE = True
except ImportError:
    JINJA2_AVAILABLE = False

from .database import DatabaseManager
from .case_manager import CaseManager
from .evidence_manager import EvidenceManager
from .custody_tracker import CustodyTracker
from .integrity_checker import IntegrityChecker
from .utils import utc_now, human_file_size, format_timestamp


# ── Jinja2 template directory ──────────────────────────────────────────────
TEMPLATE_DIR = Path(__file__).parent / "form_templates"


def _make_jinja_env() -> "Environment":
    """Create a configured Jinja2 environment with custom filters."""
    if not JINJA2_AVAILABLE:
        raise ImportError(
            "Jinja2 is required for report generation. "
            "Install it with: pip install jinja2"
        )
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=select_autoescape(["html"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    # Custom filters
    env.filters["format_ts"] = format_timestamp
    env.filters["human_size"] = human_file_size
    return env


class ReportGenerator:
    """
    Generates court-admissible HTML reports from the ChainOfCustody database.

    Three report types:
      - chain_of_custody_form : Sequential custody chain for one or all evidence items
      - evidence_report        : Full detail report for a single evidence item
      - case_summary           : Overview of the entire case with integrity status
    """

    def __init__(
        self,
        db: DatabaseManager,
        case_manager: CaseManager,
        evidence_manager: EvidenceManager,
        custody_tracker: CustodyTracker,
        integrity_checker: IntegrityChecker,
    ):
        self.db = db
        self.cm = case_manager
        self.em = evidence_manager
        self.ct = custody_tracker
        self.ic = integrity_checker
        self._env: Optional["Environment"] = None

    @property
    def env(self) -> "Environment":
        if self._env is None:
            self._env = _make_jinja_env()
        return self._env

    # ------------------------------------------------------------------
    # Report: Chain of Custody Form
    # ------------------------------------------------------------------

    def generate_custody_form(
        self,
        case_id: str,
        output_path: str,
    ) -> str:
        """
        Generate the official Chain of Custody form for a case.

        Includes all evidence items and their full custody chains.

        Args:
            case_id:     UUID of the case.
            output_path: Directory or file path for the output HTML.

        Returns:
            Absolute path to the generated HTML file.
        """
        case = self.cm.get_case(case_id)
        evidence_items = self.em.list_evidence(case_id)

        # Build custody chains dict: evidence_id → list of events
        custody_chains: dict = {}
        for ev in evidence_items:
            custody_chains[ev["evidence_id"]] = self.ct.get_custody_chain(
                ev["evidence_id"]
            )

        generated_at = utc_now()

        template = self.env.get_template("custody_form.html")
        html = template.render(
            case=case,
            evidence_items=evidence_items,
            custody_chains=custody_chains,
            generated_at=generated_at,
        )

        out_file = self._resolve_output_path(output_path, f"custody_form_{case['case_number']}.html")
        self._write_html(out_file, html)
        return out_file

    # ------------------------------------------------------------------
    # Report: Individual Evidence Report
    # ------------------------------------------------------------------

    def generate_evidence_report(
        self,
        evidence_id: str,
        output_path: str,
    ) -> str:
        """
        Generate a detailed report for a single evidence item.

        Args:
            evidence_id: UUID of the evidence item.
            output_path: Directory or file path for the output HTML.

        Returns:
            Absolute path to the generated HTML file.
        """
        evidence = self.em.get_evidence(evidence_id)
        case = self.cm.get_case(evidence["case_id"])
        custody_events = self.ct.get_custody_chain(evidence_id)
        integrity_result = self.ic.verify_evidence(evidence_id)
        generated_at = utc_now()

        template = self.env.get_template("evidence_report.html")
        html = template.render(
            case=case,
            evidence=evidence,
            custody_events=custody_events,
            integrity_result=integrity_result,
            generated_at=generated_at,
        )

        safe_num = evidence["evidence_number"].replace("-", "_")
        out_file = self._resolve_output_path(
            output_path, f"evidence_report_{case['case_number']}_{safe_num}.html"
        )
        self._write_html(out_file, html)
        return out_file

    # ------------------------------------------------------------------
    # Report: Case Summary
    # ------------------------------------------------------------------

    def generate_case_summary(
        self,
        case_id: str,
        output_path: str,
    ) -> str:
        """
        Generate a comprehensive case summary with integrity status for all evidence.

        Args:
            case_id:     UUID of the case.
            output_path: Directory or file path for the output HTML.

        Returns:
            Absolute path to the generated HTML file.
        """
        case = self.cm.get_case(case_id)
        summary = self.cm.get_case_summary(case_id)
        evidence_items = self.em.list_evidence(case_id)
        integrity_report = self.ic.verify_case(case_id)
        audit_entries = self.ic.get_audit_trail(case_id)
        db_stats = self.db.get_stats()
        generated_at = utc_now()

        # Build fast lookup: evidence_id → integrity result
        integrity_by_id = {
            r.evidence_id: r for r in integrity_report.evidence_results
        }

        template = self.env.get_template("case_summary.html")
        html = template.render(
            case=case,
            summary=summary,
            evidence_items=evidence_items,
            integrity_report=integrity_report,
            integrity_by_id=integrity_by_id,
            audit_entries=audit_entries,
            db_stats=db_stats,
            generated_at=generated_at,
        )

        out_file = self._resolve_output_path(
            output_path, f"case_summary_{case['case_number']}.html"
        )
        self._write_html(out_file, html)
        return out_file

    # ------------------------------------------------------------------
    # Generate all reports for a case
    # ------------------------------------------------------------------

    def generate_all_reports(self, case_id: str, output_dir: str) -> list[str]:
        """
        Generate all three report types for a case.

        Returns:
            List of paths to generated HTML files.
        """
        os.makedirs(output_dir, exist_ok=True)
        generated = []

        generated.append(self.generate_custody_form(case_id, output_dir))
        generated.append(self.generate_case_summary(case_id, output_dir))

        evidence_items = self.em.list_evidence(case_id)
        for ev in evidence_items:
            generated.append(self.generate_evidence_report(ev["evidence_id"], output_dir))

        return generated

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_output_path(output_path: str, default_filename: str) -> str:
        """
        Resolve the output path to a full file path.

        If output_path is a directory, append default_filename.
        If it ends with .html, use it as-is.
        """
        path = Path(output_path)
        if path.suffix.lower() == ".html":
            path.parent.mkdir(parents=True, exist_ok=True)
            return str(path.resolve())
        else:
            path.mkdir(parents=True, exist_ok=True)
            # Sanitize case number for filesystem
            safe_name = default_filename.replace("/", "_").replace("\\", "_")
            return str((path / safe_name).resolve())

    @staticmethod
    def _write_html(file_path: str, html: str) -> None:
        """Write HTML content to a file (UTF-8)."""
        with open(file_path, "w", encoding="utf-8") as fh:
            fh.write(html)
