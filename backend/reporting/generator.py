"""
backend/reporting/generator.py
Compiles normalized findings and execution records into client-ready VAPT reports.
"""

from collections import Counter
from datetime import datetime, timezone
from enum import Enum
import json
import logging
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from typing import List, Optional
from jinja2 import Environment, FileSystemLoader

from backend.models import AssessmentScope, Finding, Severity, ToolRun


logger = logging.getLogger(__name__)


class ReportGenerator:
    def __init__(self, template_dir: Optional[str] = None):
        if template_dir is None:
            template_dir = str(Path(__file__).parent)
        self.env = Environment(loader=FileSystemLoader(template_dir), autoescape=True)
        self.template = self.env.get_template("template.html")

    def generate_html_report(
        self,
        scope: AssessmentScope,
        findings: List[Finding],
        tool_runs: List[ToolRun],
        report_metadata: Optional[dict] = None,
    ) -> str:
        """Renders the HTML version of the required sections 7.1 to 7.6."""
        counts = Counter({s.value: 0 for s in Severity})
        for f in findings:
            counts[f.severity.value] += 1

        tools_used = sorted(list({r.tool_name for r in tool_runs}))

        rendered_html = self.template.render(
            target_scope=scope.authorized_targets,
            generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            findings=findings,
            tool_runs=tool_runs,
            tools_used=tools_used,
            tools_executed_summary=", ".join(tools_used) if tools_used else "None recorded",
            report_metadata=report_metadata or {},
            severity_counts=counts
        )
        return rendered_html

    def save_full_assessment_json(
        self,
        scope: AssessmentScope,
        findings: List[Finding],
        tool_runs: List[ToolRun],
        output_json_path: Optional[str] = None,
        metadata: Optional[dict] = None,
    ) -> str:
        """Save the complete scope, tool-run, and finding record as JSON."""
        if output_json_path is None:
            output_json_path = str(
                Path(__file__).resolve().parents[2] / "data" / "assessment_data.json"
            )

        json_path = Path(output_json_path).resolve()
        json_path.parent.mkdir(parents=True, exist_ok=True)
        record_metadata = {
            "system": "RedPencil VAPT Agent",
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }
        if metadata:
            record_metadata.update(metadata)

        serialized_tool_runs = self._serialize(tool_runs)
        executed_runs = [
            run
            for run in serialized_tool_runs
            if run.get("status") in {"RUNNING", "COMPLETED", "FAILED"}
        ]
        full_record = {
            "metadata": record_metadata,
            "scope": self._serialize(scope),
            "tools_executed_count": len(executed_runs),
            "tools_executed": executed_runs,
            "tool_runs_recorded_count": len(serialized_tool_runs),
            "tool_runs": serialized_tool_runs,
            "total_findings": len(findings),
            "findings": self._serialize(findings),
        }
        json_path.write_text(
            json.dumps(full_record, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        return str(json_path)

    @classmethod
    def _serialize(cls, value):
        """Convert Pydantic models and nested values into JSON-compatible data."""
        if hasattr(value, "model_dump"):
            return value.model_dump(mode="json")
        if isinstance(value, Enum):
            return value.value
        if isinstance(value, datetime):
            return value.isoformat()
        if isinstance(value, dict):
            return {key: cls._serialize(item) for key, item in value.items()}
        if isinstance(value, (list, tuple)):
            return [cls._serialize(item) for item in value]
        if hasattr(value, "__dict__"):
            return {
                key: cls._serialize(item)
                for key, item in vars(value).items()
                if not key.startswith("_")
            }
        return value

    def export_pdf(
        self,
        scope: AssessmentScope,
        findings: List[Finding],
        tool_runs: List[ToolRun],
        output_path: str,
        report_metadata: Optional[dict] = None,
        output_json_path: Optional[str] = None,
    ) -> str:
        """
        Export the report to PDF with a headless browser or WeasyPrint.

        The rendered HTML is retained beside the PDF and returned if neither
        renderer is available.
        """
        self.save_full_assessment_json(
            scope,
            findings,
            tool_runs,
            output_json_path=output_json_path,
            metadata=report_metadata,
        )
        html_content = self.generate_html_report(
            scope, findings, tool_runs, report_metadata=report_metadata
        )
        path = Path(output_path).resolve()
        pdf_path = path.with_suffix(".pdf")
        html_path = path.with_suffix(".html")
        path.parent.mkdir(parents=True, exist_ok=True)
        html_path.write_text(html_content, encoding="utf-8")

        browsers = self._find_browsers()
        if browsers:
            try:
                with tempfile.TemporaryDirectory(
                    prefix=".redpencil-report-", dir=path.parent
                ) as temp_directory:
                    temp_directory_path = Path(temp_directory)
                    temp_pdf = temp_directory_path / pdf_path.name
                    profile_path = temp_directory_path / "browser-profile"
                    command = [
                        str(browsers[0]),
                        "--headless",
                        "--disable-gpu",
                        "--no-pdf-header-footer",
                        f"--user-data-dir={profile_path}",
                        f"--print-to-pdf={temp_pdf}",
                        html_path.as_uri(),
                    ]
                    subprocess.run(
                        command,
                        check=True,
                        capture_output=True,
                        timeout=30,
                    )
                    if self._is_pdf(temp_pdf):
                        temp_pdf.replace(pdf_path)
                        return str(pdf_path)
                    logger.warning(
                        "Headless browser did not produce a valid PDF report."
                    )
            except (OSError, subprocess.SubprocessError) as exc:
                logger.warning("Headless browser PDF generation failed: %s", exc)

        try:
            from weasyprint import HTML

            with tempfile.TemporaryDirectory(
                prefix=".redpencil-report-", dir=path.parent
            ) as temp_directory:
                temp_pdf = Path(temp_directory) / pdf_path.name
                HTML(string=html_content).write_pdf(str(temp_pdf))
                if self._is_pdf(temp_pdf):
                    temp_pdf.replace(pdf_path)
                    return str(pdf_path)
                logger.warning("WeasyPrint did not produce a valid PDF report.")
        except (ImportError, OSError, RuntimeError) as exc:
            logger.warning("WeasyPrint PDF generation failed: %s", exc)

        return str(html_path)

    @staticmethod
    def _find_browsers() -> List[Path]:
        """Find installed Edge or Chrome executables on common platforms."""
        candidates = [
            shutil.which("msedge"),
            shutil.which("chrome"),
            shutil.which("google-chrome"),
            shutil.which("chromium"),
            shutil.which("chromium-browser"),
        ]

        if os.name == "nt":
            for variable in ("PROGRAMFILES(X86)", "PROGRAMFILES", "LOCALAPPDATA"):
                base_directory = os.environ.get(variable)
                if base_directory:
                    candidates.extend(
                        (
                            str(Path(base_directory) / "Microsoft/Edge/Application/msedge.exe"),
                            str(Path(base_directory) / "Google/Chrome/Application/chrome.exe"),
                        )
                    )
        elif sys.platform == "darwin":
            candidates.extend(
                (
                    "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
                    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
                )
            )

        browsers = []
        seen = set()
        for candidate in candidates:
            if candidate:
                browser = Path(candidate)
                normalized = str(browser).casefold()
                if normalized not in seen and browser.is_file():
                    browsers.append(browser)
                    seen.add(normalized)
        return browsers

    @staticmethod
    def _is_pdf(path: Path) -> bool:
        """Return whether a renderer produced a file with a PDF signature."""
        try:
            with path.open("rb") as pdf_file:
                return pdf_file.read(5) == b"%PDF-"
        except OSError:
            return False