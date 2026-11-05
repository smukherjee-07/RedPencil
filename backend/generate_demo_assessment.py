"""Generate a clearly labeled synthetic RedPencil report without running tools."""

from pathlib import Path
import sys

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.models import (
    AssessmentScope,
    Finding,
    Severity,
    ToolRun,
    ToolStatus,
)
from backend.reporting.generator import ReportGenerator


BASE_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = BASE_DIR / "data"
JSON_OUTPUT_PATH = DATA_DIR / "demo_assessment_data.json"
PDF_OUTPUT_PATH = DATA_DIR / "demo_sample_report.pdf"

DEMO_METADATA = {
    "execution_type": "synthetic_demo",
    "simulated": True,
    "prompt_objective": (
        "Demonstrate the RedPencil report format using synthetic, "
        "non-operational examples."
    ),
    "notice": (
        "All targets, tool runs, and findings are synthetic. "
        "No scanners or other security tools were executed."
    ),
}

SCOPE = AssessmentScope(
    authorized_targets=["192.0.2.10", "198.51.100.20"],
    excluded_targets=["203.0.113.25"],
)

TOOL_RUNS = [
    ToolRun(
        run_id="demo-nmap-001",
        tool_name="Nmap",
        target="192.0.2.10",
        command_or_mode="No command; synthetic record only",
        mode="Simulated demo — not executed",
        status=ToolStatus.PENDING,
        rationale="Illustrative inventory row; no network activity was performed.",
    ),
    ToolRun(
        run_id="demo-zap-001",
        tool_name="OWASP ZAP",
        target="https://192.0.2.10",
        command_or_mode="No command; synthetic record only",
        mode="Simulated demo — not executed",
        status=ToolStatus.PENDING,
        rationale="Illustrative web assessment row; no requests were sent.",
    ),
    ToolRun(
        run_id="demo-nikto-001",
        tool_name="Nikto",
        target="192.0.2.10",
        command_or_mode="No command; synthetic record only",
        mode="Simulated demo — not executed",
        status=ToolStatus.PENDING,
        rationale="Illustrative web server review row; no requests were sent.",
    ),
    ToolRun(
        run_id="demo-nessus-001",
        tool_name="Nessus",
        target="192.0.2.10",
        command_or_mode="No import; synthetic record only",
        mode="Simulated demo — not executed",
        status=ToolStatus.PENDING,
        rationale="Illustrative import-only integration row; no report was imported.",
    ),
    ToolRun(
        run_id="demo-metasploit-001",
        tool_name="Metasploit",
        target="192.0.2.10",
        command_or_mode="No command; synthetic record only",
        mode="Simulated demo — not executed",
        status=ToolStatus.PENDING,
        rationale="Illustrative integration row only; no modules or checks were run.",
    ),
]

FINDINGS = [
    Finding(
        finding_id="demo-finding-001",
        source_tool="OWASP ZAP (simulated)",
        asset="192.0.2.10",
        port=443,
        title="Recommended response header is absent (simulated)",
        description="Synthetic example of a web response-header configuration finding.",
        severity=Severity.LOW,
        supporting_evidence="Synthetic placeholder evidence; not collected from a host.",
        impact="May reduce defense-in-depth against browser-based content framing.",
        remediation=(
            "Review the application's framing requirements and configure an "
            "appropriate Content-Security-Policy frame-ancestors directive."
        ),
    ),
    Finding(
        finding_id="demo-finding-002",
        source_tool="Nmap (simulated)",
        asset="198.51.100.20",
        port=22,
        title="Service inventory example (simulated)",
        description="Synthetic example showing how an observed service may be recorded.",
        severity=Severity.INFO,
        supporting_evidence="Synthetic placeholder evidence; no service scan was performed.",
        impact="An inventory record alone does not establish a vulnerability.",
        remediation=(
            "Confirm that the service is required and restrict access according "
            "to the organization's approved network policy."
        ),
    ),
]


def build_artifacts() -> None:
    """Write demo-only JSON, HTML, and PDF artifacts under the data directory."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    generator = ReportGenerator()
    pdf_path = generator.export_pdf(
        scope=SCOPE,
        findings=FINDINGS,
        tool_runs=TOOL_RUNS,
        output_path=str(PDF_OUTPUT_PATH),
        report_metadata=DEMO_METADATA,
        output_json_path=str(JSON_OUTPUT_PATH),
    )
    print(f"Synthetic assessment JSON: {JSON_OUTPUT_PATH}")
    print(f"Synthetic report output: {pdf_path}")
    if Path(pdf_path).suffix.lower() != ".pdf":
        print("PDF renderer unavailable; the synthetic HTML report was generated instead.")


if __name__ == "__main__":
    build_artifacts()
