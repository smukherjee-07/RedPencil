"""
tests/test_report.py
Tests verifying that the generated report contains sections 7.1 through 7.6.
"""

from backend.models import AssessmentScope, Finding, Severity, ToolRun, ToolStatus
from backend.reporting.generator import ReportGenerator


def test_report_contains_mandatory_sections():
    scope = AssessmentScope(authorized_targets=["10.0.0.5"])
    finding = Finding(
        finding_id="find-01",
        source_tool="OWASP ZAP",
        asset="10.0.0.5",
        port=443,
        title="Cross-Site Scripting",
        description="Reflected XSS parameter detected.",
        severity=Severity.HIGH,
        cwe_id="CWE-79",
        supporting_evidence="Payload reflection in q parameter."
    )
    tool_run = ToolRun(
        run_id="run-01",
        tool_name="OWASP ZAP",
        target="10.0.0.5",
        command_or_mode="zap-baseline.py",
        status=ToolStatus.COMPLETED,
        rationale="Web vulnerability scan"
    )

    generator = ReportGenerator()
    html_output = generator.generate_html_report(scope, [finding], [tool_run])

    # Assert presence of required sections from Section 7 of the problem statement
    assert "7.1 Executive Summary" in html_output
    assert "7.2 Assessment Methodology" in html_output
    assert "7.3 Severity Distribution" in html_output
    assert "7.4 Detailed Vulnerability Findings" in html_output
    assert "7.5 Impact and Remediation" in html_output
    assert "7.6 Assessment Limitations" in html_output
    assert "Cross-Site Scripting" in html_output
    assert "Payload reflection in q parameter." in html_output