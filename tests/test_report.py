"""
tests/test_report.py
Tests verifying that the generated report contains sections 7.1 through 7.6.
"""

import json

from fastapi.testclient import TestClient

from backend import main
from backend.models import AssessmentScope, Finding, Severity, ToolRun, ToolStatus
from backend.reporting.generator import ReportGenerator


def test_assessment_json_download_endpoint(tmp_path, monkeypatch):
    json_path = tmp_path / "assessment_data.json"
    monkeypatch.setattr(main, "ASSESSMENT_JSON_PATH", json_path)
    client = TestClient(main.app)

    assert client.get("/api/report/json").status_code == 404

    json_path.write_text('{"tools_executed_count": 1}', encoding="utf-8")
    response = client.get("/api/report/json")

    assert response.status_code == 200
    assert response.headers["content-type"] == "application/json"
    assert "RedPencil_Assessment_Data.json" in response.headers["content-disposition"]
    assert response.json() == {"tools_executed_count": 1}


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
    assert "Tools Executed:</strong> OWASP ZAP" in html_output
    assert "<td><strong>OWASP ZAP</strong></td>" in html_output
    assert "<td>COMPLETED</td>" in html_output


def test_full_assessment_json_includes_tools_scope_and_findings(tmp_path):
    scope = AssessmentScope(
        authorized_targets=["10.0.0.5"],
        excluded_targets=["10.0.0.9"],
    )
    finding = Finding(
        finding_id="find-01",
        source_tool="OWASP ZAP",
        asset="10.0.0.5",
        title="Cross-Site Scripting",
        description="Reflected XSS parameter detected.",
        severity=Severity.HIGH,
        supporting_evidence="Payload reflection in q parameter.",
    )
    tool_run = ToolRun(
        run_id="run-01",
        tool_name="OWASP ZAP",
        target="10.0.0.5",
        command_or_mode="zap-baseline.py",
        status=ToolStatus.COMPLETED,
        rationale="Web vulnerability scan",
    )
    output_path = tmp_path / "assessment_data.json"

    saved_path = ReportGenerator().save_full_assessment_json(
        scope, [finding], [tool_run], str(output_path)
    )
    record = json.loads(output_path.read_text(encoding="utf-8"))

    assert saved_path == str(output_path.resolve())
    assert record["metadata"]["system"] == "RedPencil VAPT Agent"
    assert record["scope"]["authorized_targets"] == ["10.0.0.5"]
    assert record["scope"]["excluded_targets"] == ["10.0.0.9"]
    assert record["tools_executed_count"] == 1
    assert record["tools_executed"][0]["status"] == "COMPLETED"
    assert record["total_findings"] == 1
    assert record["findings"][0]["severity"] == "HIGH"