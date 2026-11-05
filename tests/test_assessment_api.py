"""Tests for honest planning and authorized evidence-import behavior."""

from fastapi.testclient import TestClient

from backend import main
from backend.audit.logger import AuditLogger


def test_start_assessment_creates_plan_without_claiming_scans(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "AuditLogger", lambda: AuditLogger(str(tmp_path)))
    monkeypatch.setattr(
        main.AssessmentPlanner,
        "generate_plan",
        staticmethod(lambda scope, request_text, model_name=None: [{
            "stage": 1,
            "tool": "Nmap",
            "target": "192.0.2.10",
            "action": "Review recorded network evidence",
            "rationale": "Network coverage was requested.",
            "planning_source": "Ollama (test-model)",
        }]),
    )

    response = TestClient(main.app).post(
        "/api/assessment/start",
        json={
            "request_text": "Review authorized lab evidence",
            "authorized_targets": ["192.0.2.10"],
            "excluded_targets": [],
        },
    )

    assert response.status_code == 200
    assert response.json()["status"] == "PLANNED"
    assert response.json()["tools_executed"] == 0
    assert main.GLOBAL_STATE["runs"] == []


def test_model_list_endpoint_returns_only_installed_tags(monkeypatch):
    monkeypatch.setattr(
        main.OllamaClient,
        "list_models",
        lambda self: ["qwen3.5:4b", "mistral:latest"],
    )
    monkeypatch.setenv("OLLAMA_MODEL", "mistral:latest")

    response = TestClient(main.app).get("/api/models")

    assert response.status_code == 200
    assert response.json()["models"] == ["qwen3.5:4b", "mistral:latest"]
    assert response.json()["default"] == "mistral:latest"
    assert response.json()["ollama_available"] is True


def test_model_list_endpoint_reports_ollama_unavailable(monkeypatch):
    def unavailable(self):
        raise ConnectionError("Ollama is not running")

    monkeypatch.setattr(main.OllamaClient, "list_models", unavailable)

    response = TestClient(main.app).get("/api/models")

    assert response.status_code == 200
    assert response.json()["models"] == []
    assert response.json()["ollama_available"] is False


def test_evidence_import_rejects_out_of_scope_target(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "AuditLogger", lambda: AuditLogger(str(tmp_path)))
    monkeypatch.setattr(
        main.AssessmentPlanner,
        "generate_plan",
        staticmethod(lambda scope, request_text, model_name=None: []),
    )
    client = TestClient(main.app)
    client.post(
        "/api/assessment/start",
        json={"request_text": "Review evidence", "authorized_targets": ["192.0.2.10"]},
    )
    response = client.post(
        "/api/evidence/import",
        json={
            "tool_name": "Nmap",
            "target": "198.51.100.10",
            "filename": "record.xml",
            "content": "<nmaprun />",
        },
    )

    assert response.status_code == 403


def test_assessment_rejects_model_tag_not_installed_locally(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "AuditLogger", lambda: AuditLogger(str(tmp_path)))
    monkeypatch.setattr(main.OllamaClient, "list_models", lambda self: ["qwen3.5:4b"])

    response = TestClient(main.app).post(
        "/api/assessment/start",
        json={
            "request_text": "Review evidence",
            "authorized_targets": ["192.0.2.10"],
            "selected_model": "not-installed:latest",
        },
    )

    assert response.status_code == 400


def test_assessment_passes_selected_model_to_planner(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "AuditLogger", lambda: AuditLogger(str(tmp_path)))
    monkeypatch.setattr(main.OllamaClient, "list_models", lambda self: ["qwen3.5:latest"])
    selected = {}

    def capture_model(scope, request_text, model_name=None):
        selected["model"] = model_name
        return []

    monkeypatch.setattr(
        main.AssessmentPlanner,
        "generate_plan",
        staticmethod(capture_model),
    )
    response = TestClient(main.app).post(
        "/api/assessment/start",
        json={
            "request_text": "Review evidence",
            "authorized_targets": ["192.0.2.10"],
            "selected_model": "qwen3.5:latest",
        },
    )

    assert response.status_code == 200
    assert selected["model"] == "qwen3.5:latest"


def test_evidence_import_records_only_imported_runs_and_findings(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "AuditLogger", lambda: AuditLogger(str(tmp_path)))
    monkeypatch.setattr(main, "DATA_DIRECTORY", tmp_path)
    monkeypatch.setattr(
        main.AssessmentPlanner,
        "generate_plan",
        staticmethod(lambda scope, request_text, model_name=None: []),
    )
    client = TestClient(main.app)
    client.post(
        "/api/assessment/start",
        json={"request_text": "Review evidence", "authorized_targets": ["192.0.2.10"]},
    )
    response = client.post(
        "/api/evidence/import",
        json={
            "tool_name": "Nmap",
            "target": "192.0.2.10",
            "filename": "scan.xml",
            "content": (
                '<nmaprun><host><status state="up"/><address addr="192.0.2.10"/>'
                '<ports><port portid="443"><state state="open"/></port></ports></host></nmaprun>'
            ),
        },
    )

    assert response.status_code == 200
    assert response.json()["status"] == "IMPORTED"
    assert response.json()["tool_run"]["mode"] == "Import-only"
    assert response.json()["imported_findings"] == 1
    assert response.json()["findings"][0]["raw_reference"]["original_filename"] == "scan.xml"
    assert len(main.GLOBAL_STATE["runs"]) == 1