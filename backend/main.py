"""
backend/main.py
FastAPI backend exposing endpoints for conversational requests,
execution status, human approval gates, and report downloads.
"""

from pathlib import Path
import sys
from typing import List, Literal, Optional
import uuid
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.agent.orchestrator import AssessmentOrchestrator
from backend.agent.llm import OllamaClient
from backend.agent.planner import AssessmentPlanner
from backend.adapters.nessus import NessusAdapter
from backend.adapters.nikto import NiktoAdapter
from backend.adapters.nmap import NmapAdapter
from backend.adapters.zap import ZAPAdapter
from backend.audit.logger import AuditLogger
from backend.guardrails.approval import ApprovalGate
from backend.guardrails.scope import ScopeValidator, ScopeViolationError
from backend.models import AssessmentScope, Finding, ToolRun
from backend.pipeline.correlator import Correlator, GroundingViolationError
from backend.reporting.generator import ReportGenerator

app = FastAPI(title="RedPencil VAPT Agent API")
PROJECT_DIRECTORY = Path(__file__).resolve().parent.parent
DATA_DIRECTORY = PROJECT_DIRECTORY / "data"
frontend_directory = Path(__file__).resolve().parent.parent / "frontend"
ASSESSMENT_JSON_PATH = (
    Path(__file__).resolve().parent.parent / "data" / "assessment_data.json"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In memory state for prototype demonstration
GLOBAL_STATE = {
    "scope": None,
    "orchestrator": None,
    "approval_gate": ApprovalGate(),
    "findings": [],
    "runs": [],
    "latest_report_path": None,
    "request_text": "",
}


class StartAssessmentRequest(BaseModel):
    request_text: str
    authorized_targets: List[str]
    excluded_targets: List[str] = []
    selected_model: Optional[str] = None


class ImportEvidenceRequest(BaseModel):
    tool_name: Literal["Nmap", "OWASP ZAP", "Nessus", "Nikto"]
    target: str
    filename: str
    content: str


class ApprovalDecisionRequest(BaseModel):
    approval_id: str
    approved: bool
    notes: Optional[str] = ""


@app.get("/api/models")
def get_available_models():
    client = OllamaClient()
    try:
        models = client.list_models()
    except Exception:
        return {
            "models": [],
            "default": None,
            "configured_model": client.model,
            "ollama_available": False,
            "message": "Local Ollama is unavailable; planning will use the rule-based fallback.",
        }

    default_model = client.model if client.model in models else (models[0] if models else None)
    return {
        "models": models,
        "default": default_model,
        "configured_model": client.model,
        "ollama_available": True,
        "message": "Select an installed local model." if models else "Ollama is running but has no models installed.",
    }


@app.post("/api/assessment/start")
def start_assessment(payload: StartAssessmentRequest):
    if not payload.authorized_targets:
        raise HTTPException(status_code=400, detail="Provide at least one authorized target.")

    scope = AssessmentScope(
        authorized_targets=payload.authorized_targets,
        excluded_targets=payload.excluded_targets or [],
    )
    validator = ScopeValidator(scope)
    try:
        for target in scope.authorized_targets:
            validator.enforce_scope(target)
    except ScopeViolationError as exc:
        raise HTTPException(status_code=403, detail=str(exc))

    selected_model = payload.selected_model or OllamaClient().model
    try:
        available_models = OllamaClient().list_models()
    except Exception:
        available_models = None
    if available_models is not None and selected_model not in available_models:
        raise HTTPException(
            status_code=400,
            detail=f"Selected Ollama model '{selected_model}' is not installed locally.",
        )

    audit_logger = AuditLogger()
    approval_gate = ApprovalGate(audit_logger)
    orchestrator = AssessmentOrchestrator(
        scope=scope, approval_gate=approval_gate, audit_logger=audit_logger
    )
    GLOBAL_STATE.update({
        "scope": scope,
        "approval_gate": approval_gate,
        "findings": [],
        "runs": [],
        "latest_report_path": None,
        "request_text": payload.request_text,
    })
    GLOBAL_STATE["orchestrator"] = orchestrator
    audit_logger.log_analyst_request(payload.request_text, ", ".join(scope.authorized_targets))

    plan = AssessmentPlanner.generate_plan(
        scope, payload.request_text, model_name=selected_model
    )
    for step in plan:
        audit_logger.log_agent_decision(step["tool"], step["rationale"])

    return {
        "status": "PLANNED",
        "plan": plan,
        "tools_executed": 0,
        "message": "Plan generated. No scanner was run; import authorized recorded output to analyze evidence.",
    }


@app.post("/api/evidence/import")
def import_evidence(payload: ImportEvidenceRequest):
    scope = GLOBAL_STATE["scope"]
    orchestrator = GLOBAL_STATE["orchestrator"]
    if not scope or not orchestrator:
        raise HTTPException(status_code=400, detail="Start an assessment and register scope before importing evidence.")
    if len(payload.content.encode("utf-8")) > 2_000_000:
        raise HTTPException(status_code=413, detail="Import files must be 2 MB or smaller.")

    try:
        ScopeValidator(scope).enforce_scope(payload.target)
    except ScopeViolationError as exc:
        raise HTTPException(status_code=403, detail=str(exc))

    adapters = {
        "Nmap": NmapAdapter(mode="import-only"),
        "OWASP ZAP": ZAPAdapter(mode="import-only"),
        "Nessus": NessusAdapter(),
        "Nikto": NiktoAdapter(),
    }
    adapter = adapters[payload.tool_name]
    try:
        findings = adapter.parse(payload.content, payload.target)
        validator = ScopeValidator(scope)
        for finding in findings:
            validator.enforce_scope(finding.asset)
            Correlator.verify_grounding(finding, payload.content)
    except ScopeViolationError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    except (ValueError, GroundingViolationError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    imports_dir = DATA_DIRECTORY / "imports"
    imports_dir.mkdir(parents=True, exist_ok=True)
    original_filename = payload.filename.replace("\\", "/").rsplit("/", 1)[-1][:120] or "evidence"
    stored_name = f"{uuid.uuid4().hex}_{original_filename}"
    evidence_path = imports_dir / stored_name
    evidence_path.write_text(payload.content, encoding="utf-8")
    evidence_reference = str(evidence_path.relative_to(DATA_DIRECTORY))

    for finding in findings:
        finding.raw_reference = {
            "file": evidence_reference,
            "original_filename": original_filename,
        }
    run = ToolRun(
        run_id=uuid.uuid4().hex,
        tool_name=payload.tool_name,
        target=payload.target,
        command_or_mode=f"Imported recorded output: {original_filename}",
        mode="Import-only",
        status="COMPLETED",
        rationale="Recorded tool output parsed; no network activity was performed.",
    )
    orchestrator.execution_history.append(run)
    orchestrator.collected_findings.extend(findings)
    GLOBAL_STATE["runs"] = orchestrator.execution_history
    GLOBAL_STATE["findings"] = orchestrator.consolidate_assessment()
    orchestrator.audit_logger.log_event(
        "EVIDENCE_IMPORTED",
        {
            "tool": payload.tool_name,
            "target": payload.target,
            "filename": original_filename,
            "finding_count": len(findings),
            "stored_reference": evidence_reference,
        },
    )
    return {
        "status": "IMPORTED",
        "tool_run": run,
        "imported_findings": len(findings),
        "total_findings": len(GLOBAL_STATE["findings"]),
        "findings": GLOBAL_STATE["findings"],
    }


@app.get("/api/assessment/status")
def get_status():
    pending = list(GLOBAL_STATE["approval_gate"].pending_approvals.values())
    return {
        "runs": GLOBAL_STATE["runs"],
        "findings": GLOBAL_STATE["findings"],
        "pending_approvals": pending,
    }


@app.post("/api/approval/decide")
def decide_approval(payload: ApprovalDecisionRequest):
    try:
        resolved = GLOBAL_STATE["approval_gate"].resolve_request(
            approval_id=payload.approval_id,
            approved=payload.approved,
            analyst_notes=payload.notes or "",
        )
        return {"status": "RESOLVED", "decision": resolved}
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@app.post("/api/report/generate")
def generate_report():
    if not GLOBAL_STATE["scope"]:
        raise HTTPException(status_code=400, detail="No active assessment found.")

    generator = ReportGenerator()
    report_file = (
        Path(__file__).resolve().parent.parent
        / "data"
        / "reports"
        / f"assessment_{uuid.uuid4().hex}.pdf"
    )
    output_path = generator.export_pdf(
        scope=GLOBAL_STATE["scope"],
        findings=GLOBAL_STATE["findings"],
        tool_runs=GLOBAL_STATE["runs"],
        output_path=report_file,
        report_metadata={
            "prompt_objective": GLOBAL_STATE["request_text"],
            "execution_type": "recorded_evidence_import",
            "simulated": False,
            "human_approvals": [
                approval.model_dump(mode="json")
                for approval in GLOBAL_STATE["approval_gate"].decided_approvals.values()
            ],
        },
    )
    GLOBAL_STATE["latest_report_path"] = output_path
    return {"message": "Report generated", "path": output_path}


@app.get("/api/report/json")
def download_assessment_json():
    if not ASSESSMENT_JSON_PATH.is_file():
        raise HTTPException(
            status_code=404,
            detail="Assessment data has not been generated yet.",
        )
    return FileResponse(
        ASSESSMENT_JSON_PATH,
        filename="RedPencil_Assessment_Data.json",
        media_type="application/json",
    )


@app.get("/api/report/download")
def download_report():
    if not GLOBAL_STATE["latest_report_path"]:
        raise HTTPException(status_code=404, detail="Generate a report for the active assessment first.")
    path = Path(GLOBAL_STATE["latest_report_path"])

    if not path.is_file():
        raise HTTPException(status_code=404, detail="Report file not found.")
    if path.suffix.lower() == ".pdf":
        return FileResponse(
            path,
            filename="RedPencil_VAPT_Report.pdf",
            media_type="application/pdf",
        )
    return FileResponse(
        path,
        filename="RedPencil_VAPT_Report.html",
        media_type="text/html",
    )


@app.get("/")
def frontend():
    return FileResponse(frontend_directory / "index.html")


app.mount(
    "/static",
    StaticFiles(directory=frontend_directory),
    name="frontend-static",
)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000)