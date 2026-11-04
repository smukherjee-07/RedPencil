"""
backend/main.py
FastAPI backend exposing endpoints for conversational requests,
execution status, human approval gates, and report downloads.
"""

from pathlib import Path
from typing import List, Optional
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel

from backend.agent.orchestrator import AssessmentOrchestrator
from backend.agent.planner import AssessmentPlanner
from backend.guardrails.approval import ApprovalGate
from backend.guardrails.scope import ScopeViolationError
from backend.models import AssessmentScope, Finding, ToolRun
from backend.reporting.generator import ReportGenerator

app = FastAPI(title="RedPencil VAPT Agent API")

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
}


class StartAssessmentRequest(BaseModel):
    request_text: str
    authorized_targets: List[str]
    excluded_targets: Optional[List[str]] = []


class ApprovalDecisionRequest(BaseModel):
    approval_id: str
    approved: bool
    notes: Optional[str] = ""


@app.post("/api/assessment/start")
def start_assessment(payload: StartAssessmentRequest):
    scope = AssessmentScope(
        authorized_targets=payload.authorized_targets,
        excluded_targets=payload.excluded_targets or [],
    )
    GLOBAL_STATE["scope"] = scope
    orchestrator = AssessmentOrchestrator(
        scope=scope, approval_gate=GLOBAL_STATE["approval_gate"]
    )
    GLOBAL_STATE["orchestrator"] = orchestrator

    # Generate transparent plan with reasoning per tool
    plan = AssessmentPlanner.generate_plan(scope, payload.request_text)

    # Initial enumeration step
    try:
        run = orchestrator.execute_tool(
            tool_name="Nmap",
            target=payload.authorized_targets[0],
            raw_output_feed="""<nmaprun><host><status state="up"/><ports>
                <port portid="80"><state state="open"/><service name="http" product="Apache" version="2.4.41"/></port>
                <port portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="8.2p1"/></port>
            </ports></host></nmaprun>""",
        )
    except ScopeViolationError as exc:
        raise HTTPException(status_code=403, detail=str(exc))

    GLOBAL_STATE["runs"].append(run)
    GLOBAL_STATE["findings"] = orchestrator.consolidate_assessment()

    return {
        "status": "IN_PROGRESS",
        "plan": plan,
        "current_run": run,
        "findings_count": len(GLOBAL_STATE["findings"]),
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
    report_file = "artifacts/sample_report.pdf"
    output_path = generator.export_pdf(
        scope=GLOBAL_STATE["scope"],
        findings=GLOBAL_STATE["findings"],
        tool_runs=GLOBAL_STATE["runs"],
        output_path=report_file,
    )
    GLOBAL_STATE["latest_report_path"] = output_path
    return {"message": "Report generated", "path": output_path}


@app.get("/api/report/download")
def download_report():
    path = GLOBAL_STATE["latest_report_path"] or "artifacts/sample_report.pdf"
    if not Path(path).exists():
        raise HTTPException(status_code=404, detail="Report file not found.")
    return FileResponse(path, filename=Path(path).name)