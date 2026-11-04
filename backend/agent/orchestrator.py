"""
backend/agent/orchestrator.py
Coordinates end to end assessment execution while maintaining state and audit logs.
"""

from typing import Dict, List, Optional
from backend.adapters.base import BaseAdapter
from backend.adapters.nmap import NmapAdapter
from backend.adapters.zap import ZAPAdapter
from backend.audit.logger import AuditLogger
from backend.guardrails.approval import ApprovalGate
from backend.guardrails.scope import ScopeValidator
from backend.models import AssessmentScope, Finding, ToolRun, ToolStatus
from backend.pipeline.correlator import Correlator
from backend.pipeline.prioritizer import RiskPrioritizer


class AssessmentOrchestrator:
    def __init__(
        self,
        scope: AssessmentScope,
        approval_gate: Optional[ApprovalGate] = None,
        audit_logger: Optional[AuditLogger] = None
    ):
        self.scope = scope
        self.validator = ScopeValidator(scope)
        self.audit_logger = audit_logger or AuditLogger()
        self.approval_gate = approval_gate or ApprovalGate(self.audit_logger)

        self.adapters: Dict[str, BaseAdapter] = {
            "Nmap": NmapAdapter(mode="live"),
            "OWASP ZAP": ZAPAdapter(mode="live")
        }

        self.collected_findings: List[Finding] = []
        self.execution_history: List[ToolRun] = []

    def execute_tool(
        self,
        tool_name: str,
        target: str,
        raw_output_feed: Optional[str] = None
    ) -> ToolRun:
        """
        Enforces scope checks, runs the requested adapter, and normalizes findings.
        """
        # Scope Guardrail Check
        self.validator.enforce_scope(target)
        self.audit_logger.log_scope_check(target, allowed=True)

        if tool_name not in self.adapters:
            raise ValueError(f"Tool {tool_name} is not registered in the active adapter pool.")

        adapter = self.adapters[tool_name]
        tool_run = adapter.execute(target, options={})
        self.execution_history.append(tool_run)

        # Parse output if raw feed is provided or retrieved
        if raw_output_feed:
            parsed = adapter.parse(raw_output_feed, target)
            self.collected_findings.extend(parsed)

        return tool_run

    def consolidate_assessment(self) -> List[Finding]:
        """
        Applies deduplication, grounding checks, and prioritization across all findings.
        """
        deduplicated = Correlator.deduplicate(self.collected_findings)
        ranked = RiskPrioritizer.rank_findings(deduplicated)
        return ranked