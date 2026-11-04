"""
backend/guardrails/approval.py
Enforces mandatory human analyst signoff before active validation runs.
"""

from datetime import datetime
from typing import Dict, Optional
import uuid

from backend.audit.logger import AuditLogger
from backend.models import ApprovalRequest, ValidationStatus


class UnauthorizedActionError(Exception):
    """Raised when an unapproved active action attempts execution."""
    pass


class ApprovalGate:
    def __init__(self, audit_logger: Optional[AuditLogger] = None):
        self.pending_approvals: Dict[str, ApprovalRequest] = {}
        self.decided_approvals: Dict[str, ApprovalRequest] = {}
        self.audit_logger = audit_logger or AuditLogger()

    def create_request(
        self,
        tool_name: str,
        target: str,
        proposed_action: str,
        risk_summary: str
    ) -> ApprovalRequest:
        """Registers a pending request requiring analyst confirmation."""
        approval_id = f"appr_{uuid.uuid4().hex[:8]}"
        request = ApprovalRequest(
            approval_id=approval_id,
            tool_name=tool_name,
            target=target,
            proposed_action=proposed_action,
            risk_summary=risk_summary,
            is_approved=None,
            requested_at=datetime.utcnow()
        )
        self.pending_approvals[approval_id] = request
        self.audit_logger.log_event("APPROVAL_REQUEST_CREATED", request.model_dump())
        return request

    def resolve_request(
        self,
        approval_id: str,
        approved: bool,
        analyst_notes: str = ""
    ) -> ApprovalRequest:
        """Records the human analyst decision into an immutable audit record."""
        if approval_id not in self.pending_approvals:
            raise KeyError(f"Approval request {approval_id} does not exist or has already been resolved.")

        request = self.pending_approvals.pop(approval_id)
        request.is_approved = approved
        request.analyst_notes = analyst_notes
        request.decided_at = datetime.utcnow()
        self.decided_approvals[approval_id] = request

        self.audit_logger.log_approval_action(
            approval_id=approval_id,
            action=request.proposed_action,
            approved=approved,
            notes=analyst_notes
        )
        return request

    def verify_permission(self, approval_id: str) -> bool:
        """
        Validates whether the specific approval token was authorized.
        Raises UnauthorizedActionError if rejected or absent.
        """
        if approval_id not in self.decided_approvals:
            raise UnauthorizedActionError(
                f"Action blocked: Token {approval_id} has not received explicit analyst approval."
            )

        decision = self.decided_approvals[approval_id]
        if not decision.is_approved:
            raise UnauthorizedActionError(
                f"Action blocked: Request {approval_id} was explicitly rejected by the analyst."
            )

        return True