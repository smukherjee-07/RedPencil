"""
backend/audit/logger.py
Append-only audit trail capturing agent reasoning, actions, and human approvals.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict


class AuditLogger:
    def __init__(self, log_dir: str = "data"):
        self.log_path = Path(log_dir) / "audit_trail.jsonl"
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def log_event(self, event_type: str, details: Dict[str, Any]) -> None:
        """Appends an event record atomically to the audit file."""
        record = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "event_type": event_type,
            "details": details,
        }
        with open(self.log_path, mode="a", encoding="utf-8") as file:
            file.write(json.dumps(record) + "\n")

    def log_analyst_request(self, request_text: str, target: str) -> None:
        self.log_event("ANALYST_REQUEST", {"request": request_text, "target": target})

    def log_agent_decision(self, tool_name: str, rationale: str) -> None:
        self.log_event("AGENT_DECISION", {"selected_tool": tool_name, "rationale": rationale})

    def log_approval_action(self, approval_id: str, action: str, approved: bool, notes: str) -> None:
        self.log_event("HUMAN_APPROVAL", {
            "approval_id": approval_id,
            "action": action,
            "approved": approved,
            "analyst_notes": notes
        })

    def log_scope_check(self, target: str, allowed: bool) -> None:
        self.log_event("SCOPE_CHECK", {"target": target, "allowed": allowed})