"""
backend/models.py
Core data contracts and schemas across RedPencil.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ToolStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    BLOCKED = "BLOCKED"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ValidationStatus(str, Enum):
    SUSPECTED = "SUSPECTED"
    CONFIRMED = "CONFIRMED"
    REQUIRES_APPROVAL = "REQUIRES_APPROVAL"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"


class AssessmentScope(BaseModel):
    authorized_targets: List[str] = Field(
        ..., description="List of authorized IPs, hostnames, or CIDR blocks"
    )
    excluded_targets: List[str] = Field(
        default_factory=list, description="Explicitly forbidden IPs or subnets"
    )
    allowed_ports: Optional[List[int]] = None
    lab_id: Optional[str] = None


class Finding(BaseModel):
    finding_id: str
    source_tool: str
    asset: str
    port: Optional[int] = None
    title: str
    description: str
    severity: Severity = Severity.INFO
    cvss_score: Optional[float] = None
    cve_id: Optional[str] = None
    cwe_id: Optional[str] = None
    supporting_evidence: str
    impact: Optional[str] = None
    remediation: Optional[str] = None
    raw_reference: Optional[Dict[str, Any]] = None
    confidence_level: float = Field(
        1.0, ge=0.0, le=1.0, description="Confidence score from 0.0 to 1.0"
    )
    validation_status: ValidationStatus = ValidationStatus.SUSPECTED
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ToolRun(BaseModel):
    run_id: str
    tool_name: str
    target: str
    command_or_mode: str
    mode: Optional[str] = None
    status: ToolStatus = ToolStatus.PENDING
    rationale: str
    start_time: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    end_time: Optional[datetime] = None
    error_message: Optional[str] = None


class ApprovalRequest(BaseModel):
    approval_id: str
    tool_name: str
    target: str
    proposed_action: str
    risk_summary: str
    is_approved: Optional[bool] = None
    analyst_notes: Optional[str] = None
    requested_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    decided_at: Optional[datetime] = None