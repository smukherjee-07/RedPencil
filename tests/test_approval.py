"""
tests/test_approval.py
Tests verifying that unapproved active actions are blocked and approved ones succeed.
"""

import pytest
from backend.guardrails.approval import ApprovalGate, UnauthorizedActionError


def test_approval_gate_blocks_unapproved_action():
    gate = ApprovalGate()
    request = gate.create_request(
        tool_name="Metasploit",
        target="192.168.1.10",
        proposed_action="Exploitation Verification",
        risk_summary="Validating RCE vulnerability"
    )

    # Attempt verification without resolving approval
    with pytest.raises(UnauthorizedActionError):
        gate.verify_permission(request.approval_id)


def test_approval_gate_allows_approved_action():
    gate = ApprovalGate()
    request = gate.create_request(
        tool_name="Metasploit",
        target="192.168.1.10",
        proposed_action="Proof of Concept Verification",
        risk_summary="Controlled check on lab target"
    )

    gate.resolve_request(
        approval_id=request.approval_id,
        approved=True,
        analyst_notes="Authorized for lab assessment."
    )

    assert gate.verify_permission(request.approval_id) is True


def test_approval_gate_blocks_rejected_action():
    gate = ApprovalGate()
    request = gate.create_request(
        tool_name="Metasploit",
        target="192.168.1.10",
        proposed_action="Active Exploit",
        risk_summary="Potential service disruption"
    )

    gate.resolve_request(
        approval_id=request.approval_id,
        approved=False,
        analyst_notes="Too risky during current window."
    )

    with pytest.raises(UnauthorizedActionError):
        gate.verify_permission(request.approval_id)