"""
tests/test_scope.py
Unit tests for scope verification and boundary enforcement.
"""

import pytest
from backend.models import AssessmentScope
from backend.guardrails.scope import ScopeValidator, ScopeViolationError


def test_scope_validation_success():
    scope = AssessmentScope(
        authorized_targets=["192.168.1.0/24"],
        excluded_targets=["192.168.1.50"]
    )
    validator = ScopeValidator(scope)

    assert validator.is_target_allowed("192.168.1.10") is True
    assert validator.is_target_allowed("192.168.1.50") is False  # Excluded
    assert validator.is_target_allowed("10.0.0.1") is False       # Out of scope


def test_scope_enforcement_raises():
    scope = AssessmentScope(
        authorized_targets=["10.0.0.0/8"],
        excluded_targets=["10.0.0.2"]
    )
    validator = ScopeValidator(scope)

    with pytest.raises(ScopeViolationError):
        validator.enforce_scope("10.0.0.2")

    with pytest.raises(ScopeViolationError):
        validator.enforce_scope("172.16.0.1")