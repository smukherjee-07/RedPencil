"""
tests/test_correlation.py
Tests for deduplication, grounding verification, and risk prioritization.
"""

import pytest
from backend.models import Finding, Severity
from backend.pipeline.correlator import Correlator, GroundingViolationError
from backend.pipeline.prioritizer import RiskPrioritizer


def test_deduplication_combines_evidence():
    f1 = Finding(
        finding_id="1", source_tool="Nmap", asset="10.0.0.5", port=80,
        title="Apache Outdated", description="v1", severity=Severity.MEDIUM,
        supporting_evidence="Server: Apache/2.4.29"
    )
    f2 = Finding(
        finding_id="2", source_tool="OWASP ZAP", asset="10.0.0.5", port=80,
        title="Apache Outdated", description="v2", severity=Severity.MEDIUM,
        supporting_evidence="Header check: Apache/2.4.29"
    )

    deduped = Correlator.deduplicate([f1, f2])
    assert len(deduped) == 1
    assert "Nmap, OWASP ZAP" in deduped[0].source_tool
    assert "Server: Apache/2.4.29" in deduped[0].supporting_evidence


def test_grounding_rejects_hallucinated_cve():
    finding = Finding(
        finding_id="3", source_tool="ZAP", asset="10.0.0.5", port=443,
        title="SSL Flaw", description="desc", severity=Severity.HIGH,
        cve_id="CVE-2024-99999",
        supporting_evidence="SSL certificate valid until 2027"
    )

    with pytest.raises(GroundingViolationError):
        Correlator.verify_grounding(finding, raw_evidence=finding.supporting_evidence)


def test_risk_prioritization_ranking():
    low_find = Finding(
        finding_id="1", source_tool="Nmap", asset="10.0.0.1", port=22,
        title="SSH Open", description="desc", severity=Severity.INFO,
        supporting_evidence="Open"
    )
    high_find = Finding(
        finding_id="2", source_tool="ZAP", asset="10.0.0.1", port=443,
        title="SQL Injection", description="desc", severity=Severity.HIGH,
        supporting_evidence="Error detected"
    )

    ranked = RiskPrioritizer.rank_findings([low_find, high_find])
    assert ranked[0].title == "SQL Injection"