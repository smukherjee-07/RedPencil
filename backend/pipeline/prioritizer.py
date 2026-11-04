"""
backend/pipeline/prioritizer.py
Calculates defensible priority scores based on CVSS, exposure, and confidence.
"""

from typing import List
from backend.models import Finding, Severity


class RiskPrioritizer:
    SEVERITY_WEIGHTS = {
        Severity.CRITICAL: 10.0,
        Severity.HIGH: 8.0,
        Severity.MEDIUM: 5.0,
        Severity.LOW: 2.0,
        Severity.INFO: 0.5,
    }

    @classmethod
    def calculate_priority_score(cls, finding: Finding) -> float:
        """Calculates normalized priority score (0.0 to 10.0)."""
        base_weight = cls.SEVERITY_WEIGHTS.get(finding.severity, 1.0)
        
        # Factor in direct CVSS score if provided by scanner
        score = finding.cvss_score if finding.cvss_score is not None else base_weight
        
        # Exposure boost for public services
        exposure_multiplier = 1.1 if finding.port in [80, 443, 8080, 8443] else 1.0
        
        final_score = round(min(score * exposure_multiplier * finding.confidence_level, 10.0), 2)
        return final_score

    @classmethod
    def rank_findings(cls, findings: List[Finding]) -> List[Finding]:
        """Sorts findings descending by calculated priority."""
        return sorted(findings, key=cls.calculate_priority_score, reverse=True)