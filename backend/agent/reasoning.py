"""
backend/agent/reasoning.py
Analyzes normalized findings to decide subsequent steps and highlight high risk issues.
"""

from typing import List, Dict, Any
from backend.models import Finding, Severity


class ReasoningEngine:
    @staticmethod
    def determine_next_steps(findings: List[Finding]) -> List[Dict[str, Any]]:
        """
        Evaluates current findings and produces defensible next step recommendations.
        """
        next_steps = []
        observed_ports = {f.port for f in findings if f.port is not None}

        # Check if HTTP services were discovered during port enumeration
        web_ports = {80, 443, 8080, 8443}
        if observed_ports.intersection(web_ports):
            has_web_findings = any(f.source_tool == "OWASP ZAP" for f in findings)
            if not has_web_findings:
                next_steps.append({
                    "recommended_tool": "OWASP ZAP",
                    "reasoning": "Open HTTP or HTTPS ports were observed during enumeration; targeted application scanning is required."
                })

        # Check for Critical findings that warrant controlled validation
        critical_findings = [f for f in findings if f.severity == Severity.CRITICAL]
        for item in critical_findings:
            next_steps.append({
                "recommended_tool": "Metasploit",
                "finding_id": item.finding_id,
                "target": item.asset,
                "requires_human_approval": True,
                "reasoning": f"Critical vulnerability '{item.title}' detected on {item.asset}. Analyst approval required for verification."
            })

        return next_steps