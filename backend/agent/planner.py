"""
backend/agent/planner.py
Selects security assessment tools and provides clear rationale per tool.
"""

from typing import List, Dict, Any
from backend.models import AssessmentScope


class AssessmentPlanner:
    @staticmethod
    def generate_plan(scope: AssessmentScope, request_text: str) -> List[Dict[str, Any]]:
        """
        Produces an auditable scan plan detailing tool sequences and justifications.
        """
        plan = []

        # Stage 1: Network and Host Discovery
        for target in scope.authorized_targets:
            plan.append({
                "stage": 1,
                "tool": "Nmap",
                "target": target,
                "action": "Network and Service Enumeration",
                "rationale": "Identify active hosts, open ports, and running service banners to guide application scans."
            })

        # Stage 2: Web Application Assessment (conditional on user intent or web targets)
        is_web_oriented = any(keyword in request_text.lower() for keyword in ["web", "api", "http", "webapp", "url"])
        if is_web_oriented:
            for target in scope.authorized_targets:
                plan.append({
                    "stage": 2,
                    "tool": "OWASP ZAP",
                    "target": target,
                    "action": "Web Vulnerability and API Assessment",
                    "rationale": "Automated security analysis of web endpoints, application inputs, and common misconfigurations."
                })

        return plan