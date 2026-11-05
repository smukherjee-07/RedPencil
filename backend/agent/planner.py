"""
backend/agent/planner.py
Selects security assessment tools and provides clear rationale per tool.
"""

import logging
from typing import List, Dict, Any
from backend.agent.llm import OllamaClient
from backend.models import AssessmentScope

logger = logging.getLogger(__name__)


class AssessmentPlanner:
    AVAILABLE_TOOLS = ("Nmap", "Nessus", "Nikto", "OWASP ZAP")
    IMPORT_ACTIONS = {
        "Nmap": "Import and review recorded Nmap XML; no scanner is launched.",
        "Nessus": "Import and review recorded Nessus XML; no scanner is launched.",
        "Nikto": "Import and review recorded Nikto JSON; no scanner is launched.",
        "OWASP ZAP": "Import and review recorded ZAP JSON; no requests are sent.",
    }
    DISALLOWED_RATIONALE_TERMS = (
        "exploit", "payload", "brute force", "credential attack", "--script",
        "active scan", "scan", "traffic", "silent", "live tool",
    )

    @staticmethod
    def generate_plan(
        scope: AssessmentScope, request_text: str, model_name: str = None
    ) -> List[Dict[str, Any]]:
        """
        Produces a validated, advisory plan; execution remains backend-controlled.
        """
        try:
            client = OllamaClient(model=model_name)
            model_steps = client.generate_plan(
                request_text=request_text,
                targets=scope.authorized_targets,
                available_tools=list(AssessmentPlanner.AVAILABLE_TOOLS),
            )
            return AssessmentPlanner._validate_model_plan(
                model_steps, scope, model_name=client.model
            )
        except Exception as exc:
            logger.warning("Ollama planning unavailable; using rule-based plan: %s", exc)
            fallback_model = model_name or OllamaClient().model
            return AssessmentPlanner._fallback_plan(
                scope, request_text, model_name=fallback_model
            )

    @staticmethod
    def _validate_model_plan(
        model_steps: List[Dict[str, Any]],
        scope: AssessmentScope,
        model_name: str = "unknown model",
    ) -> List[Dict[str, Any]]:
        """Reject recommendations that invent tools, targets, or malformed steps."""
        if not model_steps:
            raise ValueError("Ollama returned no plan steps.")

        validated = []
        allowed_targets = set(scope.authorized_targets)
        for step in model_steps:
            if not isinstance(step, dict):
                raise ValueError("Ollama returned a malformed plan step.")

            tool = step.get("tool")
            target = step.get("target")
            rationale = step.get("rationale")
            if tool not in AssessmentPlanner.AVAILABLE_TOOLS:
                raise ValueError("Ollama recommended an unavailable tool.")
            if target not in allowed_targets:
                raise ValueError("Ollama recommended a target outside the supplied scope.")
            if not isinstance(rationale, str) or not rationale.strip():
                raise ValueError("Ollama returned a plan step without a rationale.")
            if any(term in rationale.lower() for term in AssessmentPlanner.DISALLOWED_RATIONALE_TERMS):
                rationale = "This export type may provide relevant evidence for the requested review. No live scan is run."

            validated.append(
                {
                    "stage": len(validated) + 1,
                    "tool": tool,
                    "target": target,
                    "action": AssessmentPlanner.IMPORT_ACTIONS[tool],
                    "rationale": rationale[:500],
                    "planning_source": f"RedPencil Reasoning Engine ({model_name})",
                }
            )
        return validated

    @staticmethod
    def _fallback_plan(
        scope: AssessmentScope, request_text: str, model_name: str = "not configured"
    ) -> List[Dict[str, Any]]:
        plan = []
        planning_source = (
            f"RedPencil Reasoning Engine ({model_name}; rule-based fallback)"
        )

        # Stage 1: Network and Host Discovery
        for target in scope.authorized_targets:
            plan.append({
                "stage": 1,
                "tool": "Nmap",
                "target": target,
                "action": "Network and Service Enumeration",
                "rationale": "Identify active hosts, open ports, and running service banners to guide application scans.",
                "planning_source": planning_source,
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
                    "rationale": "Automated security analysis of web endpoints, application inputs, and common misconfigurations.",
                    "planning_source": planning_source,
                })

        return plan