"""Tests for advisory LLM planning and deterministic fallback behavior."""

from backend.agent import planner
from backend.agent.planner import AssessmentPlanner
from backend.models import AssessmentScope


def test_planner_accepts_only_registered_tools_and_in_scope_targets(monkeypatch):
    scope = AssessmentScope(authorized_targets=["192.0.2.10"])
    model_steps = [
        {
            "tool": "OWASP ZAP",
            "target": "192.0.2.10",
            "rationale": "The request mentions an API.",
        }
    ]
    monkeypatch.setattr(
        planner.OllamaClient,
        "generate_plan",
        lambda self, **kwargs: model_steps,
    )

    result = AssessmentPlanner.generate_plan(
        scope, "Review this API", model_name="qwen3.5:latest"
    )

    assert result[0]["tool"] == "OWASP ZAP"
    assert result[0]["target"] == "192.0.2.10"
    assert result[0]["planning_source"] == "RedPencil Reasoning Engine (qwen3.5:latest)"
    assert "no requests are sent" in result[0]["action"]


def test_planner_falls_back_when_model_recommends_out_of_scope_target(monkeypatch):
    scope = AssessmentScope(authorized_targets=["192.0.2.10"])
    monkeypatch.setattr(
        planner.OllamaClient,
        "generate_plan",
        lambda self, **kwargs: [
            {
                "tool": "Nmap",
                "target": "198.51.100.5",
                "rationale": "The model suggested this host.",
            }
        ],
    )

    result = AssessmentPlanner.generate_plan(scope, "Check services")

    assert result
    assert all(step["target"] == "192.0.2.10" for step in result)
    assert all("rule-based fallback" in step["planning_source"] for step in result)


def test_planner_falls_back_when_ollama_is_unavailable(monkeypatch):
    scope = AssessmentScope(authorized_targets=["192.0.2.10"])

    def unavailable(self, **kwargs):
        raise ConnectionError("Ollama is not running")

    monkeypatch.setattr(planner.OllamaClient, "generate_plan", unavailable)

    result = AssessmentPlanner.generate_plan(scope, "Assess the web API")

    assert {step["tool"] for step in result} == {"Nmap", "OWASP ZAP"}
    assert all("qwen3.5:4b; rule-based fallback" in step["planning_source"] for step in result)


def test_planner_sanitizes_command_or_active_scan_rationale(monkeypatch):
    scope = AssessmentScope(authorized_targets=["192.0.2.10"])
    monkeypatch.setattr(
        planner.OllamaClient,
        "generate_plan",
        lambda self, **kwargs: [
            {
                "tool": "Nmap",
                "target": "192.0.2.10",
                "rationale": "Run an active scan using --script=vuln.",
            }
        ],
    )

    result = AssessmentPlanner.generate_plan(scope, "Review this host")

    assert result[0]["planning_source"] == "RedPencil Reasoning Engine (qwen3.5:4b)"
    assert result[0]["action"] == AssessmentPlanner.IMPORT_ACTIONS["Nmap"]
    assert "No live scan is run" in result[0]["rationale"]