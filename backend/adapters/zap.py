"""
backend/adapters/zap.py
Adapter for web application and API security scanning via OWASP ZAP.
"""

import json
from datetime import datetime, timezone
from typing import Any, Dict, List
import uuid

from backend.adapters.base import BaseAdapter
from backend.models import Finding, Severity, ToolRun, ToolStatus, ValidationStatus


class ZAPAdapter(BaseAdapter):
    def __init__(self, mode: str = "live"):
        super().__init__(tool_name="OWASP ZAP", mode=mode)

    def _map_severity(self, riskcode: str) -> Severity:
        mapping = {
            "3": Severity.HIGH,
            "2": Severity.MEDIUM,
            "1": Severity.LOW,
            "0": Severity.INFO
        }
        return mapping.get(str(riskcode), Severity.INFO)

    def parse(self, raw_output: str, target: str) -> List[Finding]:
        findings = []
        try:
            data = json.loads(raw_output)
        except json.JSONDecodeError:
            raise ValueError("Input is not valid JSON.") from None

        if not isinstance(data, dict):
            raise ValueError("ZAP export must be a JSON object.")

        sites = data.get("site")
        if sites is not None:
            if not isinstance(sites, list) or any(not isinstance(site, dict) for site in sites):
                raise ValueError("ZAP site data has an invalid structure.")
            alerts = [alert for site in sites for alert in site.get("alerts", [])]
        else:
            alerts = data.get("alerts", [])
        if not isinstance(alerts, list) or any(not isinstance(alert, dict) for alert in alerts):
            raise ValueError("ZAP alerts have an invalid structure.")

        for alert in alerts:
            finding = Finding(
                finding_id=f"zap-{uuid.uuid4().hex[:8]}",
                source_tool="OWASP ZAP",
                asset=target,
                port=int(alert.get("port", 80)) if str(alert.get("port", "")).isdigit() else 80,
                title=alert.get("name", "Web Vulnerability"),
                description=alert.get("desc", ""),
                severity=self._map_severity(alert.get("riskcode", "0")),
                cwe_id=f"CWE-{alert.get('cweid')}" if alert.get("cweid") else None,
                supporting_evidence=f"URL: {alert.get('url')}\nAttack: {alert.get('attack')}\nEvidence: {alert.get('evidence')}",
                confidence_level=0.85,
                validation_status=ValidationStatus.SUSPECTED,
                timestamp=datetime.now(timezone.utc)
            )
            findings.append(finding)

        return findings

    def execute(self, target: str, options: Dict[str, Any]) -> ToolRun:
        return ToolRun(
            run_id=uuid.uuid4().hex,
            tool_name=self.tool_name,
            target=target,
            command_or_mode="Import-only adapter; live execution is not implemented.",
            mode="Unsupported live execution",
            status=ToolStatus.BLOCKED,
            rationale="This prototype imports recorded ZAP JSON and does not launch scanners."
        )