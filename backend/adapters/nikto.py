"""Import Nikto JSON output into the common finding schema."""

import json
from datetime import datetime, timezone
from urllib.parse import urlsplit
import uuid

from backend.adapters.base import BaseAdapter
from backend.models import Finding, Severity, ToolRun, ToolStatus, ValidationStatus


class NiktoAdapter(BaseAdapter):
	def __init__(self):
		super().__init__(tool_name="Nikto", mode="import-only")

	@staticmethod
	def _severity(value: str) -> Severity:
		normalized = str(value or "").strip().upper()
		return {
			"CRITICAL": Severity.CRITICAL,
			"HIGH": Severity.HIGH,
			"MEDIUM": Severity.MEDIUM,
			"LOW": Severity.LOW,
			"INFO": Severity.INFO,
			"INFORMATIONAL": Severity.INFO,
		}.get(normalized, Severity.INFO)

	def parse(self, raw_output: str, target: str) -> list[Finding]:
		try:
			data = json.loads(raw_output)
		except json.JSONDecodeError:
			raise ValueError("Input is not valid Nikto JSON.") from None
		if not isinstance(data, dict):
			raise ValueError("Nikto export must be a JSON object.")

		vulnerabilities = data.get("vulnerabilities", data.get("findings", []))
		if not isinstance(vulnerabilities, list) or any(not isinstance(item, dict) for item in vulnerabilities):
			raise ValueError("Nikto findings have an invalid structure.")

		findings = []
		for item in vulnerabilities:
			url = str(item.get("url") or "")
			parsed_url = urlsplit(url)
			port_text = str(item.get("port") or parsed_url.port or "")
			try:
				port = int(port_text) if port_text else None
			except ValueError:
				port = None
			message = str(item.get("msg") or item.get("message") or item.get("description") or "Nikto observation")
			evidence = "\n".join(part for part in (url, str(item.get("method") or ""), message) if part)
			findings.append(
				Finding(
					finding_id=f"nikto-{uuid.uuid4().hex[:8]}",
					source_tool="Nikto",
					asset=target,
					port=port,
					title=message[:200],
					description=message,
					severity=self._severity(item.get("severity", "INFO")),
					supporting_evidence=evidence,
					confidence_level=0.75,
					validation_status=ValidationStatus.SUSPECTED,
					timestamp=datetime.now(timezone.utc),
				)
			)
		return findings

	def execute(self, target: str, options: dict) -> ToolRun:
		return ToolRun(
			run_id=uuid.uuid4().hex,
			tool_name=self.tool_name,
			target=target,
			command_or_mode="Import-only adapter; live execution is not implemented.",
			mode="Import-only",
			status=ToolStatus.BLOCKED,
			rationale="This prototype imports recorded Nikto JSON and does not launch scans.",
		)
