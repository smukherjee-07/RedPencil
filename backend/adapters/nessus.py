"""Import Nessus XML reports into the common finding schema."""

import xml.etree.ElementTree as ET
from datetime import datetime, timezone
import uuid

from backend.adapters.base import BaseAdapter
from backend.models import Finding, Severity, ToolRun, ToolStatus, ValidationStatus


class NessusAdapter(BaseAdapter):
	SEVERITIES = {
		"0": Severity.INFO,
		"1": Severity.LOW,
		"2": Severity.MEDIUM,
		"3": Severity.HIGH,
		"4": Severity.CRITICAL,
	}

	def __init__(self):
		super().__init__(tool_name="Nessus", mode="import-only")

	def parse(self, raw_output: str, target: str) -> list[Finding]:
		if "<!DOCTYPE" in raw_output.upper() or "<!ENTITY" in raw_output.upper():
			raise ValueError("Nessus XML with DTD or entity declarations is not accepted.")
		try:
			root = ET.fromstring(raw_output)
		except ET.ParseError:
			raise ValueError("Input is not valid Nessus XML.") from None
		if root.tag != "NessusClientData_v2":
			raise ValueError("Input is not a Nessus XML export.")

		findings = []
		for report_host in root.findall(".//ReportHost"):
			asset = report_host.get("name") or target
			for item in report_host.findall("ReportItem"):
				severity = self.SEVERITIES.get(item.get("severity", "0"), Severity.INFO)
				get_text = lambda tag: (item.findtext(tag) or "").strip()
				cvss_text = get_text("cvss3_base_score") or get_text("cvss_base_score")
				try:
					cvss_score = float(cvss_text) if cvss_text else None
				except ValueError:
					cvss_score = None
				cves = [value.text.strip() for value in item.findall("cve") if value.text]
				evidence = get_text("plugin_output") or get_text("synopsis") or get_text("description")
				findings.append(
					Finding(
						finding_id=f"nessus-{uuid.uuid4().hex[:8]}",
						source_tool="Nessus",
						asset=asset,
						port=int(item.get("port")) if (item.get("port") or "").isdigit() and int(item.get("port")) else None,
						title=item.get("pluginName") or "Nessus finding",
						description=get_text("description") or get_text("synopsis"),
						severity=severity,
						cvss_score=cvss_score,
						cve_id=cves[0] if cves else None,
						cwe_id=get_text("cwe") or None,
						supporting_evidence=evidence or "No plugin output was provided.",
						remediation=get_text("solution") or None,
						confidence_level=0.8,
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
			rationale="This prototype imports recorded Nessus XML and does not launch scans.",
		)
