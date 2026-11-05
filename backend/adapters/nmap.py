"""
backend/adapters/nmap.py
Adapter for host, port, and service reconnaissance using Nmap.
"""

import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any, Dict, List
import uuid

from backend.adapters.base import BaseAdapter
from backend.models import Finding, Severity, ToolRun, ToolStatus, ValidationStatus


class NmapAdapter(BaseAdapter):
    def __init__(self, mode: str = "live"):
        super().__init__(tool_name="Nmap", mode=mode)

    def parse(self, raw_output: str, target: str) -> List[Finding]:
        findings = []
        if "<!DOCTYPE" in raw_output.upper() or "<!ENTITY" in raw_output.upper():
            raise ValueError("Nmap XML with DTD or entity declarations is not accepted.")
        try:
            root = ET.fromstring(raw_output)
        except ET.ParseError:
            raise ValueError("Input is not valid Nmap XML.") from None
        if root.tag != "nmaprun":
            raise ValueError("Input is not an Nmap XML export.")

        for host in root.findall("host"):
            status_elem = host.find("status")
            if status_elem is None or status_elem.get("state") != "up":
                continue

            ports = host.find("ports")
            if ports is None:
                continue

            for port_elem in ports.findall("port"):
                state = port_elem.find("state")
                if state is None or state.get("state") != "open":
                    continue

                port_id = int(port_elem.get("portid"))
                service_elem = port_elem.find("service")
                address_elem = host.find("address")
                service_name = service_elem.get("name", "unknown") if service_elem is not None else "unknown"
                product = service_elem.get("product", "") if service_elem is not None else ""
                version = service_elem.get("version", "") if service_elem is not None else ""
                asset = address_elem.get("addr", target) if address_elem is not None else target

                description = f"Open port {port_id}/{service_name}. Detected: {product} {version}".strip()

                finding = Finding(
                    finding_id=f"nmap-{uuid.uuid4().hex[:8]}",
                    source_tool="Nmap",
                    asset=asset,
                    port=port_id,
                    title=f"Open Port {port_id} ({service_name})",
                    description=description,
                    severity=Severity.INFO,
                    supporting_evidence=f"Port {port_id} open. Product: {product}, Version: {version}",
                    confidence_level=1.0,
                    validation_status=ValidationStatus.CONFIRMED,
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
            rationale="This prototype imports recorded Nmap XML and does not launch scanners."
        )