"""Tests for parsing supported recorded tool output formats."""

import json
import pytest

from backend.adapters.nessus import NessusAdapter
from backend.adapters.nikto import NiktoAdapter
from backend.adapters.nmap import NmapAdapter
from backend.adapters.zap import ZAPAdapter
from backend.models import Severity


def test_nmap_import_parses_open_port_and_scanned_asset():
	raw_xml = """<nmaprun><host><status state="up"/><address addr="192.0.2.10" addrtype="ipv4"/>
	<ports><port protocol="tcp" portid="443"><state state="open"/>
	<service name="https" product="Example" version="1.2"/></port></ports></host></nmaprun>"""

	findings = NmapAdapter(mode="import-only").parse(raw_xml, "192.0.2.10")

	assert len(findings) == 1
	assert findings[0].asset == "192.0.2.10"
	assert findings[0].port == 443
	assert findings[0].severity == Severity.INFO


def test_nessus_import_preserves_tool_severity_and_identifiers():
	raw_xml = """<NessusClientData_v2><Report><ReportHost name="192.0.2.10"><ReportItem
	port="443" severity="3" pluginName="Example issue"><description>Observed issue</description>
	<solution>Apply vendor update</solution><cvss3_base_score>7.5</cvss3_base_score>
	<cve>CVE-2024-1234</cve><plugin_output>Version observed</plugin_output>
	</ReportItem></ReportHost></Report></NessusClientData_v2>"""

	findings = NessusAdapter().parse(raw_xml, "192.0.2.10")

	assert len(findings) == 1
	assert findings[0].severity == Severity.HIGH
	assert findings[0].cvss_score == 7.5
	assert findings[0].cve_id == "CVE-2024-1234"
	assert findings[0].remediation == "Apply vendor update"


def test_nikto_import_parses_json_observations():
	raw_json = '{"vulnerabilities":[{"msg":"Server header observed","url":"https://192.0.2.10/","severity":"LOW"}]}'

	findings = NiktoAdapter().parse(raw_json, "192.0.2.10")

	assert len(findings) == 1
	assert findings[0].title == "Server header observed"
	assert findings[0].severity == Severity.LOW
	assert "https://192.0.2.10/" in findings[0].supporting_evidence
	assert findings[0].port == 443


def test_nikto_import_uses_root_port_then_http_default():
	root_port_result = NiktoAdapter().parse(
		'{"port":8080,"vulnerabilities":[{"msg":"Server header observed"}]}',
		"192.0.2.10",
	)
	item_port_result = NiktoAdapter().parse(
		'{"port":8080,"vulnerabilities":[{"msg":"Server header observed","port":9090}]}',
		"192.0.2.10",
	)
	http_default_result = NiktoAdapter().parse(
		'{"vulnerabilities":[{"msg":"Server header observed"}]}',
		"192.0.2.10",
	)

	assert root_port_result[0].port == 8080
	assert item_port_result[0].port == 9090
	assert http_default_result[0].port == 80


@pytest.mark.parametrize(
	("message", "expected"),
	[
		("Path traversal exposes /etc/passwd", Severity.HIGH),
		("Sensitive configuration /.env exposes DB_PASSWORD", Severity.CRITICAL),
		("Unauthenticated admin panel exposed", Severity.MEDIUM),
		("Admin login page is available", Severity.INFO),
	],
)
def test_nikto_import_maps_known_web_risk_patterns(message, expected):
	findings = NiktoAdapter().parse(
		json.dumps({"vulnerabilities": [{"msg": message}]}),
		"192.0.2.10",
	)

	assert findings[0].severity == expected


def test_zap_import_parses_risk_and_cwe():
	raw_json = '{"alerts":[{"name":"Example alert","riskcode":"2","cweid":"79","url":"https://192.0.2.10/","evidence":"reflected value"}]}'

	findings = ZAPAdapter(mode="import-only").parse(raw_json, "192.0.2.10")

	assert len(findings) == 1
	assert findings[0].severity == Severity.MEDIUM
	assert findings[0].cwe_id == "CWE-79"
	assert "reflected value" in findings[0].supporting_evidence


def test_zap_import_infers_severity_from_exposed_sensitive_file_evidence():
	raw_json = json.dumps({
		"alerts": [{
			"name": "Informational response",
			"riskcode": "0",
			"url": "https://192.0.2.10/.env",
			"evidence": "DB_PASSWORD is exposed",
		}]
	})

	findings = ZAPAdapter().parse(raw_json, "192.0.2.10")

	assert findings[0].severity == Severity.CRITICAL


@pytest.mark.parametrize(
	("adapter", "raw_output"),
	[
		(NmapAdapter(), "<not-nmap/>"),
		(NessusAdapter(), "<not-nessus/>"),
		(NiktoAdapter(), "not-json"),
		(ZAPAdapter(), "not-json"),
	],
)
def test_import_parsers_reject_invalid_or_wrong_format(adapter, raw_output):
	with pytest.raises(ValueError):
		adapter.parse(raw_output, "192.0.2.10")
