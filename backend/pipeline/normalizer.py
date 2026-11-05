"""Normalize findings from different input formats."""

from backend.models import Severity


SEVERITY_RANK = {
	Severity.INFO: 0,
	Severity.LOW: 1,
	Severity.MEDIUM: 2,
	Severity.HIGH: 3,
	Severity.CRITICAL: 4,
}


def infer_web_severity(reported: Severity, evidence: str) -> Severity:
	"""Apply conservative evidence-pattern rules without lowering scanner severity."""
	text = evidence.casefold()
	inferred = Severity.INFO

	if "/.env" in text and any(
		token in text for token in ("password", "secret", "credential", "api_key", "token")
	):
		inferred = Severity.CRITICAL
	elif any(
		pattern in text
		for pattern in ("/.env", "/etc/passwd", "path traversal", "directory traversal", "sensitive configuration")
	):
		inferred = Severity.HIGH
	elif "admin" in text and any(
		term in text
		for term in ("unauthenticated", "no authentication", "default credential", "authentication bypass", "exposed")
	):
		inferred = Severity.MEDIUM

	return inferred if SEVERITY_RANK[inferred] > SEVERITY_RANK[reported] else reported
