"""
backend/pipeline/correlator.py
Cross-tool finding correlation, duplicate merging, and evidence grounding checks.
"""

from typing import List
from backend.models import Finding


class GroundingViolationError(Exception):
    """Raised if an ungrounded or fabricated vulnerability claim is detected."""
    pass


class Correlator:
    @staticmethod
    def verify_grounding(finding: Finding, raw_evidence: str) -> bool:
        """
        Validates that any CVE identifier cited in the finding exists
        verbatim inside the supporting evidence or raw scanner output.
        """
        if finding.cve_id and finding.cve_id not in raw_evidence:
            raise GroundingViolationError(
                f"Grounding check failed: Claimed {finding.cve_id} missing from raw output."
            )
        return True

    @staticmethod
    def deduplicate(findings: List[Finding]) -> List[Finding]:
        """
        Merges genuine duplicates sharing asset, port, and vulnerability fingerprint,
        while concatenating supporting evidence and tracking all contributing tools.
        """
        merged_map = {}

        for f in findings:
            key = f"{f.asset}:{f.port}:{f.title.strip().lower()}"

            if key not in merged_map:
                merged_map[key] = f
            else:
                existing = merged_map[key]
                existing.supporting_evidence += f"\n[{f.source_tool} Evidence]: {f.supporting_evidence}"
                if f.source_tool not in existing.source_tool:
                    existing.source_tool += f", {f.source_tool}"
                if f.raw_reference:
                    existing_reference = existing.raw_reference or {}
                    existing_sources = existing_reference.get(
                        "sources", [existing_reference] if existing_reference else []
                    )
                    incoming_sources = f.raw_reference.get("sources", [f.raw_reference])
                    existing.raw_reference = {
                        **existing_reference,
                        "sources": existing_sources + incoming_sources,
                    }
                
                # Prioritize higher confidence
                existing.confidence_level = max(existing.confidence_level, f.confidence_level)

        return list(merged_map.values())