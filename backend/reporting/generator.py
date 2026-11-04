"""
backend/reporting/generator.py
Compiles normalized findings and execution records into client-ready VAPT reports.
"""

from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import List, Optional
from jinja2 import Environment, FileSystemLoader

from backend.models import AssessmentScope, Finding, Severity, ToolRun


class ReportGenerator:
    def __init__(self, template_dir: Optional[str] = None):
        if template_dir is None:
            template_dir = str(Path(__file__).parent)
        self.env = Environment(loader=FileSystemLoader(template_dir), autoescape=True)
        self.template = self.env.get_template("template.html")

    def generate_html_report(
        self,
        scope: AssessmentScope,
        findings: List[Finding],
        tool_runs: List[ToolRun]
    ) -> str:
        """Renders the HTML version of the required sections 7.1 to 7.6."""
        counts = Counter({s.value: 0 for s in Severity})
        for f in findings:
            counts[f.severity.value] += 1

        tools_used = sorted(list({r.tool_name for r in tool_runs}))

        rendered_html = self.template.render(
            target_scope=scope.authorized_targets,
            generated_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
            findings=findings,
            tool_runs=tool_runs,
            tools_used=tools_used,
            severity_counts=counts
        )
        return rendered_html

    def export_pdf(
        self,
        scope: AssessmentScope,
        findings: List[Finding],
        tool_runs: List[ToolRun],
        output_path: str
    ) -> str:
        """
        Exports the rendered HTML report to PDF.
        Falls back to saving HTML if a headless PDF utility (like WeasyPrint) is not installed.
        """
        html_content = self.generate_html_report(scope, findings, tool_runs)
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        try:
            from weasyprint import HTML
            HTML(string=html_content).write_pdf(str(path))
        except ImportError:
            # Fallback for environments lacking cairo/weasyprint binary dependencies
            fallback_path = path.with_suffix(".html")
            with open(fallback_path, "w", encoding="utf-8") as f:
                f.write(html_content)
            return str(fallback_path)

        return str(path)