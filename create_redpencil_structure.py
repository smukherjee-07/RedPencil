"""Create the RedPencil hackathon project scaffold without overwriting files."""

from pathlib import Path


FILES = {
    ".env.example": "",
    ".gitignore": "/data/\n__pycache__/\n.env\nvenv/\n",
    "LICENSE": "",
    "README.md": "",
    "docs/architecture.md": "",
    "docs/integration_matrix.md": "",
    "docs/sample_report.pdf": "",
    "samples/nmap_sample.xml": "",
    "samples/nikto_sample.json": "",
    "samples/nessus_sample.nessus": "",
    "samples/openvas_sample.xml": "",
    "samples/burp_sample.xml": "",
    "backend/main.py": '"""Backend application entry point."""\n',
    "backend/requirements.txt": "",
    "backend/models.py": '"""Data models shared by backend components."""\n',
    "backend/agent/llm.py": '"""Language-model interface used by the agent."""\n',
    "backend/agent/planner.py": '"""Plan authorized assessment and analysis steps."""\n',
    "backend/agent/reasoning.py": '"""Reason over normalized findings and supporting evidence."""\n',
    "backend/agent/orchestrator.py": '"""Coordinate the agent workflow and its guarded components."""\n',
    "backend/guardrails/scope.py": '"""Check targets against the authorized scope before runs."""\n',
    "backend/guardrails/approval.py": '"""Enforce approval requirements before sensitive operations."""\n',
    "backend/adapters/base.py": '"""Define the common interface implemented by tool adapters."""\n',
    "backend/adapters/nmap.py": '"""Adapt Nmap output to the common adapter interface."""\n',
    "backend/adapters/nikto.py": '"""Adapt Nikto output to the common adapter interface."""\n',
    "backend/adapters/zap.py": '"""Adapt OWASP ZAP output to the common adapter interface."""\n',
    "backend/adapters/nessus.py": '"""Adapt Nessus output to the common adapter interface."""\n',
    "backend/adapters/metasploit.py": '"""Adapt Metasploit data to the common adapter interface."""\n',
    "backend/adapters/openvas.py": '"""Adapt OpenVAS output to the common adapter interface."""\n',
    "backend/adapters/burp.py": '"""Adapt Burp Suite output to the common adapter interface."""\n',
    "backend/pipeline/normalizer.py": '"""Normalize findings from different input formats."""\n',
    "backend/pipeline/correlator.py": (
        '"""Deduplicate findings and ground correlations in source evidence."""\n'
    ),
    "backend/pipeline/prioritizer.py": '"""Prioritize normalized findings for review."""\n',
    "backend/audit/logger.py": '"""Record auditable events for application operations."""\n',
    "backend/reporting/generator.py": '"""Generate reports from reviewed assessment findings."""\n',
    "backend/reporting/template.html": "",
    "frontend/index.html": (
        "<!doctype html>\n"
        '<html lang="en">\n'
        "<head>\n"
        '  <meta charset="utf-8">\n'
        '  <meta name="viewport" content="width=device-width, initial-scale=1">\n'
        "  <title>RedPencil</title>\n"
        "</head>\n"
        "<body>\n"
        "  <main>\n"
        "    <h1>RedPencil</h1>\n"
        "  </main>\n"
        "</body>\n"
        "</html>\n"
    ),
    "frontend/style.css": "",
    "frontend/app.js": "",
    "tests/test_scope.py": '"""Tests for target-scope guardrails."""\n',
    "tests/test_approval.py": '"""Tests for approval guardrails."""\n',
    "tests/test_parsers.py": '"""Tests for parsing supported tool output formats."""\n',
    "tests/test_correlation.py": '"""Tests for finding correlation and deduplication."""\n',
    "tests/test_report.py": '"""Tests for report generation."""\n',
}

DIRECTORIES = (
    "docs",
    "samples",
    "data",
    "backend",
    "backend/agent",
    "backend/guardrails",
    "backend/adapters",
    "backend/pipeline",
    "backend/audit",
    "backend/reporting",
    "frontend",
    "tests",
)

REQUIRED_GITIGNORE_ENTRIES = ("/data/", "__pycache__/", ".env", "venv/")


def get_root() -> Path:
    """Use this directory when installed in RedPencil, otherwise create it here."""
    script_directory = Path(__file__).resolve().parent
    if script_directory.name.casefold() == "redpencil":
        return script_directory
    return Path.cwd() / "RedPencil"


def create_scaffold(root: Path) -> None:
    """Create the requested folders and files, preserving existing contents."""
    root.mkdir(parents=True, exist_ok=True)

    for directory in DIRECTORIES:
        (root / directory).mkdir(parents=True, exist_ok=True)

    for relative_path, content in FILES.items():
        path = root / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            if not path.is_file():
                raise NotADirectoryError(f"Expected a file but found another type: {path}")
            continue
        path.write_text(content, encoding="utf-8", newline="\n")

    gitignore = root / ".gitignore"
    existing_entries = set(gitignore.read_text(encoding="utf-8").splitlines())
    missing_entries = [
        entry for entry in REQUIRED_GITIGNORE_ENTRIES if entry not in existing_entries
    ]
    if missing_entries:
        with gitignore.open("a", encoding="utf-8", newline="\n") as stream:
            if gitignore.stat().st_size and not gitignore.read_bytes().endswith(b"\n"):
                stream.write("\n")
            stream.write("\n".join(missing_entries) + "\n")

    print(f"RedPencil scaffold is ready at: {root}")


if __name__ == "__main__":
    create_scaffold(get_root())
