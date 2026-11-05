<div align="center">

# 🛡️ RedPencil

**AI-Powered Unified VAPT Agent for Authorized Penetration Testing**

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/Backend-FastAPI-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Web-lightgrey)]()
[![Scope](https://img.shields.io/badge/Scope-Lab%20Only-red)]()

</div>

```
Request + target list -> local Qwen plan -> recorded scanner export import
-> normalization / deduplication / ranking -> analyst review -> report
```

1. **Request and target list:** Enter the assessment objective and targets. The target list is user-supplied and is not proof of authorization.
2. **Planning:** Local Ollama/Qwen proposes a plan from the supported tool list. The backend validates model output; it does not let the model execute tools.
3. **Evidence import:** Import recorded Nmap XML, Nessus XML, Nikto JSON, or OWASP ZAP JSON. RedPencil does not run scans.
4. **Analysis:** Findings are normalized, deduplicated, checked for source-backed CVEs, and ranked.
5. **Review and reporting:** Review the import provenance and generate a report that states these are recorded outputs.
- [Project Structure](#-project-structure)
- [Testing](#-testing)
- [Standards and Reference Frameworks](#-standards-and-reference-frameworks)
- [Licensing Assumptions](#-licensing-assumptions)
- [Known Limitations](#-known-limitations)
- [Troubleshooting](#-troubleshooting)
- [License](#-license)

---

## 📖 Overview

RedPencil is a conversational AI agent that guides an **authorized** security assessment from initial reconnaissance to a client-ready VAPT report. Penetration testers often spend more time combining and interpreting the output of different tools than analyzing actual risk. RedPencil reduces that manual work: it plans which tools to run and explains why, orchestrates the scans, correlates the results into one evidence-backed set of findings, ranks the risks, and keeps the human analyst in control of every consequential action.

> ⚠️ **Authorized use only.** RedPencil must only be pointed at organizer-provided or explicitly authorized lab/sandbox targets. Testing third-party or production systems without written authorization is prohibited. Active exploitation or offensive validation never runs without explicit human approval.

---

## ✨ Key Features

| Feature | Description |
|---|---|
| 💬 **Qwen-Assisted Planning** | Uses local Ollama/Qwen to propose an auditable tool plan; validates tool and target recommendations and shows model or fallback provenance. |
| 🎯 **Scope Checks** | Rejects targets outside the target list entered for the current assessment. This prototype does not independently verify authorization. |
| 📥 **Recorded Evidence Imports** | Parses Nmap XML, Nessus XML, Nikto JSON, and OWASP ZAP JSON. These are imports only; the app does not launch scanners. |
| 🔗 **Normalization and Correlation** | Maps imported findings into a common schema and ranks/deduplicates them while retaining evidence. |
| 🔍 **Evidence Traceability** | Stores imported files locally and records source filename, tool, asset, evidence, confidence, and validation status. |
| ✋ **Approval-Gate Logic** | Approval recording and checks are implemented and tested, but active validation is not integrated or executed in this prototype. |
| 📄 **Assessment Report** | Produces findings, evidence, and limitations with explicit import/no-live-scan disclosure. PDF depends on a local renderer; HTML is the fallback. |

---

## 🔄 Workflow

```
┌─────────────────┐       ┌────────────────┐       ┌────────────────────────┐
│ Analyst Request │ ────> │ Scope Check &  │ ────> │ Recorded Output Import │
│ & Target Input  │       │ Qwen Planning  │       │ (Nmap/ZAP/Nessus/etc.) │
└─────────────────┘       └────────────────┘       └───────────┬────────────┘
                                                               │
                                                               v
┌─────────────────┐       ┌────────────────┐       ┌────────────────────────┐
│  VAPT Report    │ <──── │ Analyst Review │ <──── │ Normalization,         │
│                 │       │                │       │ Correlation & Ranking  │
└─────────────────┘       └────────────────┘       └────────────────────────┘
```

1. **Analyst Request:** Enter a conversational request with the authorized target and exclusions.
2. **Scope Check and Planning:** The target list is checked against itself and Qwen proposes a plan. The app does not independently verify authorization.
3. **Evidence Import:** Import an existing Nmap XML, Nessus XML, Nikto JSON, or OWASP ZAP JSON file. No live scan is run by this prototype.
4. **Normalization and Correlation:** Results are mapped to one schema, duplicates are merged, and raw evidence is linked.
5. **Risk Prioritization:** Findings are ranked using the factors listed above.
6. **Human Review:** The analyst reviews findings. Active validation is not implemented, so there is no exploit/validation action to approve or execute.
7. **Report:** Generate a report that identifies imported evidence and links findings to their local source filename.

---

## 🔌 Integration Status

| Tool | Role | Status | File | Notes |
|---|---|---|---|---|
| **Nmap** | Host, port, and service discovery | **Import-only** | `backend/adapters/nmap.py` | Parses recorded Nmap XML; no CLI execution |
| **OWASP ZAP** | Web application and API scanning | **Import-only** | `backend/adapters/zap.py` | Parses recorded ZAP JSON; no API execution |
| **Nikto** | Web server configuration checks | **Import-only** | `backend/adapters/nikto.py` | Parses recorded Nikto JSON; no CLI execution |
| **Nessus** | Infrastructure vulnerability assessment | **Import-only** | `backend/adapters/nessus.py` | Parses `.nessus` files; no Nessus licence assumed or bundled |
| **Metasploit** | Lab-only controlled validation | **Planned** | `backend/adapters/metasploit.py` | Not implemented; no validation or exploitation is executed |
| **OpenVAS / Greenbone** | Infrastructure vulnerability assessment | **Planned** | not implemented | Will be import-only (Greenbone XML) |
| **Burp Suite** | Analyst-assisted web testing | **Planned** | not implemented | Would be import-only (XML issue export); no live integration claimed |

**Status definitions**

- **Live:** the adapter executes the tool against an authorized target.
- **Import-only:** the adapter parses recorded output files. Nothing is executed, and the UI and report label such data as imported.
- **Planned:** not implemented; no action is available for it.
- **Unsupported:** will not be supported.

The import endpoint accepts analyst-provided files up to 2 MB. No sample scanner output is fabricated or bundled. The full matrix and limitations are in [docs/integration_matrix.md](docs/integration_matrix.md).

---

## 🧰 Tech Stack

| Layer | Technology |
|---|---|
| **Frontend** | HTML5, CSS3, Vanilla JavaScript (no build step) |
| **Backend** | FastAPI (Python) |
| **AI and Reasoning** | Selectable installed local Ollama models for advisory planning; deterministic fallback if unavailable |
| **Security Tools** | Nmap, Nessus, Nikto, and OWASP ZAP recorded-output imports only |
| **Storage** | `<SQLite / JSON files>` under `data/` |
| **Reporting** | Jinja2 template rendered to PDF with `<WeasyPrint / ReportLab>` |

---

## 📋 Requirements

| Tool | Purpose |
|---|---|
| [Python 3.10+](https://www.python.org/downloads/) | Runs the backend server |
| [Git](https://git-scm.com/) | Clones the repository |
| [Nmap](https://nmap.org/) | Host and service discovery |
| [OWASP ZAP](https://www.zaproxy.org/) | Web application scanning |
| [Nikto](https://github.com/sullo/nikto) | Web server checks |
| [Metasploit Framework](https://www.metasploit.com/) | Optional, lab-only validation |
| [Ollama](https://ollama.com/) | Runs local models; no API key or cloud quota required |
| Authorized lab target | Organizer-provided sandbox. Never a public or third-party system |

---

## 🚀 Installation

### 1. Clone the Repository

```bash
git clone https://github.com/smukherjee-07/RedPencil.git
cd RedPencil
```

### 2. Install Python Dependencies

<details>
<summary><strong>Windows</strong></summary>

```powershell
py -m venv venv
.\venv\Scripts\Activate.ps1
py -m pip install -r backend/requirements.txt
```
</details>

<details>
<summary><strong>Linux / macOS</strong></summary>

```bash
python3 -m venv venv
source venv/bin/activate
python3 -m pip install -r backend/requirements.txt
```
</details>

> 📄 PDF generation may need extra system libraries depending on the PDF library in `backend/requirements.txt`. If PDF export fails, see [Troubleshooting](#-troubleshooting).

### 3. Optional: Install Security Tools Separately

This prototype does not execute security tools. You do not need Nmap, Nessus, Nikto, or ZAP installed to run RedPencil; you need existing recorded exports in the supported formats. Follow each tool vendor's terms and only assess authorized lab targets if you generate your own exports.

### 4. Set Up the Local Model

Install Ollama, then download Qwen in PowerShell:

```powershell
ollama pull qwen3.5:4b
```

Each person who clones the repository installs Ollama and downloads their chosen model on their own computer; model weights are not part of the Git repository. The UI lists only tags returned by that local Ollama server. `OLLAMA_MODEL` sets the preferred default; if it is installed, it is selected, otherwise the first installed model is selected. The Python app sends requests only to that local server. A plan identifies its source as `RedPencil Reasoning Engine (<model tag>)`; a rule-based fallback is labeled as such. Run `ollama ps` to show a model is loaded locally.

Ollama normally runs at `http://127.0.0.1:11434`; the preferred default is `qwen3.5:4b`. You can choose any model reported by the local model selector. To change the preferred default or server address in the PowerShell window used to start the backend:

```powershell
$env:OLLAMA_MODEL = "qwen3.5:4b"
$env:OLLAMA_BASE_URL = "http://127.0.0.1:11434"
```

The model only proposes a plan using the Nmap, Nessus, Nikto, and OWASP ZAP import adapters. The backend rejects other tools and targets not exactly in the supplied target list. That list is user-provided and does not itself prove authorization. If Ollama is unavailable or returns invalid output, the rule-based planner is used. This integration does not execute scans or send data to a cloud model.

### 5. Run the App

From the repository root:

```bash
uvicorn backend.main:app --reload --port 8000
```

The backend also serves the frontend, so there is nothing else to start. Open `http://127.0.0.1:8000` in your browser. Interactive API docs are at `http://127.0.0.1:8000/docs`.

---

## 🎬 Usage

| Step | Action |
|---|---|
| 1 | Start the server (see [Run the App](#5-run-the-app)) and open `http://127.0.0.1:8000` |
| 2 | Enter the authorized lab target and a request, for example "Assess this host for exposed services and web vulnerabilities". Scope validation runs immediately and shows accept or reject with the reason |
| 3 | Select an installed local model and confirm the plan source shows `RedPencil Reasoning Engine` with that model tag; a rule-based fallback is labeled explicitly |
| 4 | Choose the source tool, an in-scope asset, and its recorded XML/JSON export, then select **Import Evidence** |
| 5 | Review normalized findings, source tool, confidence, validation status, and import status |
| 6 | Generate and download the report; it explicitly states that no live scanner was run |

**Import-only mode:** Files are stored locally under `data/imports/` and are git-ignored. Imports are limited to 2 MB; DTD/entity-enabled XML is rejected. Use only results you are authorized to handle.

The legacy files under `samples/` are empty placeholders, not scanner results. Use an actual export from an authorized lab; the repository intentionally does not fabricate scanner evidence.

**Synthetic report-format demo:** run `python backend/generate_demo_assessment.py` from the repository root. This produces clearly labeled synthetic report artifacts only; it is not scanner evidence and must not be presented as an assessment result.

**Tracing a finding:** each finding in the report identifies its original filename and local reference under `data/imports/`.

---

## 🔒 Safety and Scope Controls

1. **Scope checks** (`backend/guardrails/scope.py`): the target list and exclusions are checked before planning and imports. Authorization must be established separately by the analyst.
2. **No live execution**: scanner adapters are import-only. The prototype cannot run scans or active validation.
3. **Evidence grounding** (`backend/pipeline/correlator.py`): imported CVE identifiers must appear in the raw uploaded file. The LLM only proposes plans and does not create finding evidence or scores.
4. **Audit trail** (`backend/audit/logger.py`): requests, planning choices, scope checks, imports, and approval-module decisions are recorded under `data/`.
5. **Data handling**: imported scanner output and logs remain local in the git-ignored `data/` folder. Do not commit sensitive assessment files.

---

## 📂 Project Structure

```text
RedPencil/
├── README.md      
│
├── LICENSE/
├── .gitignore/
├── .env.example/
│
├── docs/
│   ├── architecture.md          # current architecture and security boundaries
│   └── integration_matrix.md    # seven tools with verified status and limits
│
├── data/                        # GITIGNORED: raw tool outputs, database, audit log
├── reports/
├── samples/
│
├── backend/
│   ├── main.py                  # app entry and API routes
│   ├── generate_demo_assessment.py  # offline synthetic report generator; never runs tools
│   ├── requirements.txt
│   ├── models.py                # Finding, ToolRun, Approval, Assessment
│   │
│   ├── agent/
│   │   ├── llm.py               # local Ollama HTTP client
│   │   ├── planner.py           # Qwen plan validation and deterministic fallback
│   │   ├── reasoning.py         # rule-based next-step helper; not currently wired
│   │   └── orchestrator.py      # normalized findings and run state; no live scans
│   │
│   ├── guardrails/
│   │   ├── scope.py             # scope and exclusion validation
│   │   └── approval.py          # active-validation approval gate
│   │
│   ├── adapters/                # recorded-output parsers; no live integrations
│   │   ├── base.py              # adapter interface
│   │   ├── nmap.py
│   │   ├── nikto.py
│   │   ├── zap.py
│   │   ├── nessus.py
│   │   └── metasploit.py
│   │
│   ├── pipeline/
│   │   ├── normalizer.py        # tool output to the common Finding model
│   │   ├── correlator.py        # deduplication, confidence, grounding check
│   │   └── prioritizer.py       # severity, CVSS, exposure, exploitability, impact, confidence
│   │
│   ├── audit/
│   │   └── logger.py            # append-only audit trail
│   │
│   └── reporting/
│       ├── generator.py         # builds the PDF report
│       └── template.html        # report sections 7.1 to 7.6
│
├── frontend/                    # plain HTML/JS, no build step
│   ├── index.html
│   ├── style.css
│   └── app.js
│
└── tests/
    ├── test_scope.py
    ├── test_approval.py
    ├── test_parsers.py
    ├── test_correlation.py
    └── test_report.py
```

---

## 🧪 Testing

```bash
pytest tests/ -v
```

| Test file | What it checks |
|---|---|
| `test_scope.py` | Out-of-scope and excluded targets are rejected |
| `test_approval.py` | Approval module blocks unresolved/rejected actions and records decisions |
| `test_parsers.py` | Nmap, Nessus, Nikto, and ZAP recorded exports parse and malformed formats are rejected |
| `test_assessment_api.py` | Planning makes no scanner claims; imports enforce scope and keep provenance |
| `test_correlation.py` | Duplicates merge, raw references are retained, and fabricated CVEs are rejected |
| `test_report.py` | Required report sections and import-mode disclosures render |

---

## 📚 Standards and Reference Frameworks

RedPencil's methodology and report reference the following where applicable:

- NIST SP 800-115
- OWASP Top 10
- CVE, CVSS, and CWE
- MITRE ATT&CK
- NIST Cybersecurity Framework (CSF) 2.0

> Referencing these standards does not, by itself, establish formal compliance with them.

---

## 📜 Licensing Assumptions

- **RedPencil** is released under the MIT License (see [LICENSE](LICENSE)).
- Python dependencies are used under their own licences, listed in `backend/requirements.txt`.
- The external security tools are **not bundled or redistributed**. Each is installed separately and used under its own licence terms.
- **Nessus** and **Burp Suite** are commercial products. RedPencil assumes no licence for either and only parses exported or recorded output files for them.

---

## 🚧 Known Limitations

- No live testing is implemented. All current scanner integrations are import-only.
- The target list is self-declared; scope checks do not prove authorization.
- OpenVAS and Burp Suite are planned and not implemented. See [Integration Status](#-integration-status).
- Metasploit is planned; no active validation flow exists. The approval-gate module is not connected to an executable action.
- Findings are only as reliable as their source output. The LLM does not verify scan data, and analyst review remains required.
- Imports are limited to 2 MB; supported parser shapes are documented in [docs/integration_matrix.md](docs/integration_matrix.md).
- Assessment state is in memory and is reset when a new assessment is started or the server restarts.
- Additional limitations and unsupported scenarios are tracked in [docs/integration_matrix.md](docs/integration_matrix.md).

---

## 🩺 Troubleshooting

| Issue | Likely Fix |
|---|---|
| Import rejected | Confirm tool selection matches the file format, target is in the entered assessment scope, and the file is within the 2 MB limit. |
| XML import rejected | Export standard Nmap or Nessus XML; DTD/entity declarations are not accepted. |
| No findings after import | Confirm the selected parser matches the vendor's supported export shape; see `docs/integration_matrix.md`. |
| Target rejected as out of scope | Confirm the imported asset is covered by the target list and not excluded. This check does not verify authorization. |
| Planner uses a rule-based fallback | Check that Ollama is running with `ollama list`, that the selected model is installed, and that `OLLAMA_BASE_URL` points to the local Ollama server. |
| PDF export fails | Make sure the PDF library's system dependencies are installed, then re-run `pip install -r backend/requirements.txt`. |
| Report is missing findings | Confirm the import succeeded and review the assessment status feed. |

---

## 📄 License

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for details.

> **Ethical Testing Notice:** RedPencil is built for authorized security assessments, sandbox testing, and defensive auditing.
