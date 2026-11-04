<div align="center">

# 🛡️ RedPencil

**AI-Powered Unified VAPT Agent for Authorized Penetration Testing**

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/Backend-FastAPI-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Web-lightgrey)]()
[![Scope](https://img.shields.io/badge/Scope-Lab%20Only-red)]()

</div>

---

## 📖 Table of Contents

- [Overview](#-overview)
- [Key Features](#-key-features)
- [Workflow](#-workflow)
- [Integration Status](#-integration-status)
- [Tech Stack](#-tech-stack)
- [Requirements](#-requirements)
- [Installation](#-installation)
  - [1. Clone the Repository](#1-clone-the-repository)
  - [2. Install Python Dependencies](#2-install-python-dependencies)
  - [3. Install the Security Tools](#3-install-the-security-tools)
  - [4. Configure the Environment](#4-configure-the-environment)
  - [5. Run the App](#5-run-the-app)
- [Usage](#-usage)
- [Safety and Scope Controls](#-safety-and-scope-controls)
- [Project Structure](#-project-structure)
- [Testing](#-testing)
- [Standards and Reference Frameworks](#-standards-and-reference-frameworks)
- [Licensing Assumptions](#-licensing-assumptions)
- [Known Limitations](#-known-limitations)
- [Troubleshooting](#-troubleshooting)
- [Team](#-team)
- [License](#-license)

---

## 📖 Overview

RedPencil is a conversational AI agent that guides an **authorized** security assessment from initial reconnaissance to a client-ready VAPT report. Penetration testers often spend more time combining and interpreting the output of different tools than analyzing actual risk. RedPencil reduces that manual work: it plans which tools to run and explains why, orchestrates the scans, correlates the results into one evidence-backed set of findings, ranks the risks, and keeps the human analyst in control of every consequential action.

> ⚠️ **Authorized use only.** RedPencil must only be pointed at organizer-provided or explicitly authorized lab/sandbox targets. Testing third-party or production systems without written authorization is prohibited. Active exploitation or offensive validation never runs without explicit human approval.

---

## ✨ Key Features

| Feature | Description |
|---|---|
| 💬 **Conversational Planning** | Accepts a natural-language request plus target and scope, then produces an auditable plan with a stated rationale for each tool. |
| 🎯 **Scope Enforcement** | Registers authorized targets and exclusions, and rejects any action outside them, checked again immediately before every execution. |
| ⚙️ **Scan Orchestration** | Runs approved scans, tracks job status, and handles timeouts and tool failures without silently skipping them. |
| 🔗 **Normalization and Correlation** | Maps findings from different tools into one schema and merges genuine duplicates without hiding distinct affected assets or supporting evidence. |
| 🔍 **Evidence Traceability** | Every finding records its source tool, affected asset, timestamps, raw output reference, confidence, and confirmed/suspected status. Observed evidence is kept separate from AI inference. |
| 📊 **Risk Prioritization** | Ranks findings by severity, tool-reported CVSS, exposure, exploitability, asset impact, and confidence. CVE and CVSS values come from tool output, never from the model. |
| ✋ **Human-in-the-Loop Approval** | Active validation (for example Metasploit) is blocked until an analyst approves it. The approval and its outcome are written to the audit trail. |
| 📄 **Client-Ready PDF Report** | Executive and technical views, remediation guidance, and assessment limitations, downloadable as a PDF. |

---

## 🔄 Workflow

```
┌─────────────────┐       ┌────────────────┐       ┌────────────────────────┐
│ Analyst Request │ ────> │ Scope Check &  │ ────> │ Approved Orchestration │
│ & Target Input  │       │ Agent Planning │       │   (Nmap, ZAP, etc.)    │
└─────────────────┘       └────────────────┘       └───────────┬────────────┘
                                                               │
                                                               v
┌─────────────────┐       ┌────────────────┐       ┌────────────────────────┐
│  Client-Ready   │ <──── │ Human Approval │ <──── │ AI Normalization,      │
│   VAPT Report   │       │ Gate (Active)  │       │ Correlation & Scoring  │
└─────────────────┘       └────────────────┘       └────────────────────────┘
```

1. **Analyst Request:** Enter a conversational request with the authorized target and exclusions.
2. **Scope Validation and Planning:** The scope is verified and the agent proposes a plan with a rationale per tool. The analyst approves it before anything runs.
3. **Scan Orchestration:** Live scans run, or recorded outputs are imported, with real-time status for each tool.
4. **Normalization and Correlation:** Results are mapped to one schema, duplicates are merged, and raw evidence is linked.
5. **Risk Prioritization:** Findings are ranked using the factors listed above.
6. **Human Review and Approval:** The analyst reviews findings and explicitly approves or denies any active validation.
7. **Report:** A unified PDF report is generated and can be traced back to the original tool evidence.

---

## 🔌 Integration Status

All seven tools named in the problem statement are listed below with their real status. **Update this table to match what actually runs before you submit.**

| Tool | Role | Status | File | Notes |
|---|---|---|---|---|
| **Nmap** | Host, port, and service discovery | **Live** | `backend/adapters/nmap.py` | CLI runner and XML parser |
| **OWASP ZAP** | Web application and API scanning | **Live** | `backend/adapters/zap.py` | Uses the ZAP API; ZAP must be running |
| **Nikto** | Web server configuration checks | **Live** | `backend/adapters/nikto.py` | CLI runner and JSON parser |
| **Nessus** | Infrastructure vulnerability assessment | **Import-only** | `backend/adapters/nessus.py` | Parses `.nessus` files; no Nessus licence assumed or bundled |
| **Metasploit** | Lab-only controlled validation | **Live, human-approved** | `backend/adapters/metasploit.py` | Blocked until an approval is recorded; never autonomous |
| **OpenVAS / Greenbone** | Infrastructure vulnerability assessment | **Planned** | not implemented | Will be import-only (Greenbone XML) |
| **Burp Suite** | Analyst-assisted web testing | **Planned** | not implemented | Would be import-only (XML issue export); no live integration claimed |

**Status definitions**

- **Live:** the adapter executes the tool against an authorized target.
- **Import-only:** the adapter parses recorded output files. Nothing is executed, and the UI and report label such data as imported.
- **Planned:** not implemented. The orchestrator refuses to run it.
- **Unsupported:** will not be supported.

Recorded sample outputs in `samples/` are used for import demonstrations and are labelled as recorded. The full matrix, including limitations and unsupported scenarios, is in [docs/integration_matrix.md](docs/integration_matrix.md).

---

## 🧰 Tech Stack

| Layer | Technology |
|---|---|
| **Frontend** | HTML5, CSS3, Vanilla JavaScript (no build step) |
| **Backend** | FastAPI (Python) |
| **AI and Reasoning** | `<LLM provider and model>` |
| **Security Tools** | Nmap, OWASP ZAP, Nikto, Metasploit (live); Nessus (import-only) |
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
| LLM API key | Powers planning and reasoning (see [Configure the Environment](#4-configure-the-environment)) |
| Authorized lab target | Organizer-provided sandbox. Never a public or third-party system |

---

## 🚀 Installation

### 1. Clone the Repository

```bash
git clone https://github.com/<your-username>/RedPencil.git
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

### 3. Install the Security Tools

Install the tools listed in [Requirements](#-requirements) using their official instructions and make sure the executables are on your `PATH` (or set their paths in `.env`). Start the ZAP daemon before running web scans. Tools you skip are simply unavailable for live runs, and import-only mode still works without them.

### 4. Configure the Environment

```bash
cp .env.example .env        # Windows: copy .env.example .env
```

Edit `.env` and set the values below (names must match `.env.example`):

```env
LLM_API_KEY=<your-key>
LLM_MODEL=<model-name>
ALLOWED_TARGETS=<organizer-provided lab host or CIDR>
EXCLUDED_TARGETS=<optional, comma-separated>
ZAP_API_URL=http://127.0.0.1:8080
ZAP_API_KEY=<your-zap-key>
```

> ⚠️ Never commit `.env` or real keys. `data/` (raw scan output, database, audit log) is gitignored because it may contain sensitive scan data.

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
| 3 | Review the plan. Each tool is listed with its rationale. Approve it to start the scans |
| 4 | Watch live tool status and the agent's explanation of why each next step is needed |
| 5 | Review findings. Each shows its source tool, affected asset, confidence, confirmed/suspected status, raw evidence, and any AI inference, kept separate |
| 6 | If validation is proposed, review the exact action and target in the approval prompt, then approve or deny. The decision is written to the audit trail |
| 7 | Download the PDF report |

**Import-only mode:** upload a recorded output (for example `samples/nmap_sample.xml` or `samples/nessus_sample.nessus`) instead of running a live scan. Imported findings are labelled as imported in the UI and the report.

**Tracing a finding:** open a finding to see its raw reference, which points to the original tool output stored under `data/`.

---

## 🔒 Safety and Scope Controls

1. **Scope validation** (`backend/guardrails/scope.py`): checks every target against the authorized targets and exclusions, at planning time and again immediately before each execution. Anything outside scope is rejected and logged.
2. **Human approval gate** (`backend/guardrails/approval.py`): active validation creates an approval request describing the exact action and target. The backend blocks execution until an analyst approves, and the decision and outcome are recorded. The UI button only records the decision; enforcement lives in the backend.
3. **Evidence grounding** (`backend/pipeline/correlator.py`): CVE identifiers that do not appear in the source tool output are rejected. CVSS, CVE, and CWE values are taken from tool output, not generated by the model.
4. **Safe execution**: tools are launched with argument lists (no shell strings built from user input) and with timeouts.
5. **Audit trail** (`backend/audit/logger.py`): an append-only log of analyst requests, scope checks, agent decisions, tool runs, LLM calls, and approvals, stored in `data/`.
6. **Data handling**: raw scan data and logs stay local in the gitignored `data/` folder.

---

## 📂 Project Structure

```text
RedPencil/
├── README.md  LICENSE  .gitignore  .env.example
│
├── docs/
│   ├── architecture.md          # models, orchestration, data flow, state, security boundaries
│   ├── integration_matrix.md    # all seven tools with status and limitations
│   └── sample_report.pdf        # sample AI-generated report
│
├── samples/                     # recorded outputs for import-only mode
│   ├── nmap_sample.xml
│   ├── nikto_sample.json
│   └── nessus_sample.nessus
│
├── data/                        # GITIGNORED: raw tool outputs, database, audit log
│
├── backend/
│   ├── main.py                  # app entry and API routes
│   ├── requirements.txt
│   ├── models.py                # Finding, ToolRun, Approval, Assessment
│   │
│   ├── agent/
│   │   ├── llm.py               # model wrapper and prompts, logs every call
│   │   ├── planner.py           # plan with a rationale per tool
│   │   ├── reasoning.py         # interprets results, chooses and explains next step
│   │   └── orchestrator.py      # runs scans, status, timeouts, errors, run state
│   │
│   ├── guardrails/
│   │   ├── scope.py             # scope and exclusion validation
│   │   └── approval.py          # active-validation approval gate
│   │
│   ├── adapters/                # each adapter's parse() is shared by live and import modes
│   │   ├── base.py              # adapter interface and registry of all seven tools
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
| `test_approval.py` | Metasploit cannot run without a recorded approval, and approvals are logged |
| `test_parsers.py` | Live and imported output normalize to the same findings |
| `test_correlation.py` | Duplicates merge, distinct assets stay separate, fabricated CVEs are rejected |
| `test_report.py` | The report contains every required section |

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

- Live testing is limited to organizer-provided or explicitly authorized lab targets.
- Import-only integrations process recorded files. They do not run scans.
- OpenVAS and Burp Suite are planned and not implemented. See [Integration Status](#-integration-status).
- Findings are only as reliable as the tool output behind them. Confidence levels are estimates, and findings can remain marked as suspected until validated.
- The grounding check rejects CVE identifiers missing from tool output. It does not independently verify every statement the model produces, so analyst review is still required.
- Metasploit validation runs only after approval and only against lab targets.
- Scan failures and timeouts are recorded and listed in the report's limitations section.
- Additional limitations and unsupported scenarios are tracked in [docs/integration_matrix.md](docs/integration_matrix.md).

---

## 🩺 Troubleshooting

| Issue | Likely Fix |
|---|---|
| "Tool not found" for Nmap, Nikto, or Metasploit | Install the tool and make sure it is on your `PATH`, or set its path in `.env`. |
| ZAP scan fails to connect | Start the ZAP daemon and check `ZAP_API_URL` and `ZAP_API_KEY` in `.env`. |
| Target rejected as out of scope | Check that the target is inside `ALLOWED_TARGETS` and not in `EXCLUDED_TARGETS`. This is by design. |
| Metasploit action does not run | It is blocked until an approval is recorded. Approve it in the approval prompt. |
| Agent gives no plan or errors | Check `LLM_API_KEY` and `LLM_MODEL` in `.env`, then look at the server log and `data/` audit trail. |
| PDF export fails | Make sure the PDF library's system dependencies are installed, then re-run `pip install -r backend/requirements.txt`. |
| Report is missing findings | Confirm the scans completed. Failed or timed-out runs are listed in the report's limitations section. |

---

## 👥 Team

Developed for the **DataOps Innovation Hackathon** (PS-1: AI Agent for Automated Penetration Testing).

| Role | Member |
|---|---|
| `<role>` | `<name>` |
| `<role>` | `<name>` |

---

## 📄 License

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for details.

> **Ethical Testing Notice:** RedPencil is built strictly for authorized security assessments, hackathon sandbox testing, and defensive auditing.