| Tool | Status | Supported behavior | Not supported / limitations |
|---|---|---|---|
| Nmap | Import-only | Parses recorded Nmap XML and normalizes open-port/service observations. | Does not invoke Nmap or perform network discovery. |
| Nessus | Import-only | Parses `.nessus` XML ReportHost/ReportItem entries, severity, CVSS, CVE/CWE, plugin output, and solution. | Does not connect to Nessus or run a scan; export variants may contain fields this prototype does not map. |
| Nikto | Import-only | Parses JSON `vulnerabilities` or `findings` records into normalized observations. | Does not invoke Nikto; only the documented JSON shape is supported. |
| OWASP ZAP | Import-only | Parses recorded JSON alerts and maps risk/CWE/evidence fields. | Does not connect to ZAP or crawl/test a site; export variants may differ. |
| OpenVAS / Greenbone | Planned | None. | No parser or live API integration is implemented. |
| Burp Suite | Planned | None. | No parser, extension, or API integration is implemented. |
| Metasploit | Planned | Approval-gate logic exists independently. | No Metasploit adapter execution or active validation is implemented. |

## Shared limitations

- No live network scans are executed by this prototype.
- The assessment target list is entered by the user; the application does not independently verify authorization.
- Imported evidence is stored under the local `data/imports/` directory. Treat it as sensitive and do not commit it.
- Import size is limited to 2 MB per file. XML inputs with DTD/entity declarations are rejected.
- Qwen runs locally through Ollama and only proposes plans. It does not create findings, CVEs, CVSS scores, or evidence.
- PDF export requires a supported local renderer. If unavailable, the generated report is HTML.
