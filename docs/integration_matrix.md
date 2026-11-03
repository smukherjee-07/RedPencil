# Integration matrix

| Integration | Planned module | Current status |
|---|---|---|
| Nmap | `app/tools/nmap_adapter.py` | Placeholder; not implemented |
| Nikto | `app/tools/nikto_adapter.py` | Placeholder; not implemented |
| OWASP ZAP | `app/tools/zap_adapter.py` | Placeholder; not implemented |
| Nessus | `app/tools/nessus_adapter.py` | Placeholder; not implemented |
| OpenVAS | `app/tools/openvas_adapter.py` | Placeholder; not implemented |
| Burp Suite | `app/tools/burp_adapter.py` | Placeholder; not implemented |
| Metasploit | `app/tools/metasploit_adapter.py` | Placeholder; not implemented |

Any future active integration requires explicit authorization, strict target
scope validation, and an approval gate. Importing existing reports should be
kept separate from launching assessment tools.
