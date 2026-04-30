# Atomic Red Team

Technique-level adversary simulation mapped directly to MITRE ATT&CK. Each test runs from the Windows victim or ThinkPad, and the matching detection in Wazuh is verified before the Sigma rule is committed.

## Tests run and detections verified
| Technique | MITRE ID | Detection fired |
|-----------|----------|----------------|
| LSASS dump via Task Manager | T1003.001 | |
| PowerShell -EncodedCommand | T1059.001 | |
| Disable Windows Defender | T1562.001 | |
| Clear Security event log | T1070.001 | |
| systeminfo.exe discovery | T1082 | |
| Registry run key persistence | T1547.001 | |
| Process injection | T1055 | |

## Screenshots
<!-- Add after build -->
![Atomic test running in PowerShell](screenshots/atomic-running.png)
![Wazuh alert firing from the test](screenshots/wazuh-atomic-alert.png)
