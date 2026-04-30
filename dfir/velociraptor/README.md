# Velociraptor DFIR

Velociraptor server with agents on all Windows and Linux endpoints. Used for threat hunting with VQL, YARA scanning across the fleet, and forensic artifact collection.

- IP: 10.10.10.11 | Web UI: https://10.10.10.11:8889

## VQL hunts run
| Hunt | What it finds | MITRE |
|------|-------------|-------|
| LSASS access | Processes reading lsass.exe memory | T1003.001 |
| Scheduled task persistence | New or modified scheduled tasks | T1053.005 |
| PowerShell encoded commands | Base64 in process command lines | T1059.001 |
| YARA fleet scan | File system scan against custom YARA rules | — |

## Screenshots
<!-- Add after build -->
![Velociraptor clients enrolled](screenshots/velociraptor-clients.png)
![Hunt results](screenshots/velociraptor-hunt.png)
![YARA scan output](screenshots/velociraptor-yara.png)
