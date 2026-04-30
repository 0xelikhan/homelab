# Wazuh SIEM

Wazuh all-in-one (manager + indexer + dashboard) on Ubuntu 22.04. Primary detection platform for the lab — all host-based alerts flow through here.

- IP: 10.10.10.10 | Dashboard: https://10.10.10.10
- Agents: all 20 lab VMs enrolled
- Log sources: Sysmon (Windows), auditd (Linux), Suricata alerts via syslog, osquery

## Custom detection rules
Custom rules live in `local_rules.xml` and mirror the Sigma rules in the [detection-rules](https://github.com/YOUR-USERNAME/detection-rules) repo.

| Rule ID | Technique | Event Source | MITRE |
|---------|-----------|-------------|-------|
| 100001 | LSASS dump | Sysmon EID 10 | T1003.001 |
| 100002 | PowerShell encoded | Sysmon EID 1 | T1059.001 |
| 100003 | Registry run key | Sysmon EID 13 | T1547.001 |
| 100004 | Script + network tool | auditd EXECVE | T1059 |

## Attack scenarios tested
| Attack | MITRE | Detected | Rule |
|--------|-------|----------|------|
| LSASS dump via Task Manager | T1003.001 | | 100001 |
| PowerShell -EncodedCommand | T1059.001 | | 100002 |
| Registry run key persistence | T1547.001 | | 100003 |

## Detection gaps found
<!-- Fill in after running attack scenarios — this is the most important section -->

## Screenshots
<!-- Add after build -->
![Wazuh dashboard](screenshots/wazuh-dashboard.png)
![All agents enrolled](screenshots/wazuh-agents.png)
![Custom rule firing](screenshots/wazuh-custom-rule-alert.png)
