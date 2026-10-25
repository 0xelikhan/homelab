# Wazuh

| Item | Value |
|---|---|
| VM | 101 `wazuh`, VLAN 10, 4 GB RAM, 60 GB disk |
| Web UI | port 443 |
| Version | 4.14.5 all-in-one (manager, indexer, dashboard) |

Main SIEM. Everything comes in through agents.

## Agents

| Agent | Sends |
|---|---|
| DC01 | Windows event logs, Sysmon (once installed) |
| web-01 | Apache, pingapp, auditd |
| velociraptor, n8n, dfir-iris, misp, thehive, opencanary, k8s-01 | auditd |
| opencanary | also OpenCanary and Cowrie logs |

Agents on stopped VMs show as disconnected. The agent version is held so it never gets ahead of the manager.

## On the VM

| What | Where |
|---|---|
| Custom rules | `local_rules.xml` |
| Detection rule repos | Elastic, Splunk, Sigma, Panther, Azure Sentinel, Hayabusa, SOF-ELK, ThreatHunter-Playbook |
| Sigma tooling | sigma-cli, Zircolite |
| Sysmon configs | sysmon-config, sysmon-modular |

## Planned rule checks

| Rule ID | Technique | Source | MITRE | Tested |
|---|---|---|---|---|
| 100001 | LSASS dump | Sysmon EID 10 | T1003.001 | no |
| 100002 | PowerShell encoded | Sysmon EID 1 | T1059.001 | no |
| 100003 | Registry run key | Sysmon EID 13 | T1547.001 | no |
| 100004 | Script plus network tool | auditd EXECVE | T1059 | no |
