# Wazuh

| Item | Value |
|---|---|
| VM | 101 `wazuh`, VLAN 10, 4 GB RAM, 60 GB disk |
| Group | `soc`, `purple` |
| Web UI | port 443 |
| Version | 4.14.5 all-in-one (manager, indexer, dashboard) |

Main SIEM. Everything comes in through agents.

## Agents

| Agent | Sends |
|---|---|
| DC01 | Windows event logs, Sysmon, PowerShell operational log |
| nsm-sensor | Suricata alerts (eve.json), Zeek notice.log |
| web-01 | Apache, pingapp, auditd |
| velociraptor, n8n, dfir-iris, misp, thehive, opencanary, k8s-01 | auditd |
| opencanary | also OpenCanary and Cowrie JSON logs |

Agents on stopped VMs show as disconnected. The agent version is held so it never gets ahead of the manager.

## Custom rules

[local_rules.xml](local_rules.xml), installed at `/var/ossec/etc/rules/local_rules.xml`. Test before restarting:

```bash
sudo /var/ossec/bin/wazuh-analysisd -t && sudo systemctl restart wazuh-manager
```

| ID | What | MITRE | Tested |
|---|---|---|---|
| 100001 | Task Manager reading LSASS | T1003.001 | no |
| 100002 | PowerShell encoded command | T1059.001 | yes, fires on `powershell -EncodedCommand` |
| 100200, 100201 | osquery results, outbound connections | T1071 | no |
| 100300 | LSASS access by anything except known system processes | T1003.001 | yes, agent false positive tuned out |
| 100301 | PowerShell encoded command (longer payloads) | T1059.001 | no |
| 100302 | Kerberoasting, RC4 service ticket | T1558.003 | no |
| 100303 | Atomic Red Team marker in a command line | | no |
| 100304 | BloodHound / SharpHound | T1087.002 | no |
| 100305 | Admin share access | T1021.002 | no |
| 100306 | NTLM network logon | T1550.002 | no |
| 100307 | User added to Administrators | T1098 | no |
| 100308 | Long DNS query | T1071.004 | no |
| 100361 | Honeypot port probe | T1046 | yes |
| 100362 | Honeypot service interaction (login, query) | T1078 | yes |
| 100371 | Cowrie SSH login attempt | T1110 | yes |
| 100372 | Command typed into Cowrie | T1059 | yes |

Notes from tuning:

| Gotcha | Fix |
|---|---|
| Wazuh's Sysmon process-creation group is `sysmon_event1` (no underscore). Other event IDs use `sysmon_event_10`, `sysmon_event_22` | Use the exact group names from `0595-win-sysmon_rules.xml` |
| The default regex engine has no groups or character classes | Add `type="pcre2"` to the field |
| `negate` is not accepted on `<field>` in this version | Write a positive pattern or a PCRE2 negative lookahead |
| Honeypot JSON has no field that names the product | Match on `<location>` (the log file path) |

## On the VM

| What | Where |
|---|---|
| Detection rule repos | Elastic, Splunk, Sigma, Panther, Azure Sentinel, Hayabusa, SOF-ELK, ThreatHunter-Playbook |
| Sigma tooling | sigma-cli, Zircolite |
| Sysmon configs | sysmon-config, sysmon-modular |
