# Metasploit

Real exploitation scenarios from Kali against the victim network. Used to generate authentic attack traffic and verify the full detection chain end to end.

## Scenarios run
| Scenario | Target | MITRE | Detection |
|----------|--------|-------|-----------|
| EternalBlue → shell | win11-victim | T1210 | |
| Shell → Meterpreter → privilege escalation | win11-victim | T1068 | |
| Post-exploitation: hashdump | win11-victim | T1003.002 | |

## Screenshots
<!-- Add after build -->
![Metasploit session open](screenshots/metasploit-session.png)
![Wazuh alert from exploitation](screenshots/wazuh-exploit-alert.png)
