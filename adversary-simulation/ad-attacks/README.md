# Active Directory Attacks

AD attacks from Kali using Impacket, CrackMapExec, and BloodHound. All attacks target the lab.local domain built in [infrastructure/active-directory/](../../infrastructure/active-directory/).

## Attacks run
| Attack | Tool | MITRE | Event IDs | Detection |
|--------|------|-------|-----------|-----------|
| Kerberoasting | Impacket GetUserSPNs | T1558.003 | 4769 | |
| Pass-the-Hash | Impacket psexec | T1550.002 | 4624 LogonType=3 | |
| SMB enumeration | CrackMapExec | T1021.002 | 5140 | |
| Attack path mapping | BloodHound + SharpHound | T1069 | — | |
| secretsdump | Impacket | T1003.003 | — | |

## Screenshots
<!-- Add after build -->
![BloodHound attack path from low-priv user to DA](screenshots/bloodhound-path.png)
![Kerberoasting in Wazuh](screenshots/kerberoasting-alert.png)
![Pass-the-Hash event in Wazuh](screenshots/pass-the-hash-alert.png)
