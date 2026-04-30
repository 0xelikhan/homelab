# pfSense + Suricata

pfSense CE is the lab router and firewall. Suricata runs on the victim-facing interface (OPT2) for network-level detection. All Suricata alerts forward to Wazuh via syslog on port 514.

- pfSense: 2 cores, 2GB RAM, WAN + LAN trunk interfaces
- Suricata: Emerging Threats Open rules + custom rules below
- Alerts → Wazuh syslog 10.10.10.10:514

## Firewall rules (key entries)
| Source | Destination | Action | Reason |
|--------|-------------|--------|--------|
| Attacker VLAN | Victim VLAN | Allow | Kali reaches victims |
| Attacker VLAN | SOC VLAN | Block | Kali cannot touch SOC tools |
| Isolated VLAN | WAN | Block | No internet for malware VMs |

## Custom Suricata rules written
- SSH brute force: 5 attempts / 60 seconds
- NMAP SYN scan: 20 SYN packets / 3 seconds
- DNS tunneling: PCRE on queries > 50 characters
- SMB lateral movement: external source to port 445

## Attack scenarios tested
| Attack | MITRE | Detected | Rule |
|--------|-------|----------|------|
| Nmap SYN scan from Kali | T1046 | | sid:1000002 |
| SSH brute force | T1110 | | sid:1000001 |
| DNS tunneling | T1071.004 | | sid:1000003 |

## Detection gaps found
<!-- Fill in after scenarios -->

## Screenshots
<!-- Add after build -->
![pfSense dashboard all interfaces](screenshots/pfsense-dashboard.png)
![Suricata alert from Nmap scan](screenshots/suricata-nmap-alert.png)
![Firewall rules table](screenshots/firewall-rules.png)
