# pfSense

| Item | Value |
|---|---|
| VM | 100 `pfsense`, 2 cores, 1 GB RAM |
| Version | pfSense 2.8.1 |
| Interfaces | WAN to the home network, LAN trunk with one VLAN sub-interface per lab VLAN |
| Boots | first |

Router, firewall and NAT for every lab VLAN.

| VLAN | Purpose |
|---|---|
| 10 | SOC tools |
| 20 | Victim network |
| 30 | Attacker |
| 40 | Web / Kubernetes |
| 50 | NSM (empty) |
| 99 | Malware, no internet (empty) |
