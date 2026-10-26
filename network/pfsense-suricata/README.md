# pfSense

| Item | Value |
|---|---|
| VM | 100 `pfsense`, 2 cores, 1 GB RAM |
| Version | pfSense 2.8.1 |
| Interfaces | WAN to the home network, LAN trunk with one VLAN sub-interface per lab VLAN |
| Boots | first |
| Web UI | HTTPS (http redirects). Admin over SSH with a key |

Router, firewall and NAT for every lab VLAN.

| VLAN | Purpose |
|---|---|
| 10 | SOC tools |
| 20 | Victim network |
| 30 | Attacker |
| 40 | Web / Kubernetes |
| 50 | Not used. The NSM sensor is managed from the SOC VLAN |
| 99 | Malware, no internet (FLARE-VM, CAPE) |

## Firewall policy

| VLAN | Can reach |
|---|---|
| SOC (10) | Everything, for management |
| Victim (20) | pfSense DNS and NTP, SOC agent ports, attacker VLAN, internet |
| Attacker (30) | pfSense DNS and NTP, SOC agent ports, victim and server VLANs, internet |
| Servers (40) | pfSense DNS and NTP, SOC agent ports, internet |
| Malware (99) | Nothing |

Everything else between lab VLANs and to the home network is blocked. Rules are tagged `LAB:` in the rule descriptions.

IDS runs on the [NSM sensor](../nsm-sensor/README.md), which gets a copy of all LAN traffic, not on pfSense itself.
