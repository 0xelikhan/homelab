# Architecture

## Host

| Item | Value |
|---|---|
| Hardware | Lenovo ThinkCentre M710q, 4 cores, 32 GB RAM |
| Hypervisor | Proxmox VE 9.2 |
| Bridge | VLAN-aware bridge. Each VM gets its VLAN by tag |

32 GB is not enough to run every VM at once. VMs are grouped with `lab-profile` (see [infrastructure/proxmox](../infrastructure/proxmox/README.md)).

## Storage

| Storage | Used for |
|---|---|
| local | ISOs, container templates |
| local-lvm (internal SSD) | pfSense, Wazuh, Velociraptor, DFIR-IRIS, DC01, web-01, Kali, n8n, LXCs |
| sandisk-1tb (USB) | MISP, TheHive/OpenCTI |
| ssd-enclosure (USB) | k8s-01, OpenCanary |

## VLANs

| VLAN | Purpose | Machines |
|---|---|---|
| 10 | SOC tools | Wazuh, Velociraptor, n8n, ElastAlert, DFIR-IRIS, MISP, TheHive/OpenCTI/Cortex, Hermes |
| 20 | Victim network | DC01, Metasploitable, OpenCanary |
| 30 | Attacker | Kali |
| 40 | Servers | web-01, k8s-01 |

## Data flow

```
Linux VMs, DC01 ── Wazuh agent ──► Wazuh ──► ElastAlert
All Linux VMs  ── Velociraptor client ──► Velociraptor
Honeypots (OpenCanary, Cowrie) ── logs via Wazuh agent ──► Wazuh

MISP feeds (abuse.ch, CIRCL, Botvrij, dataplane, ...) ──► MISP
OpenCTI connectors + 164 RSS feeds ──► OpenCTI ◄── MISP (published events)
TheHive ──► Cortex analyzers
TheHive ◄──► MISP

Collector (ransomware.live, deepdarkCTI) ──► local database ─┐
OpenCTI, MISP, Cortex (read only) ──────────────────────────┴─► Hermes ──► briefs
```
