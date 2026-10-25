# Home Lab

Proxmox VE 9.2 on a Lenovo ThinkCentre M710q (4 cores, 32 GB RAM). Lab networks sit behind pfSense on separate VLANs.

## Machines

Group = the `lab-profile` group that starts and stops it. See [infrastructure/proxmox](infrastructure/proxmox/README.md).

| ID | Name | Type | Group | What it does | Docs |
|---|---|---|---|---|---|
| 100 | pfsense | VM | core | Router, firewall, NAT for every lab VLAN | [network/pfsense-suricata](network/pfsense-suricata/README.md) |
| 101 | wazuh | VM | core | Main SIEM. Agents on every Linux VM and DC01 | [siem/wazuh](siem/wazuh/README.md) |
| 102 | velociraptor | VM | core | DFIR and hunting server. Clients on every Linux machine | [dfir/velociraptor](dfir/velociraptor/README.md) |
| 103 | elastalert | LXC | core | Alert rules on the Wazuh indexer | [siem/elastalert](siem/elastalert/README.md) |
| 104 | dfir-iris | VM | core | Forensic case management | [dfir/dfir-iris](dfir/dfir-iris/README.md) |
| 105 | win-dc01 | VM | attack | Active Directory domain controller | [infrastructure/active-directory](infrastructure/active-directory/README.md) |
| 106 | web-01 | VM | core | Vulnerable web app (Apache, ModSecurity, pingapp) | [web-app](web-app/README.md) |
| 107 | kali | VM | attack | Attack box | [adversary-simulation](adversary-simulation/README.md) |
| 108 | metasploitable2 | VM | attack | Intentionally vulnerable target | [adversary-simulation/metasploit](adversary-simulation/metasploit/README.md) |
| 109 | n8n | VM | core | SOAR workflows | [threat-intel/n8n-soar](threat-intel/n8n-soar/README.md) |
| 111 | misp | VM | core | Threat intel feeds, sharing, enrichment modules | [threat-intel/misp](threat-intel/misp/README.md) |
| 112 | thehive | VM | core | OpenCTI 7, TheHive 6, Cortex 4 | [threat-intel/opencti](threat-intel/opencti/README.md), [dfir/thehive-cortex](dfir/thehive-cortex/README.md) |
| 115 | k8s-01 | VM | k8s | MicroK8s with Falco, Fluent Bit, Trivy | [infrastructure/kubernetes](infrastructure/kubernetes/README.md) |
| 118 | opencanary | VM | core | OpenCanary and Cowrie honeypots | [deception/opencanary](deception/opencanary/README.md) |
| 120 | hermes | LXC | core | Hermes Agent: daily and weekly CTI briefs, IOC lookups | [threat-intel/hermes](threat-intel/hermes/README.md) |

## Folders

```
architecture/            Network layout, data flow
infrastructure/
  proxmox/               Host, storage, lab-profile groups
  active-directory/      DC01
  kubernetes/            k8s-01
  tailscale/             Remote access
siem/                    wazuh, elastalert
dfir/                    velociraptor, dfir-iris, thehive-cortex
threat-intel/            opencti, misp, hermes, feeds, n8n-soar
network/                 pfsense-suricata, wireshark
deception/               opencanary, Azure-HoneyPot, GCP-HoneyPot
adversary-simulation/    kali tools, metasploit, ad-attacks
web-app/                 web-01
```
