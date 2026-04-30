# homelab

A production-style security operations lab running 20 VMs across 6 segmented VLANs on a Proxmox hypervisor. Built to develop and validate detection engineering skills across the full attack lifecycle.

## Architecture

| Layer | Tools |
|-------|-------|
| Hypervisor | Proxmox VE 8.x — ThinkCentre, 32GB RAM |
| Firewall / IDS | pfSense CE + Suricata |
| SIEM | Wazuh + Graylog + ElastAlert |
| DFIR | Velociraptor + DFIR-IRIS + TheHive + Cortex |
| Network Security | Security Onion + Zeek + Wireshark |
| Threat Intel / SOAR | MISP + n8n |
| Endpoint Visibility | osquery + Sysmon + auditd |
| Adversary Simulation | Atomic Red Team + MITRE CALDERA + Metasploit |
| Active Directory | Windows Server 2022 DC + BadBlood + BloodHound |
| Containers | MicroK8s + Falco + FluentBit |
| Malware Analysis | Cuckoo Sandbox + FLARE-VM |
| Deception | OpenCanary + Canarytokens |
| Automation | Ansible + Tailscale |

## VLAN Segmentation

| VLAN | Network | Purpose |
|------|---------|---------|
| 10 | 10.10.10.0/24 | SOC tools — Wazuh, Velociraptor, ElastAlert, IRIS |
| 20 | 10.10.20.0/24 | Victim network — AD DC, Windows 11, honeypot |
| 30 | 10.10.30.0/24 | Attacker — Kali Linux |
| 40 | 10.10.40.0/24 | Servers — web app, Kubernetes |
| 50 | 10.10.50.0/24 | Monitoring — Security Onion span port |
| 99 | 10.10.99.0/24 | Isolated — Cuckoo, FLARE-VM, no internet |

## Structure

```
homelab/
├── architecture/           Network diagram, VLAN design, VM inventory
├── infrastructure/
│   ├── proxmox/            Hypervisor setup, VLAN-aware bridge, VM plan
│   ├── ansible/            Playbooks and roles for all VM provisioning
│   ├── active-directory/   DC setup, BadBlood, audit policies
│   ├── kubernetes/         MicroK8s, Falco, FluentBit, audit policy
│   └── tailscale/          Remote access, subnet routing
├── siem/
│   ├── wazuh/              All-in-one install, agents, custom rules
│   ├── graylog/            Log normalization pipeline
│   └── elastalert/         Detection alerting from Wazuh/Elastic index
├── network/
│   ├── pfsense-suricata/   Firewall rules, VLAN config, IDS
│   ├── security-onion-zeek/ NSM, full PCAP, Zeek logs
│   └── wireshark/          PCAP analysis workflow
├── dfir/
│   ├── velociraptor/       Server, VQL hunts, YARA scanning
│   ├── dfir-iris/          Case management, ElastAlert integration
│   ├── thehive-cortex/     Incident management, automated enrichment
│   └── malware-analysis/   Cuckoo Sandbox + FLARE-VM workflow
├── threat-intel/
│   ├── misp/               Threat intel feeds, IOC management
│   └── n8n-soar/           SOAR automation workflows
├── adversary-simulation/
│   ├── atomic-red-team/    ATT&CK technique tests, detection validation
│   ├── caldera/            Full adversary emulation campaigns
│   ├── metasploit/         Exploitation, privilege escalation scenarios
│   └── ad-attacks/         Kerberoasting, Pass-the-Hash, BloodHound
├── endpoint-visibility/
│   └── osquery/            SQL-based endpoint queries, Wazuh integration
├── deception/
│   ├── opencanary/         Network honeypot in victim VLAN
│   └── canarytokens/       File-based traps on victim endpoints
└── web-app/                Vulnerable Flask app, Burp Suite, OWASP ZAP, WAF
```

## Detection rules

Sigma rules and YARA rules built and tested in this lab live in a dedicated repo:
[detection-rules](https://github.com/YOUR-USERNAME/detection-rules)

## Cloud lab

AWS and Microsoft Sentinel work is in a dedicated repo:
[cloud](https://github.com/YOUR-USERNAME/cloud)

## Detection tools

Custom Python tools built to extend this lab's capability:
[scripts](https://github.com/YOUR-USERNAME/scripts)
