# Home Lab


## Architecture

| Layer | Tools |
|-------|-------|
| Hypervisor | Proxmox VE 8.x |
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


