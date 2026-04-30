# Architecture

Full lab architecture documentation — network topology, VLAN design, and VM inventory.

## Network Topology

20 VMs across 6 VLANs on a Proxmox hypervisor. pfSense handles routing and firewall rules between VLANs. Suricata runs on the victim-facing interface. Security Onion sits on a span port seeing all victim traffic passively.

## VM Inventory

| VM | OS | RAM | Disk | VLAN | IP | Purpose |
|----|----|-----|------|------|----|---------|
| pfsense | pfSense CE | 2GB | 20GB | trunk | gateway | Firewall, DHCP, DNS |
| wazuh | Ubuntu 22.04 | 8GB | 100GB | 10 | 10.10.10.10 | SIEM all-in-one |
| velociraptor | Ubuntu 22.04 | 2GB | 30GB | 10 | 10.10.10.11 | DFIR |
| n8n | Ubuntu CT | 2GB | 20GB | 10 | 10.10.10.12 | SOAR |
| elastalert | Ubuntu CT | 2GB | 20GB | 10 | 10.10.10.13 | Alerting |
| dfir-iris | Ubuntu CT | 2GB | 20GB | 10 | 10.10.10.14 | Case management |
| splunk | Ubuntu 22.04 | 4GB | 50GB | 10 | 10.10.10.25 | Splunk SIEM |
| graylog | Ubuntu 22.04 | 4GB | 50GB | 10 | 10.10.10.20 | Log ingestion |
| misp | Ubuntu 22.04 | 4GB | 30GB | 10 | 10.10.10.21 | Threat intel |
| thehive | Ubuntu 22.04 | 4GB | 30GB | 10 | 10.10.10.22 | Case management |
| security-onion | Security Onion | 8GB | 200GB | 50 | 10.10.50.10 | NSM, Zeek, PCAP |
| win-dc01 | Windows Server 2022 | 4GB | 60GB | 20 | 10.10.20.10 | Active Directory DC |
| win11-victim | Windows 11 | 4GB | 40GB | 20 | 10.10.20.20 | Domain victim |
| opencanary | Ubuntu 22.04 | 1GB | 10GB | 20 | 10.10.20.99 | Honeypot |
| flare-vm | Windows 10 | 4GB | 80GB | 99 | 10.10.99.10 | Malware analysis |
| cuckoo | Ubuntu 20.04 | 4GB | 60GB | 99 | 10.10.99.11 | Sandbox |
| kali | Kali Linux | 4GB | 40GB | 30 | DHCP | Attacker |
| web-01 | Ubuntu 22.04 | 2GB | 30GB | 40 | 10.10.40.10 | Vulnerable web app |
| k8s-01 | Ubuntu 22.04 | 4GB | 40GB | 40 | 10.10.40.20 | Kubernetes master |
| k8s-02 | Ubuntu 22.04 | 2GB | 30GB | 40 | 10.10.40.21 | Kubernetes worker |

## Screenshots
<!-- Add after build -->
![Network topology diagram](screenshots/network-topology.png)
