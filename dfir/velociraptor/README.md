# Velociraptor

| Item | Value |
|---|---|
| VM | 102 `velociraptor`, VLAN 10, 2 GB RAM |
| Web UI | port 8889 |
| Version | 0.76.1 |

DFIR collection and hunting (VQL artifacts, YARA hunts) across every Linux machine.

## Clients

Service `velociraptor-client` on: Wazuh, n8n, DFIR-IRIS, MISP, TheHive VM, web-01, OpenCanary, ElastAlert, Hermes.

Not yet: Kali, k8s-01 (stopped VMs), DC01 (Windows MSI from the GUI, `Server.Utils.CreateMSI`).
