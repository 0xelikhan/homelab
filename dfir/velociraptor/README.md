# Velociraptor

| Item | Value |
|---|---|
| VM | 102 `velociraptor`, VLAN 10, 2 GB RAM |
| Group | `soc`, `purple` |
| Web UI | port 8889 |
| Version | 0.76.1 |

## Clients

| Machines | Client |
|---|---|
| Wazuh, n8n, DFIR-IRIS, MISP, TheHive VM, web-01, OpenCanary, ElastAlert, Hermes | service `velociraptor-client` |
| DC01 | Windows service `Velociraptor`, binary in `C:\Program Files\Velociraptor` |

Not yet: Kali, k8s-01.
