# DFIR-IRIS

| Item | Value |
|---|---|
| VM | 104 `dfir-iris`, VLAN 10, 4 GB RAM |
| Web UI | port 443 |
| Runs as | docker compose (app, worker, nginx, Postgres, RabbitMQ) |

Forensics-first case management. TheHive handles IR workflow, IRIS holds forensic case notes, evidence and timelines.

Has a Wazuh agent (auditd) and a Velociraptor client.
