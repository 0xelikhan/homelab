# n8n

| Item | Value |
|---|---|
| VM | 109 `n8n`, VLAN 10, 2 GB RAM |
| Web UI | port 5678 |
| Runs as | Docker container (`n8nio/n8n`) |

Has a Wazuh agent (auditd) and a Velociraptor client.

## Ideas to wire up

- ElastAlert webhook into n8n, then create a TheHive alert
- TheHive case closed, then push IOCs to MISP
- Copy each Hermes brief into notes or email
