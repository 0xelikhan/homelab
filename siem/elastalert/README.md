# ElastAlert 2

| Item | Value |
|---|---|
| Container | LXC 103 `elastalert`, VLAN 10 |
| Access | `pct enter 103` from Proxmox |
| Service | `elastalert.service`. A drop-in (`wait-indexer.conf`) makes it wait up to 5 minutes for the Wazuh indexer at start |
| Reads from | Wazuh indexer |

Runs alert rules against the Wazuh indexer every minute.

| Rule | What it matches |
|---|---|
| `high_severity_wazuh.yaml` | High severity Wazuh alerts |

No alert destination is set yet. Add one (n8n webhook, Slack, email) to the rule's `alert:` section.

```bash
pct exec 103 -- systemctl status elastalert
```
