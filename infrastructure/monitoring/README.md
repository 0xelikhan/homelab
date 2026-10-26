# Lab health check

| Item | Value |
|---|---|
| Runs on | Proxmox host, `/usr/local/bin/lab-health` |
| Schedule | `lab-health.timer`, every 15 minutes |
| Alerts | Telegram, through the same bot that sends the CTI briefs |
| State | `/var/lib/lab-health/state.json` |

Checks the CTI stack every run, and every other machine only while it is running. When a check fails it tries a known fix, then checks again.

| Result | Telegram message |
|---|---|
| Failing, fix worked | One message: what broke and that it was fixed |
| Failing, fix did not work | Alert, repeated every 6 hours while it stays broken |
| Back to normal | One message |

## Checks

| Check | Fix it tries |
|---|---|
| pfSense answers | |
| MISP web, API and containers | `docker compose up -d` |
| OpenCTI API and containers, TheHive and Cortex | `docker compose up -d`, restart TheHive and Cortex |
| OpenCTI connectors active, ingest backlog | |
| Hermes Telegram gateway | restart the gateway |
| Hermes collector | run the collector |
| Hermes brief jobs | resend a brief whose Telegram delivery failed (once per brief) |
| IOC export ran in the last 5 hours | run the export |
| Backups (errors in the last 2 days) | |
| Host disk over 85 %, host RAM under 1 GB | |
| Wazuh manager, indexer, dashboard | restart the stopped service |
| NSM sensor Suricata and Zeek | restart Suricata, start Zeek |
| CTI detection self-test (sensor and Wazuh running) | |
| Velociraptor, ElastAlert, honeypots, CAPE, DFIR-IRIS, n8n, Falco | restart the service or pod |

The self-test looks up `ioc-selftest.lab.invalid` from the OpenCTI VM and expects a Wazuh alert within two minutes. It proves the whole intel to detection path works: [IOC export](../../threat-intel/ioc-export/README.md), the port mirror, Suricata and Wazuh.

## Run it by hand

```bash
lab-health --dry-run        # prints results, sends nothing
systemctl start lab-health  # normal run
```
