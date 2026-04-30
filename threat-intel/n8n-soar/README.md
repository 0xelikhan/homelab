# n8n SOAR Automation

n8n automates the response side of the detection pipeline — no manual steps between alert and action.

- IP: 10.10.10.12:5678 | Web UI: http://10.10.10.12:5678

## Workflows built
| Workflow | Trigger | Action |
|----------|---------|--------|
| Alert triage | Wazuh webhook | Enrich with VirusTotal, post to Slack |
| IOC blocking | MISP new indicator | Push block rule to pfSense |
| Case creation | High-severity alert | Auto-create DFIR-IRIS case with context |

## Screenshots
<!-- Add after build -->
![n8n workflow canvas](screenshots/n8n-workflow.png)
![Workflow execution log](screenshots/n8n-execution.png)
