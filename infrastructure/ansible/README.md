# Ansible Automation

Ansible runs from ThinkPad WSL and provisions all lab VMs simultaneously. Every agent install, auditd rule, and Sysmon deployment is automated — rebuilding any VM means re-running one playbook.

**Note:** `inventory/hosts.yml` is excluded from this repo via `.gitignore` — it contains real lab IPs.

## Roles
| Role | What it does |
|------|-------------|
| wazuh-agent-linux | Installs and enrolls Wazuh agent, sets manager to 10.10.10.10 |
| wazuh-agent-windows | WinRM-based Wazuh agent install |
| velociraptor-agent | Deploys Velociraptor agent and enrolls to server |
| auditd | Deploys audit rules: /etc/, /root/, all execve syscalls |
| sysmon | Installs Sysmon with SwiftOnSecurity config on Windows endpoints |

## Screenshots
<!-- Add after build -->
![Ansible playbook run — all green, no failed](screenshots/ansible-run-success.png)
