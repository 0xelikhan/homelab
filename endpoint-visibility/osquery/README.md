# osquery Endpoint Visibility

osquery on all Windows and Linux VMs. Scheduled queries run every 5-15 minutes and ship results to Wazuh. Enables SQL-based hunting across all endpoints simultaneously.

## Detection queries scheduled
| Query | Detects | MITRE |
|-------|---------|-------|
| Listening ports (delta) | Unexpected new service or backdoor | T1049 |
| Startup items | Registry or cron persistence | T1547 |
| Users with no password (Linux) | Credential weakness | T1078 |
| Processes with deleted binaries | In-memory execution | T1055 |
| Cron jobs | Scheduled task persistence | T1053.003 |

## Screenshots
<!-- Add after build -->
![osquery query results in terminal](screenshots/osquery-query.png)
![Wazuh showing osquery scheduled results](screenshots/wazuh-osquery.png)
