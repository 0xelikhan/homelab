# Graylog Log Ingestion

Graylog normalizes and indexes logs from multiple sources before they reach Wazuh — useful for parsing non-standard log formats and enriching events before alerting.

- IP: 10.10.10.20 | Web UI: http://10.10.10.20:9000
- Inputs: syslog UDP 514, GELF

## Screenshots
<!-- Add after build -->
![Graylog inputs and message count](screenshots/graylog-inputs.png)
![Log stream showing normalized events](screenshots/graylog-stream.png)
