# ElastAlert Detection Pipeline

ElastAlert 2 polls the Wazuh/Elastic index and fires alerts when a rule matches. Webhooks post to DFIR-IRIS automatically — closing the loop from detection to case creation without manual steps.

- IP: 10.10.10.13 (Ubuntu container)
- Index: wazuh-alerts-*
- Destination: DFIR-IRIS webhook → auto-creates investigation case

## Pipeline flow
```
Sigma rule pushed → GitHub Actions validates → ElastAlert rule deployed →
Wazuh alert fires → ElastAlert polls index → DFIR-IRIS case auto-created
```

## Screenshots
<!-- Add after build -->
![ElastAlert running and polling](screenshots/elastalert-running.png)
![DFIR-IRIS case auto-created from ElastAlert](screenshots/dfir-iris-auto-case.png)
