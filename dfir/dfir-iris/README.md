# DFIR-IRIS Case Management

DFIR-IRIS receives webhooks from ElastAlert and auto-creates investigation cases when a detection rule fires. Closes the full loop from alert to documented case without manual intervention.

- IP: 10.10.10.14 | Web UI: https://10.10.10.14

## Integration
ElastAlert → webhook → DFIR-IRIS → case created with alert context, IOCs, and timeline

## Screenshots
<!-- Add after build -->
![DFIR-IRIS case auto-created from detection](screenshots/iris-auto-case.png)
![Case timeline and IOCs](screenshots/iris-case-timeline.png)
