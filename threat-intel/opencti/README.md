# OpenCTI

| Item | Value |
|---|---|
| VM | 112 `thehive`, VLAN 10, 20 GB RAM, Elasticsearch heap 4 GB |
| Web UI | port 8080 |
| Version | 7.261019.0 |
| Runs as | docker compose: platform, Elasticsearch, Redis, RabbitMQ, Silo (MinIO replacement), 2 workers, connectors |

TheHive and Cortex run on the same VM.

## Connectors

Feeds:

| Connector | Source |
|---|---|
| mitre | ATT&CK |
| mitre-atlas | ATLAS (AI threats) |
| cisa-kev | CISA Known Exploited Vulnerabilities |
| misp | MISP, published events only |
| alienvault | OTX subscribed pulses |
| abuseipdb-blacklist | AbuseIPDB blacklist |
| abuse-ssl | abuse.ch SSL IP blacklist |
| criminalip-c2 | Criminal IP daily C2 feed |
| dshield | DShield block list |
| ransomwarelive | ransomware.live groups and victims |
| wiz | Wiz public cloud threat landscape |
| RSS ingestion | 164 blog, vendor, gov and community feeds, see [../feeds](../feeds/README.md) |

Enrichment (manual, from an observable's page): VirusTotal, AbuseIPDB, GreyNoise, CrowdSec, IPinfo, Shodan InternetDB, Google Safe Browsing, urlscan, Hybrid Analysis, FIRST EPSS (auto, scores CVEs).

Built in: export STIX/CSV/TXT, import STIX/YARA/documents, import external reference, OpenCTI datasets.

## Notes

- If the VM freezes, it ran out of memory. Check `free -m` and `docker stats`. Big RabbitMQ queues mean a connector is flooding.
- MinIO no longer publishes Docker images. `pgsty/silo` is the drop-in OpenCTI uses upstream. It needs the `x86-64-v2-AES` CPU type.
