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

## Entity extraction from RSS

RSS reports arrive as text only. [rss-extract.py](rss-extract.py) (`rss-extract.timer`, every 30 minutes) asks ImportExternalReference for the article as Markdown and pushes it onto the report, so ImportDocument links the malware, actors, techniques, CVEs and observables it finds into that report. ImportExternalReference saves the article on the external reference, not the report, so without this step nothing gets linked.

| Connector | Setting | Why |
|---|---|---|
| ImportDocument | `CONNECTOR_VALIDATE_BEFORE_IMPORT=false` | extractions land instead of waiting in a draft |
| ImportDocument | `IMPORT_DOCUMENT_CREATE_INDICATOR=false` | example IPs and domains in blog posts would otherwise reach the ioc-export block lists |
| ImportExternalReference | `IMPORT_AS_PDF=false`, Markdown only | PDF is slow and adds nothing for extraction |

ImportDocument handles about one document every 5 seconds; a backlog of a few hundred is normal.

## Notes

- If the VM freezes, it ran out of memory. Check `free -m` and `docker stats`. Big RabbitMQ queues mean a connector is flooding.
- RabbitMQ and the 3 workers run with `nofile` 65536. Each RSS feed is a connector with its own queues, and at 420 feeds the default 1024 file handles ran out: the workers stopped picking up work, the RabbitMQ management API returned 500 and enrichment requests hung. `/usr/local/bin/octi-health` reports handle use, and lab-health checks it.
- After a restart, connectors that start before the platform is up can sit stuck without retrying. `/usr/local/bin/octi-restart` restarts RabbitMQ, the platform, then workers and connectors, in that order.
- Internal connectors don't refresh their heartbeat (`updated_at`) on this version; a consumer on their RabbitMQ queue is the real sign they are alive.
- MinIO no longer publishes Docker images. `pgsty/silo` is the drop-in OpenCTI uses upstream. It needs the `x86-64-v2-AES` CPU type.
