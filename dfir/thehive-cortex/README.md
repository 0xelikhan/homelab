# TheHive and Cortex

| Item | Value |
|---|---|
| VM | 112 `thehive`, VLAN 10 (shared with OpenCTI) |
| TheHive | port 9000, path `/thehive`, version 6.0.0 |
| Cortex | port 9001, path `/cortex`, version 4.1.0 |
| Runs as | docker compose: Cassandra, Elasticsearch, TheHive, Cortex |

Based on StrangeBee's `testing` compose, without TheHive Flow and nginx.

## Connectors (TheHive)

| Name | Target |
|---|---|
| cortex-lab | Cortex, 32 analyzers |
| misp-lab | MISP, import and export |

## Cortex analyzers (32)

With API keys: VirusTotal, AbuseIPDB, OTX, urlscan (search and scan), IPinfo (details and hosted domains), CrowdSec, Google Safe Browsing, Pulsedive, Hybrid Analysis, MalwareBazaar, ThreatFox, URLhaus.

Keyless: CIRCL hashlookup, CIRCL vulnerability lookup, crt.sh, Robtex (IP, forward and reverse PDNS), Spamhaus DBL, TorProject, TorBlutmagie, DShield, StopForumSpam, EmailRep, Abuse_Finder, CyberCrime-Tracker, Mnemonic pDNS, UnshortenLink, FileInfo, MaxMind GeoIP.

Analyzers run as Docker containers. The first run of each one pulls its image.
