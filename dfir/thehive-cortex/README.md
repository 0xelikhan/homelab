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

Custom: CAPE_File_Analysis (see below).

Analyzers run as Docker containers. The first run of each one pulls its image.

## CAPE_File_Analysis

Sends a file from a TheHive case to the lab [CAPE sandbox](../../malware-analysis/cape/README.md), waits for the report, and returns the CAPE score, malware family, signatures, contacted hosts and domains, and dropped files. The score becomes a taxonomy (safe below 4, suspicious 4 to 7, malicious 7 and up).

| Piece | Where |
|---|---|
| Code, Dockerfile, definition | [analyzers/CAPE/](analyzers/CAPE/) |
| Definition on the VM | `cortex/neurons/analyzers/CAPE/CAPE_File_Analysis.json` (Cortex loads local analyzers from `/opt/cortexneurons/analyzers`) |
| Image | `lab/cape-analyzer:1.0`, built on VM 112 |

CAPE is in the `malware` group, so start it before running the analyzer. A detonation takes about 4 minutes.
