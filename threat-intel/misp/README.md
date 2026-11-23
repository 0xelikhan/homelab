# MISP

| Item | Value |
|---|---|
| VM | 111 `misp`, VLAN 10, 4 GB RAM plus a 2 GB swap file (`vm.swappiness=10`) |
| Web UI | port 443 |
| Version | MISP 2.5 via official misp-docker |

Containers: misp-core, misp-modules, nginx, mariadb, valkey, mail.

## Feeds (27 enabled, plus 2 synced recent-only)

| Feed | Format |
|---|---|
| CIRCL OSINT, Botvrij.eu, DigitalSide, Infoblox Threat Intelligence, TweetFeed | MISP |
| URLhaus, ThreatFox, MalwareBazaar recent | CSV, abuse.ch v2 exports |
| Feodo IP blocklist, abuse.ch SSL IPBL, Threatview.io C2 Hunt, ET compromised IPs | CSV |
| Tor exit nodes, blocklist.de, PhishTank, OpenPhish, Phishing.Database, crypto-scam URLs | freetext / CSV |
| Spamhaus DROP, ViriBack C2, C2IntelFeeds (IPs, domains) | freetext |
| dataplane.org (SSH password auth, SSH client, VNC) | CSV / freetext |
| HoneyLabs malware infrastructure, APNIC URLs seen in honeypots | freetext |

Disabled 2026-10-29: CyberCure IP, URL and hash feeds (service returns 520), Spamhaus EDROP (retired, merged into DROP), the second OpenPhish feed (same data). Disabled 2026-11-12: abuse.ch's MISP-format ThreatFox, MalwareBazaar and URLhaus feeds (retired upstream, 410 Gone; the v2 exports above replace them). DigitalSide times out upstream; left enabled in case it comes back.

### Recent-only feeds

Rösti (report-derived IOCs, about 10,900 events) and PrecisionSec are too large to fetch whole on 4 GB. They stay disabled as normal feeds and are imported by `/usr/local/bin/misp-feed-sync <feed id> <days>`, which reads the feed manifest and imports only events updated in the last N days, pausing when available memory drops under 400 MB.

| Job | When | What |
|---|---|---|
| `misp-feed-sync.timer` | daily 05:30 UTC | Rösti (feed 84) and PrecisionSec (feed 99), last 2 days |

Rösti events arrive published, so OpenCTI imports them through its MISP connector.

### Keeping the database lean

Every CSV and freetext feed uses delta merge: each fetch keeps only the values currently on the list and marks the rest deleted. Deleted values stay in the database until purged.

| Job | When | What |
|---|---|---|
| `misp-feed-purge.timer` | Sunday 06:45 UTC (after the 06:00 feed fetch) | `/usr/local/bin/misp-feed-purge` rebuilds each list feed that holds deleted values (MISP's `purgeFeedEvents`, then a fresh fetch), then `misp-compact-attributes` runs `OPTIMIZE TABLE attributes` to give the space back to the disk |

Both scripts wait while available memory is low. A rebuilt feed gets a new event ID; nothing in the lab refers to feed events by ID. If a scheduled fetch adds values to a feed event while it is being deleted, the purge removes those leftover rows and their correlations afterwards.

MariaDB's buffer pool is 1.5 GB (`INNODB_BUFFER_POOL_SIZE=1536M` in `/opt/misp-docker/.env`). The misp-docker default of 2 GB leaves a 4 GB VM with about 300 MB to spare once the pool fills.

The CSV and freetext feeds are fetched as unpublished events, so bulk feed data stays in MISP. The MISP-format feeds (CIRCL, Botvrij, DigitalSide) arrive published, and OpenCTI imports the ones with a timestamp after `MISP_IMPORT_FROM_DATE` (2026-09-25), which keeps years of old OSINT out of OpenCTI.

Fetched and cached every 6 hours (`FETCH_FEED_INTERVAL` and `CACHE_FEED_INTERVAL` = 21600, `CRON_USER_ID=1` in `/opt/misp-docker/.env`). Each fetch adds attributes to the feed's existing event and bumps its timestamp but not its date, so search by timestamp: the Hermes briefs use [misp-recent](../hermes/tools/misp-recent). About 17,000 IDS attributes a day.
## Enrichment modules

With API keys: VirusTotal, AbuseIPDB, OTX, urlscan, IPinfo, GreyNoise, CrowdSec, Google Safe Browsing, URLhaus, MalwareBazaar, ThreatFox.
Keyless: CVE, vulnerability-lookup, RDAP, DNS, WHOIS, CIRCL hashlookup, Spamhaus DBL, QR code, Sigma and YARA syntax check.
