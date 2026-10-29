# MISP

| Item | Value |
|---|---|
| VM | 111 `misp`, VLAN 10, 4 GB RAM |
| Web UI | port 443 |
| Version | MISP 2.5 via official misp-docker |

Containers: misp-core, misp-modules, nginx, mariadb, valkey, mail.

## Feeds (18 enabled)

| Feed | Format |
|---|---|
| CIRCL OSINT, Botvrij.eu, DigitalSide | MISP |
| URLhaus, ThreatFox, MalwareBazaar recent | CSV, abuse.ch v2 exports |
| Feodo IP blocklist, abuse.ch SSL IPBL | CSV |
| Tor exit nodes, blocklist.de, PhishTank, OpenPhish | freetext / CSV |
| Spamhaus DROP, ThreatView C2, Cybercrime-tracker, ET compromised IPs | freetext |
| dataplane.org (SSH, VNC), ViriBack C2, Phishing.Database | freetext |

Disabled 2026-10-29: CyberCure IP, URL and hash feeds (service returns 520), Spamhaus EDROP (retired, merged into DROP), the second OpenPhish feed (same data). abuse.ch SSL IPBL and DigitalSide time out from outside the lab too; left enabled in case they come back.

The CSV and freetext feeds are fetched as unpublished events, so bulk feed data stays in MISP. The MISP-format feeds (CIRCL, Botvrij, DigitalSide) arrive published, and OpenCTI imports the ones with a timestamp after `MISP_IMPORT_FROM_DATE` (2026-09-25), which keeps years of old OSINT out of OpenCTI.

Fetched and cached every 6 hours (`FETCH_FEED_INTERVAL` and `CACHE_FEED_INTERVAL` = 21600, `CRON_USER_ID=1` in `/opt/misp-docker/.env`). Each fetch adds attributes to the feed's existing event and bumps its timestamp but not its date, so search by timestamp: the Hermes briefs use [misp-recent](../hermes/tools/misp-recent). About 17,000 IDS attributes a day.
## Enrichment modules

With API keys: VirusTotal, AbuseIPDB, OTX, urlscan, IPinfo, GreyNoise, CrowdSec, Google Safe Browsing, URLhaus, MalwareBazaar, ThreatFox.
Keyless: CVE, vulnerability-lookup, RDAP, DNS, WHOIS, CIRCL hashlookup, Spamhaus DBL, QR code, Sigma and YARA syntax check.
