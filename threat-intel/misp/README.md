# MISP

| Item | Value |
|---|---|
| VM | 111 `misp`, VLAN 10, 4 GB RAM |
| Web UI | port 443 |
| Version | MISP 2.5 via official misp-docker |

Containers: misp-core, misp-modules, nginx, mariadb, valkey, mail.

## Feeds (23 enabled)

| Feed | Format |
|---|---|
| CIRCL OSINT, Botvrij.eu, DigitalSide | MISP |
| URLhaus, ThreatFox, MalwareBazaar recent | CSV, abuse.ch v2 exports |
| Feodo IP blocklist, abuse.ch SSL IPBL | CSV |
| Tor exit nodes, blocklist.de, PhishTank, OpenPhish, CyberCure | freetext / CSV |
| Spamhaus DROP and EDROP, ThreatView C2, Cybercrime-tracker, ET compromised IPs | freetext |
| dataplane.org (SSH, VNC), ViriBack C2, Phishing.Database | freetext |

Feeds are fetched as unpublished events. OpenCTI only imports published events, so bulk feed data stays in MISP.

## Enrichment modules

With API keys: VirusTotal, AbuseIPDB, OTX, urlscan, IPinfo, GreyNoise, CrowdSec, Google Safe Browsing, URLhaus, MalwareBazaar, ThreatFox.
Keyless: CVE, vulnerability-lookup, RDAP, DNS, WHOIS, CIRCL hashlookup, Spamhaus DBL, QR code, Sigma and YARA syntax check.
