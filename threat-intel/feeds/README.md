# Feeds

| File | What it is |
|---|---|
| [feeds.csv](feeds.csv) | 164 verified feeds: name, category, feed URL |
| [discover.py](discover.py) | Rebuilds `feeds.csv`. Finds the RSS link on each blog homepage and keeps only feeds that parse |

## Sources

| Source | Feeds |
|---|---|
| [awesome_threat_intel_blogs](https://github.com/muchdogesec/awesome_threat_intel_blogs) | 134 blogs with a working feed |
| vx-underground ThreatIntelligenceDiscordBot RSS list | Krebs, BleepingComputer, Securelist, Check Point, Red Canary, MSRC, NCSC, CIS, Recorded Future, Proofpoint, and others |
| Government | CISA advisories and ICS advisories, NCSC UK, CIS, Canadian Centre for Cyber Security, SANS ISC |
| Google Cloud Threat Intelligence (Mandiant) | `https://cloudblog.withgoogle.com/topics/threat-intelligence/rss/` |
| infosec.exchange hashtags | #threatintel #cti #malware #ransomware #ioc #cve #infosec #dfir |
| Media | The Record, CyberScoop, Security Affairs, Dark Reading, Infosecurity Magazine, The Hacker News |

## Not RSS

| Source | Where it goes |
|---|---|
| ransomware.live | OpenCTI connector and the Hermes collector |
| ransomwatch | Not used. Last update June 2025. ransomware.live replaces it |
| deepdarkCTI | Hermes collector tracks list changes daily |
| MISP feeds | See [../misp](../misp/README.md) |
