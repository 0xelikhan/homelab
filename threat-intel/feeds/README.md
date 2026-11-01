# Feeds

| File | What it is |
|---|---|
| [feeds.csv](feeds.csv) | 200 verified feeds: name, category, feed URL. The hand-curated core |
| [live-feeds.csv](live-feeds.csv) | Snapshot of all 438 RSS ingestions registered live in OpenCTI (432 running), exported for disaster recovery. Superset of `feeds.csv`, includes OPML imports and later additions |
| [discover.py](discover.py) | Rebuilds `feeds.csv`. Finds the RSS link on each blog homepage and keeps only feeds that parse |
| [restore.py](restore.py) | Reloads `live-feeds.csv` into a fresh OpenCTI. Run on the OpenCTI host as root. Skips feeds already registered, safe to re-run |

## Sources

| Source | Feeds |
|---|---|
| [awesome_threat_intel_blogs](https://github.com/muchdogesec/awesome_threat_intel_blogs) | 134 blogs with a working feed |
| vx-underground ThreatIntelligenceDiscordBot RSS list | Krebs, BleepingComputer, Securelist, Check Point, Red Canary, MSRC, NCSC, CIS, Recorded Future, Proofpoint, and others |
| Government | CISA advisories and ICS advisories, NCSC UK, CIS, Canadian Centre for Cyber Security, SANS ISC |
| Google Cloud Threat Intelligence (Mandiant) | `https://cloudblog.withgoogle.com/topics/threat-intelligence/rss/` |
| infosec.exchange hashtags | #threatintel #cti #malware #ransomware #ioc #cve #infosec #dfir |
| Media | The Record, CyberScoop, Security Affairs, Dark Reading, Infosecurity Magazine, The Hacker News |
| [jozeta/ThreatFeed](https://github.com/jozeta/ThreatFeed) | 36 DFIR, PSIRT, CERT, vuln and threat-intel feeds (watchTowr, PortSwigger, Volexity, Inversecos, CVEFeed.io, CERTs, distro security notices, …), deconflicted against the existing list |

## Not RSS

| Source | Where it goes |
|---|---|
| ransomware.live | OpenCTI connector and the Hermes collector |
| ransomwatch | Not used. Last update June 2025. ransomware.live replaces it |
| deepdarkCTI | Hermes collector tracks list changes daily |
| MISP feeds | See [../misp](../misp/README.md) |
