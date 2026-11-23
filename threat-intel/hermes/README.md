# Hermes Agent

| Item | Value |
|---|---|
| Container | LXC 120 `hermes`, VLAN 10, Ubuntu 24.04, 2 GB RAM, unprivileged |
| Group | `cti` (always on) |
| Delivery | Telegram bot, paired to one account |
| Version | Hermes Agent (Nous Research), stable channel |
| Model | Anthropic Claude Sonnet |

```bash
pct enter 120
su - hermes
hermes cron list
hermes -z "what do we know about <indicator>" --skills cti-ioc-lookup
```

## Provisioning

[`setup-hermes.sh`](setup-hermes.sh) runs once as the `hermes` user inside CT 120: clones/updates the Liberty91 cti-skills repo, links the skills, installs the Python deps for the CLI lookups, pulls MITRE ATT&CK data, and writes Hermes' `.env`. It reads API keys from `~/.setup-secrets` ([template](setup-secrets.example)) and deletes that file after reading. The keys are a subset of `pve:/root/lab-secrets.env`; they never live in this repo. MISP is `10.10.10.21`, OpenCTI is `10.10.10.22:8080` (co-located on VM 112).

## Scheduled jobs

All jobs deliver to Telegram. Failures are sent there too.

| Job | When | Output |
|---|---|---|
| daily-cti-brief | 07:00 every day | short summary message, full brief attached as a file |
| weekly-cti-roundup | Monday 08:00 | short summary message, full roundup attached as a file |
| fin-ransomware-flash | every 2 h, only when new financial-sector victims appear | flash note |
| exploit-flash | every 15 min, only when something escalates | alert list, no model |
| darkweb-flash | every 15 min, only when the dark-web pipeline keeps a new sample | sample note, no model |

The briefs attach the saved Markdown file with a `MEDIA:<path>` line at the end of the response.

The flash uses `~/.hermes/scripts/fin-victims-monitor.py`. A victim counts as financial when ransomware.live tags its sector as Financial Services. When the sector is missing, the victim name or domain decides. Victims the source mis-tags as financial go in `~/.hermes/scripts/fin-exclude.txt`, one name per line.

exploit-flash runs [`scripts/exploit-flash.py`](scripts/exploit-flash.py) from `~/.hermes/scripts/` as a script-only job: its output goes to Telegram as is, and an empty run sends nothing. It alerts on new CISA KEV entries, OpenCTI report titles that say a flaw is being exploited now, and recent CVEs with EPSS >= 0.5 that are not in KEV yet. A story goes out once; repeats from other outlets within 72 h are dropped. `exploit-flash.py --backtest 7d` shows what it would have sent. State is in `~/.cache/exploit-flash.json`; delete it to re-baseline.

darkweb-flash runs [`scripts/darkweb-flash.py`](scripts/darkweb-flash.py). It reads `/srv/intel/darkweb-keeps.jsonl`, which the pve [dark-web bridge](../darkweb/bridge/darkweb-bridge.py) appends to when the research VM keeps a new dark-web or Telegram sample (MalwareBazaar and VirusTotal status included).

Run one now: `hermes cron run <job id>` (from `hermes cron list`). Copies are kept in `~/.hermes/cron/output/` and `~/briefs/`. If a Telegram delivery fails, the [health check](../../infrastructure/monitoring/README.md) resends it once.

## Telegram

| Setting | Where |
|---|---|
| Bot token, allowed user, home chat | `~/.hermes/.env` (`TELEGRAM_*`) |
| Pairing | `hermes pairing list` / `approve` / `revoke` |
| Gateway service | `hermes gateway status` / `restart` (user systemd service, survives logout) |

Only the paired account can talk to the bot. Anyone else is refused. Telegram works on phone, desktop and web at the same time.

## Skills

| Skills | Source |
|---|---|
| 78 Liberty91 cti-skills (lookups, actor profiling, ATT&CK, Sigma/YARA/KQL writing, source assessment, darkweb collection, ...) | https://github.com/Liberty91LTD/cti-skills |
| cti-daily-brief, cti-weekly-roundup, cti-ioc-lookup, pirs.md | [skills/](skills/) |

Edit [skills/pirs.md](skills/pirs.md) to change what the briefs prioritise.

## Tools in the container

| Tool | What it does |
|---|---|
| `intel-items` | Reads the collector database (`--since 24h`, `--source`, `--grep`) |
| `cve-status` | KEV status (date added, known ransomware use) and EPSS score for CVE IDs. `cve-status --kev-new 24h` lists new KEV entries. KEV comes from the collector's copy, EPSS live from FIRST |
| [`misp-recent`](tools/misp-recent) | MISP feed additions in a window (`--since 24h` / `7d`), per feed, with samples from the C2, malware and phishing feeds. Installed at `/usr/local/bin/misp-recent` |

The brief skills call `cve-status` for every CVE they mention, so exploitation status comes from the source, not from news articles.

## Safeguards

- Read-only accounts on OpenCTI and MISP. Write attempts are refused.
- Only TLP:CLEAR, GREEN and AMBER are visible, because briefs leave the lab.
- Outbound network is limited to the APIs it needs. It cannot reach other lab machines.
- Browser, computer use, image, voice and code-execution tools are disabled.
- Collected text is treated as untrusted data, never as instructions.

## Collector

Plain Python, no model, runs every 30 minutes as a separate user. Writes to `/srv/intel/intel.db`, which Hermes reads.

| Source | What it collects |
|---|---|
| ransomware.live | Recent leak-site victims |
| RansomLook | Recent leak-site posts, an independent cross-source to ransomware.live |
| CISA KEV | New Known Exploited Vulnerabilities entries. The full catalog is kept in `/srv/intel/kev.json`, refreshed every 6 hours |
| Exploit-DB | New public exploits that name a CVE (every 6 h); feeds `cve-status --pre-kev` |
| GHSA | GitHub-reviewed critical/high advisories with a CVE (every 6 h) |
| OpenSourceMalware | New software-supply-chain write-ups (malicious npm/PyPI/RubyGems/Go/crate/extension packages). Headline and link only, no IOCs in the feed; early-warning source, every 6 h |
| deepdarkCTI | Changes to its lists of groups, forums and channels |
| Telegram | Text of new posts from the public channels in `/srv/intel/telegram-channels.txt`, read through each channel's public web preview. No account, no joining, no media, no links followed. Channels with the preview turned off are skipped. A channel's first read keeps only the last 48 hours |
