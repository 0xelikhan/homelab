# Hermes Agent

| Item | Value |
|---|---|
| Container | LXC 120 `hermes`, VLAN 10, Ubuntu 24.04, 2 GB RAM, unprivileged |
| Group | `cti` (always on) |
| Delivery | Telegram bot, paired to one account |
| Version | Hermes Agent (Nous Research), stable channel |
| Model | Anthropic Claude Sonnet |

Reads OpenCTI, MISP and Cortex with read-only accounts, plus a local collector database, and writes daily and weekly CTI briefs.

```bash
pct enter 120
su - hermes
hermes cron list
hermes -z "what do we know about <indicator>" --skills cti-ioc-lookup
```

## Scheduled jobs

All three deliver to Telegram. Failures are sent there too.

| Job | When | Output |
|---|---|---|
| daily-cti-brief | 07:00 every day | short summary message, full brief attached as a file |
| weekly-cti-roundup | Monday 08:00 | short summary message, full roundup attached as a file |
| fin-ransomware-flash | every 2 h, only when new financial-sector victims appear | flash note |

The briefs attach the saved Markdown file with a `MEDIA:<path>` line at the end of the response.

The flash uses `~/.hermes/scripts/fin-victims-monitor.py`. A victim counts as financial when ransomware.live tags its sector as Financial Services. When the sector is missing, the victim name or domain decides. Victims the source mis-tags as financial go in `~/.hermes/scripts/fin-exclude.txt`, one name per line.

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
| CISA KEV | New Known Exploited Vulnerabilities entries. The full catalog is kept in `/srv/intel/kev.json`, refreshed every 6 hours |
| deepdarkCTI | Changes to its lists of groups, forums and channels |
| Telegram | Text of new posts from the public channels in `/srv/intel/telegram-channels.txt`, read through each channel's public web preview. No account, no joining, no media, no links followed. Channels with the preview turned off are skipped. A channel's first read keeps only the last 48 hours |
