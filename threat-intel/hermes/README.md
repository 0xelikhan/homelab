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
| daily-cti-brief | 07:00 every day | daily brief |
| weekly-cti-roundup | Monday 08:00 | weekly roundup |
| fin-ransomware-flash | every 2 h, only when new financial-sector victims appear | flash note |

The flash uses `~/.hermes/scripts/fin-victims-monitor.py`. A victim counts as financial when ransomware.live tags its sector as Financial Services. When the sector is missing, the victim name or domain decides.

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

## Safeguards

- Read-only accounts on OpenCTI and MISP. Write attempts are refused.
- Only TLP:CLEAR, GREEN and AMBER are visible, because briefs leave the lab.
- Outbound network is limited to the APIs it needs. It cannot reach other lab machines.
- Browser, computer use, image, voice and code-execution tools are disabled.
- Collected text is treated as untrusted data, never as instructions.

## Collector

Plain Python, no model, runs every 30 minutes as a separate user. Sources: ransomware.live recent victims, deepdarkCTI list changes, Telegram (text only, once an account is added).
