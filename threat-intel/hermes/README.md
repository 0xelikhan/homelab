# Hermes Agent

| Item | Value |
|---|---|
| Container | LXC 120 `hermes`, VLAN 10, Ubuntu 24.04, 2 GB RAM, unprivileged |
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

| Job | When | Output |
|---|---|---|
| daily-cti-brief | every morning | daily brief |
| weekly-cti-roundup | Monday morning | weekly roundup |
| fin-ransomware-flash | every 2 h, only when new financial-sector victims appear | flash note |

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
