# dark-web-triage

Dark-web collection and static malware triage pipeline. Runs on the isolated
Whonix workstation (Tor-only egress), deploys to `/home/user/Desktop/cti/`.

Code only. Secrets, source lists, collected data and samples are not in git
(see `.gitignore`); they live on the box.

## Flow

1. `crawl-sources.py` reads `sources.json` / `actors.json`, pulls candidate
   links into `malware-findings.db` (`candidates`). `tg-public.py` and
   `tg-collect.sh` add Telegram-sourced links; `harvest-mirrors.py` and
   `gen_sources.py` maintain the source set.
2. `triage.py` downloads each candidate via `fetchers.py` (per-host resolvers),
   static-verifies it (file / pefile / DIE / YARA / capa), keeps real malicious
   PEs in `~/quarantine`, drops the rest. `recall-canary.py` runs known-malware
   feeds through the same filter as a ground-truth check.
3. `extract-iocs.py` pulls IOCs; `build-dashboard.py` renders the dashboard;
   `serve-quarantine.sh` serves it.
4. `cti-crawl.sh` / `refresh-all.sh` / `weekly-maint.sh` are the scheduled wrappers.

## Runtime files (provisioned on the box, not in git)

- `telegram.json` — bot token
- keys file — malshare and other API keys
- `sources.json`, `actors.json`, `deepdarkCTI/` — source and onion lists
- `malware-findings.db`, `iocs/`, `*.json` state — collected data
- `quarantine/` — retained samples
