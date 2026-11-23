# Dark Web Monitoring

Read-only Tor crawler + dashboard for catching malware (hashes, executables, loaders,
stealers, RATs, ransomware) across dark-web sources, on a Whonix Workstation.

## Install (Whonix Workstation, as `user`, no sudo)

    git clone <repo>
    cd <repo>/threat-intel/darkweb/dashboard
    sh install.sh

Open `~/Desktop/cti/dashboard.html` in Tor Browser. First findings appear after the first
crawl (every 2h, or start one now with the command install.sh prints).

## What runs

- `crawl-sources.py` - read-only crawl of `sources.json` + harvested onion mirrors, every
  2h (`cti-crawl.timer`). Round-robins categories (threat-actor telegram + forums first) and
  ranks sources by yield: proven producers are re-crawled every run, sources live-but-empty
  for many fetches are demoted, unreachable ones skipped. Extracts md5/sha1/sha256 hashes,
  executable/sample links, malware families, and Telegram bot-token C2, with malware-context
  filters in English, Russian/translit, and Chinese/Korean/Arabic/Farsi/Spanish/French/Italian.
  Non-English pages the keyword filters miss are translated to English before scoring when
  translation is installed (offline, see below). Confidence-scored, 30-day retention.
- `harvest-mirrors.py` - pulls live ransomware leak-site onion mirrors from ransomlook into
  the crawl seeds (capped ~200, self-pruning). Runs before each crawl.
- `triage.py` - pulls the sample links the crawl found (pixeldrain, mega, mediafire, direct
  links; gofile links go to a manual list because gofile blocks automated clients), opens
  archives with 7-Zip incl. RAR5 (post password, source name, common passwords; size, file-count
  and time limits), and keeps a file when YARA, pefile, DIE or the script heuristics flag it.
  Unflagged PE/ELF wait in `~/triage-pending` for capa. Kept samples go to `~/quarantine/<sha256>/`
  with `findings.txt`. MalwareBazaar status is a hash lookup.
- `triage.py --capa` - capa stage (`cti-capa.timer`, every 30 min, 600 s per sample): capabilities
  and ATT&CK IDs for kept samples, verdict for pending ones.
- `build-dashboard.py` - rebuilds `dashboard.html` (new samples this week, pipeline funnel, manual
  downloads, yield per source, indicators, Telegram monitor, source directory) and `mentions.html`
  (family mention counts, leak-site archive hashes).
- `crawl-sources.py --reclassify` - re-applies the hash rules to stored rows (back up the DB first).

RAR support without root: copy `/usr/lib/7zip` to `~/.local/lib/7zip` and add `Codecs/Rar.so` from
`apt-get download 7zip-rar`.
- `weekly-maint.sh` - refreshes the deepdarkCTI curated source lists weekly
  (`cti-weekly.timer`): adds newly-listed sources, drops ones upstream retired.
- `gen_sources.py` - regenerates `sources.json` from the deepdarkCTI markdown lists.

## Safety

The crawl is read-only (`urllib`, no browser/JS, never fetches binaries). `triage.py` does download
samples, as data only: nothing is executed. Intended for a Tor-isolated Whonix VM.

## Translation (optional)

    cd ~/Desktop/cti && sh install-translation.sh

Installs Argos Translate (offline, CPU-only) and `<lang>->en` packages so the crawler can
translate non-English pages before scoring. Models are large and download over Tor, so this
is opt-in and self-verifying - whatever installs cleanly is what the crawler uses; the crawl
falls back to keyword detection for anything not installed. Never a cloud translation API.

## Bridge (pve)

[`../bridge/darkweb-bridge.py`](../bridge/darkweb-bridge.py) runs on pve every 15 min
(`darkweb-bridge.timer`, script in `/usr/local/bin`). It reads `triage.py --export-keeps` over
SSH, looks the hashes up on VirusTotal with the lab key (the key never goes on the VM), writes
`vt-status.json` back for the dashboard, and appends new dark-web keeps to
`/srv/intel/darkweb-keeps.jsonl` in CT 120, which the Hermes `darkweb-flash` job sends to Telegram.

## Credits

Curated source lists vendored from [fastfire/deepdarkCTI](https://github.com/fastfire/deepdarkCTI)
(GPL-3.0). Actor/alias taxonomy from
[EssexRich/ThreatActors-TTPs](https://github.com/EssexRich/ThreatActors-TTPs).
