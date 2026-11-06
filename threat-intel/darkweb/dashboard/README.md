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

- `crawl-sources.py` — read-only crawl of `sources.json` + harvested onion mirrors, every
  2h (`cti-crawl.timer`). Round-robins categories (threat-actor telegram + forums first).
  Extracts md5/sha1/sha256 hashes, executable/sample links, malware families, and Telegram
  bot-token C2, with malware-context filters in English, Russian/translit, and
  Chinese/Korean/Arabic/Farsi/Spanish/French/Italian. Confidence-scored, 30-day retention.
- `harvest-mirrors.py` — pulls live ransomware leak-site onion mirrors from ransomlook into
  the crawl seeds (capped ~200, self-pruning). Runs before each crawl.
- `build-dashboard.py` — rebuilds `dashboard.html`: findings panel, ransomware leak feeds
  (ransomware.live + ransomlook over Tor), Telegram monitor, and the source directory.
- `weekly-maint.sh` — refreshes the deepdarkCTI curated source lists weekly
  (`cti-weekly.timer`): adds newly-listed sources, drops ones upstream retired.
- `gen_sources.py` — regenerates `sources.json` from the deepdarkCTI markdown lists.

## Safety

Read-only by design: `urllib` only, no browser/JS, never downloads binaries. Executables and
hashes are recorded as **links**, never fetched. Intended for a Tor-isolated Whonix VM.

## Enrichment (off-box)

Tor blocks VirusTotal/MalwareBazaar, so confirm surfaced hashes lab-side
(VirusTotal / ReversingLabs / abuse.ch URLhaus+ThreatFox). Translate foreign-language posts
with Argos Translate (offline) or a local LLM — never a cloud translation API.

## Credits

Curated source lists vendored from [fastfire/deepdarkCTI](https://github.com/fastfire/deepdarkCTI)
(GPL-3.0). Actor/alias taxonomy from
[EssexRich/ThreatActors-TTPs](https://github.com/EssexRich/ThreatActors-TTPs).
