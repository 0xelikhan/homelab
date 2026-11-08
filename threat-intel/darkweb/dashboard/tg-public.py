#!/usr/bin/env python3
"""
tg-public.py  -  account-free sweep of PUBLIC Telegram channels.

For a rotating batch of the public channels (tg-channels-all.txt), fetch each channel's
public web preview (https://t.me/s/<channel>) and extract external download links + any
password hint into the crawler's `candidates` table, so triage.py pulls them. This grabs
what IS reachable without an account (external links posted in the channel); native
Telegram attachments still need the account path. Read-only, Tor-routed, bounded, and it
rotates so all channels get covered over successive runs.
"""
import os, re, sys, time, sqlite3, urllib.request, urllib.error, socket, importlib.util

HERE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(HERE, "malware-findings.db")
CHANNELS = sys.argv[1] if len(sys.argv) > 1 else os.path.expanduser("~/tg-channels-all.txt")
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")
BATCH = 60            # channels per run (rotates through the full list)
TIMEOUT = 25

# reuse the crawler's candidate extraction (regexes + store_candidates)
_spec = importlib.util.spec_from_file_location("cs", os.path.join(HERE, "crawl-sources.py"))
CS = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(CS)


def fetch(url):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            ct = (r.headers.get("Content-Type") or "").lower()
            if ct and "html" not in ct and "text" not in ct:
                return None
            return r.read(900000).decode("utf-8", "replace")
    except (urllib.error.URLError, urllib.error.HTTPError, socket.timeout, Exception):
        return None


def main():
    if not os.path.exists(CHANNELS):
        print("tg-public: no channel list at %s" % CHANNELS); return
    chans = [l.strip() for l in open(CHANNELS, encoding="utf-8") if l.strip() and not l.startswith("#")]
    if not chans:
        print("tg-public: channel list empty"); return
    c = sqlite3.connect(DB)
    c.executescript("CREATE TABLE IF NOT EXISTS candidates("
                    "url TEXT PRIMARY KEY, password TEXT, source_name TEXT, ts REAL);"
                    "CREATE TABLE IF NOT EXISTS crawl_state(k TEXT PRIMARY KEY, v TEXT);")
    row = c.execute("SELECT v FROM crawl_state WHERE k='tgpub_off'").fetchone()
    off = int(row[0]) if (row and row[0]) else 0
    batch = [chans[(off + i) % len(chans)] for i in range(min(BATCH, len(chans)))]
    now = time.time(); pages = 0
    before = c.execute("SELECT count(*) FROM candidates").fetchone()[0]
    for ch in batch:
        html = fetch("https://t.me/s/" + ch.lstrip("@"))
        if not html:
            continue
        pages += 1
        clean = CS.WS_RE.sub(" ", CS.TAG_RE.sub(" ", html))
        CS.store_candidates(c, html, clean, ch, now)
    added = c.execute("SELECT count(*) FROM candidates").fetchone()[0] - before
    c.execute("INSERT OR REPLACE INTO crawl_state VALUES('tgpub_off',?)",
              (str((off + len(batch)) % len(chans)),))
    c.commit()
    print("tg-public: swept %d/%d channels from offset %d, +%d new candidates"
          % (pages, len(batch), off, added))


if __name__ == "__main__":
    main()
