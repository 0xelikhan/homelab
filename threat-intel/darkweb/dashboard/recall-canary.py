#!/usr/bin/env python3
"""recall-canary.py - known-feed recall for the dark-web triage pipeline.

MalwareBazaar / MalShare samples are ground-truth malware. The fraction the static
filter (YARA family + capa malicious-namespace + packing/entropy anomaly) independently
KEEPS is the filter's recall on real malware; a dropped known-feed sample is a miss and a
signal that detection coverage (YARA rules / capa) is thin for that sample's character.

Also surfaces the review bucket (kept=2): borderline dark-web PEs parked for a human glance.

Usage:  recall-canary.py [window_hours]   (default 168 = 7 days)
Read-only; never writes.
"""
import sqlite3, os, sys, time
from collections import Counter

DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "malware-findings.db")
WIN_H = float(sys.argv[1]) if len(sys.argv) > 1 else 168.0
FEEDS = ("MalwareBazaar", "MalShare")

c = sqlite3.connect(DB)
since = time.time() - WIN_H * 3600

# Archive rows are the feed's password-zip wrappers, not samples: the sample inside has its own row.
rows = c.execute(
    "SELECT kept, family, reasons, caps, category FROM triage "
    "WHERE source_name IN (?,?) AND ts >= ? AND category != 'archive'", (*FEEDS, since)).fetchall()

def caught(r):            # the filter's own verdict; a feed:forced keep is not a catch
    return r[0] == 1 and "feed:forced" not in (r[2] or "")

n = len(rows)
kept = sum(1 for r in rows if caught(r))
missed = [r for r in rows if not caught(r)]

print("=== known-feed recall canary (last %.0fh) ===" % WIN_H)
if n == 0:
    print("no MalwareBazaar/MalShare samples triaged in window (feed quiet or rate-limited)")
else:
    print("recall: %d/%d caught by the filter (%.0f%%), zip wrappers and forced keeps excluded"
          % (kept, n, 100.0 * kept / n))
    bycat = {}
    for r in rows:
        t = bycat.setdefault(r[4] or "?", [0, 0])
        t[0] += caught(r); t[1] += 1
    print("  by type: " + ", ".join("%s %d/%d" % (k, v[0], v[1]) for k, v in sorted(bycat.items())))
    forced = sum(1 for r in rows if "feed:forced" in (r[2] or ""))
    if forced:
        print("  forced keeps (filter missed, kept anyway as baseline): %d" % forced)
    why = Counter()
    for r in rows:
        if caught(r):
            for tok in (r[2] or "").split(";"):
                tok = tok.strip()
                if tok:
                    why[tok.split(":")[0]] += 1
    if why:
        print("  caught by: " + ", ".join("%s=%d" % (k, v) for k, v in why.most_common()))
    if missed:
        cerr = sum(1 for r in missed if "capa:err" in (r[2] or ""))
        print("  missed: %d  (capa-error on %d; the rest showed no YARA/capa/packing signal)"
              % (len(missed), cerr))

# review bucket snapshot (dark-web borderline PEs parked for a look)
rev = c.execute(
    "SELECT COUNT(*) FROM triage WHERE kept=2 AND ts >= ?", (since,)).fetchone()[0]
print("review bucket (kept=2) in window: %d parked for a human glance (~/quarantine-review)" % rev)

c.close()
