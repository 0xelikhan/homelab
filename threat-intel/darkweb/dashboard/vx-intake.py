#!/usr/bin/env python3
"""
vx-intake.py  -  ingest sample archives (vx-underground collections, theZoo, any password
                 archive) dropped into ~/vx-intake, and run every contained sample through
                 the same triage engine as the crawler.

Flow: one archive per run -> 7z unpack (tries 'infected' + the common passwords; no size
cap, these are trusted bulk collections) -> triage each contained file (dedup / file-type /
decide) -> real malicious executables land in ~/quarantine for the REs, everything else is
deleted -> the processed archive is removed. Bounded by the triage disk budget and a
per-run sample cap so a huge collection can't swamp the box. NOTHING is executed.

These are KNOWN/reported samples (good for RE practice + testing your EDR detections), a
complement to the dark-web crawler's novel-sample job, not a replacement.

Usage: drop collection archives into ~/vx-intake/ (download them however you like -
lab-side over clearnet is fine, then copy over), and this runs each crawl cycle.
"""
import os, sys, subprocess, shutil, sqlite3, time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import triage as T                       # reuse DB, QDIR, budget, triage_one, prune

VX_DIR = os.path.expanduser("~/vx-intake")
MAX_SAMPLES_PER_RUN = 250                 # bound capa/disk load per cycle
ARCH_EXT = (".zip", ".7z", ".rar", ".tar", ".gz", ".tgz", ".001", ".7z.001")
VX_PW = ["infected", "malware", "virus", "unpack"]


def unpack_big(archive, outdir):
    os.makedirs(outdir, exist_ok=True)
    for pw in VX_PW + [None]:
        cmd = ["7z", "x", "-y", "-o" + outdir, ("-p" + pw) if pw else "-p", archive]
        try:
            r = subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, timeout=1800)
        except Exception:
            continue
        if r.returncode == 0 and any(True for _ in os.scandir(outdir)):
            return True
    return False


def main():
    if not os.path.isdir(VX_DIR):
        return
    archives = [f for f in sorted(os.listdir(VX_DIR))
                if f.lower().endswith(ARCH_EXT) and os.path.isfile(os.path.join(VX_DIR, f))]
    if not archives:
        print("vx-intake: no archives in %s" % VX_DIR)
        return
    arc = os.path.join(VX_DIR, archives[0])          # oldest/first, one per run
    c = sqlite3.connect(T.DB); T.init_db(c); os.makedirs(T.QDIR, exist_ok=True)
    tmp = arc + ".x"
    shutil.rmtree(tmp, ignore_errors=True)
    if not unpack_big(arc, tmp):
        print("vx-intake: unpack failed for %s (bad password / corrupt) - leaving in place" % archives[0])
        shutil.rmtree(tmp, ignore_errors=True)
        return
    kept = n = 0
    for dp, _, fs in os.walk(tmp):
        for f in fs:
            if n >= MAX_SAMPLES_PER_RUN or T.quarantine_mb() >= T.BUDGET_MB:
                break
            p = os.path.join(dp, f)
            if not os.path.isfile(p):
                continue
            n += 1
            kept += T.triage_one(c, p, "vx://%s/%s" % (archives[0], f), "vx-underground", ["infected"])
            c.commit()
        if n >= MAX_SAMPLES_PER_RUN:
            break
    shutil.rmtree(tmp, ignore_errors=True)
    try:
        os.remove(arc)                               # processed
    except OSError:
        pass
    T.prune(c); c.commit()
    print("vx-intake: %s -> triaged %d samples, kept %d, quarantine %.0f MB"
          % (archives[0], n, kept, T.quarantine_mb()))


if __name__ == "__main__":
    main()
