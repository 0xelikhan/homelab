#!/usr/bin/env python3
# Harvest LIVE .onion leak-site mirrors from ransomlook's active groups into the crawl
# seeds. Capped and self-pruning: each run REWRITES the auto-harvested block (dropping
# stale/dead mirrors and adding current ones), keeping any manual seeds above it. Prefers
# mirrors ransomlook flags available. Read-only, over Tor.
import urllib.request, urllib.parse, json, os, re

SEEDS = os.path.expanduser("~/onionclaw/research-seeds.txt")
MARK = "# ransomlook mirrors (auto-harvested)"
UA = "Mozilla/5.0"
MAX_GROUPS = 20
MAX_PER_GROUP = 4
MAX_TOTAL = 200
TIMEOUT = 45
ONION = re.compile(r"[a-z2-7]{16,56}\.onion")


def g(u):
    try:
        r = urllib.request.urlopen(urllib.request.Request(u, headers={"User-Agent": UA}), timeout=TIMEOUT)
        return json.loads(r.read().decode("utf-8", "replace"))
    except Exception:
        return None


def locs_of(d):
    out = []
    if isinstance(d, list):
        for it in d:
            if isinstance(it, dict):
                out += it.get("locations") or []
    elif isinstance(d, dict):
        out = d.get("locations") or []
    return out


def main():
    recent = g("https://www.ransomlook.io/api/recent")
    groups = []
    if isinstance(recent, list):
        for v in recent:
            gn = (v.get("group_name") or "").strip()
            if gn and gn not in groups:
                groups.append(gn)
    groups = groups[:MAX_GROUPS]

    found = []
    for gn in groups:
        d = g("https://www.ransomlook.io/api/group/" + urllib.parse.quote(gn))
        n = 0
        for loc in locs_of(d):
            if not isinstance(loc, dict):
                continue
            if loc.get("available") is False:          # skip mirrors flagged dead
                continue
            slug = (loc.get("slug") or loc.get("fqdn") or "").strip()
            m = ONION.search(slug)
            if not m:
                continue
            url = (slug if slug.startswith("http") else "http://" + m.group(0)).rstrip("/")
            found.append(url)
            n += 1
            if n >= MAX_PER_GROUP:
                break
        if len(found) >= MAX_TOTAL:
            break
    found = list(dict.fromkeys(found))[:MAX_TOTAL]      # dedup + cap

    # keep manual seeds (everything above the marker), replace the auto block
    try:
        lines = [l.rstrip("\n") for l in open(SEEDS, encoding="utf-8")]
    except Exception:
        lines = []
    if MARK in lines:
        lines = lines[:lines.index(MARK)]
    while lines and not lines[-1].strip():
        lines.pop()
    manual = {l.strip().rstrip("/") for l in lines if l.strip() and not l.startswith("#")}
    new = [u for u in found if u.rstrip("/") not in manual]

    with open(SEEDS, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
        if new:
            fh.write("\n\n" + MARK + "\n" + "\n".join(new) + "\n")
        elif lines:
            fh.write("\n")
    print("harvest: groups=%d live_onions=%d (cap %d) manual_seeds=%d" %
          (len(groups), len(new), MAX_TOTAL, len(manual)))


if __name__ == "__main__":
    main()
