#!/usr/bin/env python3
"""Parse the vendored deepdarkCTI markdown into a deduped, categorized sources.json
for the research-VM dashboard. Run from the repo root (or anywhere; paths are relative
to this file). Output: sources.json next to this script."""
import csv, json, re, os
from urllib.parse import urlsplit

HERE = os.path.dirname(os.path.abspath(__file__))
# live clone (auto-pulled on the research VM) takes precedence over the repo-vendored copy
SRC = os.path.join(HERE, "deepdarkCTI") if os.path.isdir(os.path.join(HERE, "deepdarkCTI")) else os.path.join(HERE, "..", "deepdarkcti")

LINK = re.compile(r"\[(.+?)\]\((.+?)\)")

# category -> (file, title, format, cols)
CATS = [
    ("ransomware",  "ransomware_gang.md",       "Ransomware leak sites",        "link",    {"status": 1}),
    ("telegram_ta", "telegram_threat_actors.md","Telegram - threat actors",     "rawurl",  {"status": 1, "name": 2, "extra": 3}),
    ("telegram_is", "telegram_infostealer.md",  "Telegram - infostealer logs",  "rawurl",  {"status": 1, "name": 2}),
    ("forums",      "forum.md",                 "Forums",                       "link",    {"status": 1}),
    ("markets",     "markets.md",               "Markets / shops",              "link",    {"status": 1}),
    ("search",      "search_engines.md",        "Onion search engines",         "link",    {"status": 1}),
    ("others",      "others.md",                "Leak / search / monitor sites","link",    {"status": 1}),
    ("commercial",  "commercial_services.md",   "Commercial CTI lookups",       "name_url",{"name": 0, "url": 2}),
]

ACTIVE = {"ONLINE", "VALID"}

def rows(path):
    out = []
    for line in open(path, encoding="utf-8"):
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) < 2 or set("".join(cells[0])) <= set("- "):
            continue
        low = cells[0].lower()
        if low in ("name", "telegram", "url") or (len(cells) > 1 and cells[1].lower() == "status"):
            continue
        out.append(cells)
    return out

def norm(u):
    try:
        s = urlsplit(u.strip())
        return (s.netloc.lower() + s.path.rstrip("/")).lower() or u.strip().lower()
    except Exception:
        return u.strip().lower()

data = {}
for key, fname, title, fmt, cols in CATS:
    path = os.path.join(SRC, fname)
    if not os.path.exists(path):
        continue   # keep a complete set only; a missing file just drops its category
    entries, seen = [], set()
    for c in rows(path):
        name = url = status = extra = ""
        if fmt == "link":
            m = LINK.search(c[0])
            if not m:
                continue
            name, url = m.group(1).strip(), m.group(2).strip()
            status = c[cols["status"]] if len(c) > cols["status"] else ""
        elif fmt == "rawurl":
            url = c[0].strip()
            status = c[cols["status"]] if len(c) > cols["status"] else ""
            name = c[cols["name"]] if "name" in cols and len(c) > cols["name"] else url
            if "extra" in cols and len(c) > cols["extra"]:
                extra = c[cols["extra"]]
        elif fmt == "name_url":
            name = c[cols["name"]].strip()
            url = c[cols["url"]].strip() if len(c) > cols["url"] else ""
        if not url or not url.lower().startswith(("http", "t.me")):
            if url.startswith("t.me"):
                url = "https://" + url
            else:
                continue
        k = norm(url)
        if k in seen:
            continue
        seen.add(k)
        entries.append({"name": name or url, "url": url, "status": status.upper(), "extra": extra})
    # active (ONLINE/VALID) first, then by name
    entries.sort(key=lambda e: (e["status"] not in ACTIVE, e["name"].lower()))
    active = sum(1 for e in entries if e["status"] in ACTIVE)
    data[key] = {"title": title, "active": active, "total": len(entries), "entries": entries}

out = os.path.join(HERE, "sources.json")
json.dump(data, open(out, "w", encoding="utf-8"), ensure_ascii=False)
print("wrote", out)
for k, v in data.items():
    print(f"  {k:12} {v['active']:4} active / {v['total']:4} total  ({v['title']})")
