#!/usr/bin/env python3
"""octi-window.py — pull the FULL recent window of OpenCTI reports, deduplicated by
title, with real dashboard URLs. Server-side pagination + dedup so the daily brief
covers the whole window (not just the newest ~hour under a page cap) while the agent
only processes compact unique items (far fewer tokens, and nothing truncated).

Wraps ~/cti-skills/tools/clis/opencti.py and reads $OPENCTI_URL for the links.
Usage: octi-window.py [--hours 24] [--clis DIR] [--max-pages 200]
Output (JSON): window stats + reports:[{id, name, published, report_types, url, dup_count}]
Title-level and compact by design so the whole window fits in context. Read each kept report's abstract
(OpenCTI's `description`) on demand with `opencti.py get <id> --no-relationships`, not here in bulk.
"""
import argparse, datetime, json, os, subprocess, sys

def iso(dt):
    return dt.astimezone(datetime.timezone.utc).isoformat().replace("+00:00", "Z")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hours", type=int, default=24)
    ap.add_argument("--clis", default=os.path.expanduser("~/cti-skills/tools/clis"))
    ap.add_argument("--max-pages", type=int, default=200)
    a = ap.parse_args()
    now = datetime.datetime.now(datetime.timezone.utc)
    win = now - datetime.timedelta(hours=a.hours)
    octi = os.path.join(a.clis, "opencti.py")
    base = os.environ.get("OPENCTI_URL", "").rstrip("/")

    after, pages, total, backfill = None, 0, 0, 0
    seen = {}  # title(lower) -> record (newest kept; dups collapsed)
    while pages < a.max_pages:
        cmd = [sys.executable, octi, "list", "reports", "--created-after", iso(win),
               "--limit", "100", "--order", "desc"]
        if after:
            cmd += ["--after", after]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
        if r.returncode != 0:
            print(json.dumps({"error": (r.stderr or r.stdout)[:300]})); return
        try:
            d = json.loads(r.stdout)
        except Exception:
            print(json.dumps({"error": "bad json from opencti", "raw": r.stdout[:200]})); return
        rows = d.get("results") or []
        total += len(rows)
        for rep in rows:
            pub = rep.get("published") or ""
            try:
                pdt = datetime.datetime.fromisoformat(pub.replace("Z", "+00:00"))
                news = pdt >= win  # future-dated (=today) are >= win too
            except Exception:
                news = True
            if not news:
                backfill += 1
                continue
            key = (rep.get("name") or "").strip().lower()
            if key in seen:
                seen[key]["dup_count"] += 1
                continue
            seen[key] = {"id": rep.get("id"), "name": (rep.get("name") or "").strip(), "published": pub,
                         "report_types": rep.get("report_types") or [],
                         "url": f"{base}/dashboard/analyses/reports/{rep.get('id')}" if base else rep.get("id"),
                         "dup_count": 1}
        pages += 1
        if not d.get("has_next_page"):
            break
        after = d.get("end_cursor")
        if not after:
            break

    reports = sorted(seen.values(), key=lambda x: x["published"], reverse=True)
    dupes = sum(r["dup_count"] - 1 for r in reports)
    print(json.dumps({
        "window_hours": a.hours, "pages": pages, "total_pulled": total,
        "unique_news": len(reports), "backfill_dropped": backfill,
        "duplicates_collapsed": dupes, "reports": reports}, indent=2))

if __name__ == "__main__":
    main()
