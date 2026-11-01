#!/usr/bin/env python3
"""Reload live-feeds.csv into OpenCTI native RSS ingestion. Run on the OpenCTI
host as root. Skips feeds already registered by URL, so it is safe to re-run.
Usage: restore.py live-feeds.csv"""
import csv, json, sys, urllib.request
from datetime import datetime, timedelta, timezone

ENV = dict(l.split("=", 1) for l in open("/opt/opencti7/.env").read().splitlines() if "=" in l and not l.startswith("#"))
H = {"Authorization": f"Bearer {ENV['OPENCTI_ADMIN_TOKEN']}", "Content-Type": "application/json"}


def q(query, **v):
    r = json.load(urllib.request.urlopen(urllib.request.Request(
        "http://127.0.0.1:8080/graphql", json.dumps({"query": query, "variables": v}).encode(), H), timeout=120))
    if r.get("errors"):
        raise RuntimeError(r["errors"][0]["message"])
    return r["data"]


me = q("{ me { id } }")["me"]["id"]
existing = {e["node"]["uri"].rstrip("/").lower()
            for e in q("{ ingestionRsss(first: 2000) { edges { node { uri } } } }")["ingestionRsss"]["edges"]}
start = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()

added = failed = 0
for row in csv.DictReader(open(sys.argv[1], encoding="utf-8")):
    if row["feed_url"].rstrip("/").lower() in existing:
        continue
    inp = {"name": row["name"][:250], "uri": row["feed_url"], "user_id": me,
           "report_types": ["threat-report"], "current_state_date": start,
           "ingestion_running": row.get("running", "yes") == "yes"}
    try:
        q("mutation($i: IngestionRssAddInput!) { ingestionRssAdd(input: $i) { id } }", i=inp)
        added += 1
    except Exception as e:
        failed += 1
        print("FAIL", row["name"], str(e)[:120])
print(f"added {added}, failed {failed}, already present {len(existing)}")
