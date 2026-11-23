#!/usr/bin/env python3
"""
darkweb-bridge.py  -  runs on pve (root), every 15 min.

The research workstation (VM 128) is Tor-only and holds no lab secrets. This bridge does the
two things it should not do itself:

  1. VirusTotal: looks up each kept sample's SHA-256 (hash lookup only, nothing uploaded) with
     the lab key from /root/lab-secrets.env, and pushes the results back to the workstation as
     ~/Desktop/cti/vt-status.json for the dashboard.
  2. Alerts: hands each NEW dark-web / Telegram keep to Hermes by appending one sanitised JSON
     line to /srv/intel/darkweb-keeps.jsonl in CT 120. Hermes' darkweb-flash job turns new
     lines into a Telegram message (no model involved).

Only metadata crosses (hash, source name, family/signature names, reasons, MB status). Sample
bytes never leave the workstation.
"""
import json, os, re, subprocess, sys, time, urllib.request, urllib.error

WS        = ["ssh", "-i", "/root/.ssh/lab_ed25519", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15",
             "user@10.152.152.11"]
CT        = "120"
ALERTS    = "/srv/intel/darkweb-keeps.jsonl"
STATE     = "/var/lib/darkweb-bridge/state.json"
SECRETS   = "/root/lab-secrets.env"
VT_PER_RUN = 4                 # public API: 4 lookups/min, 500/day
VT_RECHECK = 24 * 3600         # re-ask about "not in VT" hashes once a day
SAFE = re.compile(r"[^A-Za-z0-9 _.:;,/+()\[\]#@&-]")


def clean(s, n=120):
    return SAFE.sub("", str(s or ""))[:n]


def load_state():
    try:
        return json.load(open(STATE))
    except Exception:
        return {"vt": {}, "alerted": []}


def save_state(st):
    os.makedirs(os.path.dirname(STATE), exist_ok=True)
    tmp = STATE + ".tmp"
    json.dump(st, open(tmp, "w"))
    os.replace(tmp, STATE)


def vt_key():
    try:
        for ln in open(SECRETS):
            m = re.match(r"\s*VIRUSTOTAL_KEY\s*=\s*['\"]?([0-9a-fA-F]{64})", ln)
            if m:
                return m.group(1)
    except Exception:
        pass
    return None


def vt_lookup(key, sha):
    req = urllib.request.Request("https://www.virustotal.com/api/v3/files/" + sha,
                                 headers={"x-apikey": key, "User-Agent": "lab-darkweb-bridge"})
    try:
        d = json.load(urllib.request.urlopen(req, timeout=30))["data"]["attributes"]
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"status": "not-found", "detail": "not in VT", "checked": time.time()}
        if e.code in (401, 403, 429):
            return None                                  # key/quota problem: try again next run
        return {"status": "error", "detail": "http %d" % e.code, "checked": time.time()}
    except Exception:
        return None
    st = d.get("last_analysis_stats") or {}
    mal = st.get("malicious", 0)
    tot = sum(v for v in st.values() if isinstance(v, int))
    first = time.strftime("%Y-%m-%d", time.gmtime(d.get("first_submission_date") or 0))
    label = (d.get("popular_threat_classification") or {}).get("suggested_threat_label") or ""
    return {"status": "found", "detail": "VT %d/%d, first %s%s" % (mal, tot, first, (", " + label) if label else ""),
            "malicious": mal, "first": first, "label": label, "checked": time.time()}


def main():
    st = load_state()
    try:
        out = subprocess.run(WS + ["python3 /home/user/Desktop/cti/triage.py --export-keeps"],
                             capture_output=True, text=True, timeout=120).stdout
        keeps = json.loads(out or "[]")
    except Exception as e:
        print("bridge: cannot read keeps from the workstation: %s" % e, file=sys.stderr)
        return 1

    # 1. VirusTotal, newest first, a few per run
    key = vt_key()
    if key:
        todo = []
        for k in sorted(keeps, key=lambda k: -k["ts"]):
            v = st["vt"].get(k["sha256"])
            if v is None or (v.get("status") != "found" and time.time() - v.get("checked", 0) > VT_RECHECK):
                todo.append(k["sha256"])
        for sha in todo[:VT_PER_RUN]:
            r = vt_lookup(key, sha)
            if r:
                st["vt"][sha] = r
    shas = {k["sha256"] for k in keeps}
    vt_out = {s: v for s, v in st["vt"].items() if s in shas}
    subprocess.run(WS + ["cat > /home/user/Desktop/cti/vt-status.json.tmp && "
                         "mv /home/user/Desktop/cti/vt-status.json.tmp /home/user/Desktop/cti/vt-status.json"],
                   input=json.dumps(vt_out), text=True, timeout=60)

    # 2. alerts for new dark-web / Telegram keeps (not known-feed, not review)
    first_run = not st.get("initialized")
    st["initialized"] = True
    new = [k for k in keeps if k["kept"] == 1 and k["origin"] != "known-feed"
           and k["sha256"] not in st["alerted"]]
    lines = []
    for k in new:
        st["alerted"].append(k["sha256"])
        if first_run:
            continue                                     # baseline: do not replay last week
        v = st["vt"].get(k["sha256"]) or {}
        lines.append(json.dumps({
            "ts": int(k["ts"]), "sha256": clean(k["sha256"], 64), "origin": clean(k["origin"], 12),
            "source": clean(k["source"], 60), "category": clean(k["category"], 10),
            "family": [clean(f, 60) for f in k["family"][:3]], "reasons": clean(k["reasons"], 200),
            "mb": clean(k["mb"], 40), "vt": clean(v.get("detail", "pending"), 80)}))
    st["alerted"] = st["alerted"][-2000:]
    if lines:
        r = subprocess.run(["pct", "exec", CT, "--", "sh", "-c",
                            "[ -f %s ] || install -m 0640 -o collector -g intel /dev/null %s; cat >> %s"
                            % (ALERTS, ALERTS, ALERTS)],
                           input="\n".join(lines) + "\n", text=True, timeout=60)
        if r.returncode != 0:
            print("bridge: could not write alerts into CT %s" % CT, file=sys.stderr)
            return 1
    save_state(st)
    print("bridge: %d keeps, %d vt cached, %d new alerts%s"
          % (len(keeps), len(vt_out), len(lines), " (baseline run)" if first_run and new else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
