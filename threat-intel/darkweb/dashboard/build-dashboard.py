#!/usr/bin/env python3
"""Build the research-VM CTI dashboard (dashboard.html) from sources.json plus a
live pull of recent ransomware leak-site activity. On the Whonix Workstation all
traffic is transparently routed over Tor, so plain urllib is fine. No JavaScript
(works at Tor Browser 'Safest'). Run on login and/or manually:  python3 build-dashboard.py
"""
import json, os, html, datetime, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = json.load(open(os.path.join(HERE, "sources.json"), encoding="utf-8"))
ACTIVE = {"ONLINE", "VALID"}
TIMEOUT = 45

def fetch(url):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "cti-dashboard"})
        return json.load(urllib.request.urlopen(req, timeout=TIMEOUT))
    except Exception as e:
        return {"__error__": str(e)[:120]}

def live_victims():
    rows, errs = [], []
    a = fetch("https://api.ransomware.live/v2/recentvictims")
    if isinstance(a, list):
        for v in a:
            rows.append({"date": (v.get("discovered") or v.get("attackdate") or "")[:10],
                         "group": v.get("group", ""), "title": v.get("victim", ""),
                         "country": v.get("country", ""), "desc": (v.get("description") or "")[:160]})
    elif isinstance(a, dict):
        errs.append("ransomware.live: " + a.get("__error__", "?"))
    b = fetch("https://www.ransomlook.io/api/recent")
    if isinstance(b, list):
        for v in b:
            rows.append({"date": (v.get("discovered") or "")[:10], "group": v.get("group_name", ""),
                         "title": v.get("post_title", ""), "country": "", "desc": (v.get("description") or "")[:160]})
    elif isinstance(b, dict):
        errs.append("ransomlook: " + b.get("__error__", "?"))
    seen, uniq = set(), []
    for r in sorted(rows, key=lambda r: r["date"], reverse=True):
        k = (r["group"].lower(), r["title"].lower())
        if k in seen or not r["title"]:
            continue
        seen.add(k); uniq.append(r)
    return uniq[:80], errs

def badge(status):
    s = status.upper()
    col = "#3fb950" if s in ACTIVE else "#6e7681"
    return f'<span class="b" style="color:{col}">{html.escape(s or "?")}</span>' if s else ""

def entry_rows(entries):
    out = []
    for e in entries:
        name = html.escape(e["name"][:90])
        url = html.escape(e["url"], quote=True)
        extra = f' <span class="x">{html.escape(e["extra"][:40])}</span>' if e.get("extra") else ""
        out.append(f'<li>{badge(e["status"])} <a href="{url}" target="_blank" rel="noreferrer">{name}</a>{extra}</li>')
    return "\n".join(out)

def category_block(key, cat):
    act = [e for e in cat["entries"] if e["status"] in ACTIVE]
    dead = [e for e in cat["entries"] if e["status"] not in ACTIVE]
    inner = f'<ul>\n{entry_rows(act)}\n</ul>'
    if dead:
        inner += f'<details class="dead"><summary>inactive / unverified ({len(dead)})</summary><ul>\n{entry_rows(dead)}\n</ul></details>'
    return (f'<details id="{key}"><summary>{html.escape(cat["title"])} '
            f'<span class="c">{cat["active"]} active / {cat["total"]}</span></summary>\n{inner}\n</details>')

victims, errs = live_victims()
now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")

vrows = "\n".join(
    f'<tr><td class="d">{html.escape(v["date"])}</td><td class="g">{html.escape(v["group"][:24])}</td>'
    f'<td>{html.escape(v["title"][:70])}</td><td class="d">{html.escape(v["country"])}</td></tr>'
    for v in victims) or '<tr><td colspan="4">No live data this refresh.</td></tr>'

nav = " ".join(f'<a href="#{k}">{SRC[k]["title"].split(" - ")[0].split(" / ")[0]} ({SRC[k]["active"]})</a>' for k in SRC)
cats = "\n".join(category_block(k, SRC[k]) for k in SRC)
errnote = (f'<p class="err">Live feed note: {html.escape("; ".join(errs))}</p>' if errs else "")

HTMLDOC = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CTI Research Dashboard</title>
<style>
:root{{color-scheme:dark}}
body{{background:#0d1117;color:#c9d1d9;font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;margin:0;padding:18px 20px 60px}}
h1{{font-size:20px;margin:0 0 2px}} h2{{font-size:15px;color:#8b949e;margin:22px 0 8px;border-bottom:1px solid #21262d;padding-bottom:4px}}
.sub{{color:#8b949e;font-size:12px;margin:0 0 14px}}
a{{color:#58a6ff;text-decoration:none}} a:hover{{text-decoration:underline}}
table{{border-collapse:collapse;width:100%;font-size:13px}}
th,td{{text-align:left;padding:4px 8px;border-bottom:1px solid #21262d;vertical-align:top}}
th{{color:#8b949e;font-weight:600}} td.d{{color:#8b949e;white-space:nowrap}} td.g{{color:#f0883e;white-space:nowrap}}
.nav{{margin:10px 0 4px;font-size:12px}} .nav a{{display:inline-block;background:#161b22;border:1px solid #21262d;border-radius:12px;padding:2px 9px;margin:2px 3px 2px 0}}
details{{background:#161b22;border:1px solid #21262d;border-radius:6px;margin:6px 0;padding:2px 10px}}
details summary{{cursor:pointer;font-weight:600;padding:6px 0}}
details.dead{{background:transparent;border:0;margin:4px 0}} details.dead summary{{color:#6e7681;font-weight:400;font-size:12px}}
ul{{list-style:none;margin:4px 0 8px;padding:0;columns:2;column-gap:28px}} li{{break-inside:avoid;padding:1px 0;font-size:13px}}
.b{{font-size:10px;font-weight:700;letter-spacing:.3px}} .c{{color:#6e7681;font-weight:400;font-size:12px}} .x{{color:#6e7681;font-size:11px}}
.err{{color:#d29922;font-size:12px}} .foot{{color:#6e7681;font-size:11px;margin-top:30px;border-top:1px solid #21262d;padding-top:10px}}
@media(max-width:700px){{ul{{columns:1}}}}
</style></head><body>
<h1>CTI Research Dashboard</h1>
<p class="sub">All traffic is routed over Tor. Refreshed {now}. Click any source to open it in Tor Browser.</p>
{errnote}
<h2>Recent ransomware leak-site activity ({len(victims)})</h2>
<table><thead><tr><th>Discovered</th><th>Group</th><th>Victim</th><th>CC</th></tr></thead>
<tbody>
{vrows}
</tbody></table>
<h2>Source directory</h2>
<div class="nav">{nav}</div>
{cats}
<p class="foot">Sources from fastfire/deepdarkCTI (GPL-3.0) + ransomware.live + RansomLook. Run <code>python3 build-dashboard.py</code> to refresh. Snapshot-revert wipes session state; this dashboard is baked into clean-base.</p>
</body></html>"""

open(os.path.join(HERE, "dashboard.html"), "w", encoding="utf-8").write(HTMLDOC)
print(f"wrote dashboard.html | live victims: {len(victims)} | errors: {errs or 'none'}")
