#!/usr/bin/env python3
"""Build the research-VM CTI dashboard (dashboard.html) from sources.json plus a
live pull of recent ransomware leak-site activity. On the Whonix Workstation all
traffic is transparently routed over Tor, so plain urllib is fine. No JavaScript
(works at Tor Browser 'Safest'). Run on login and/or manually:  python3 build-dashboard.py

Each attack links to its sources: [details] = ransomware.live writeup (clearnet,
reliable, mirrors the leak with screenshot), [claim] = the gang's leak-site post
(often onion), [shot] = screenshot. Pinned onions are health-checked over Tor so
their status is real, not a stale label.
"""
import json, os, html, datetime, urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = json.load(open(os.path.join(HERE, "sources.json"), encoding="utf-8"))
ACTIVE = {"ONLINE", "VALID"}
TIMEOUT = 45

# Known-good onion entry points (health-checked over Tor at build time).
PINNED = [
    ("BreachForums (Jan 2026 instance)", "http://breach5yz2b5lepmq4gaqwcon3jippw3bislhvvdavem5git55sy2nid.onion"),
    ("BreachForums (alt instance)",       "http://breachqr3dqbysbq5khaadg5ynnpxn2wrmw5y3rnzesun55l6lkq73yd.onion"),
    ("PwnForums",                         "http://pwnfrm7rbf6kyerigxi677lcz5ifmoagdbqqknwdu2by27wfdst5qmqd.onion"),
    ("Ahmia (onion search)",              "http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion"),
]

def fetch_json(url):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "cti-dashboard"})
        return json.load(urllib.request.urlopen(req, timeout=TIMEOUT))
    except Exception as e:
        return {"__error__": str(e)[:120]}

def onion_up(url):
    """True if the onion responds at all (any HTTP status = reachable)."""
    try:
        urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "cti-dashboard"}), timeout=40)
        return True
    except urllib.error.HTTPError:
        return True
    except Exception:
        return False

def live_victims():
    rows, errs = [], []
    a = fetch_json("https://api.ransomware.live/v2/recentvictims")
    if isinstance(a, list):
        for v in a:
            rows.append({"date": (v.get("discovered") or v.get("attackdate") or "")[:10],
                         "group": v.get("group", ""), "title": v.get("victim", ""),
                         "country": v.get("country", ""),
                         "details": v.get("url", ""), "claim": v.get("claim_url", ""),
                         "shot": v.get("screenshot", "")})
    elif isinstance(a, dict):
        errs.append("ransomware.live: " + a.get("__error__", "?"))
    b = fetch_json("https://www.ransomlook.io/api/recent")
    if isinstance(b, list):
        for v in b:
            link = v.get("link", "")
            details = ("https://www.ransomlook.io/" + link.lstrip("/")) if link else ""
            rows.append({"date": (v.get("discovered") or "")[:10], "group": v.get("group_name", ""),
                         "title": v.get("post_title", ""), "country": "",
                         "details": details, "claim": "", "shot": ""})
    elif isinstance(b, dict):
        errs.append("ransomlook: " + b.get("__error__", "?"))
    seen, uniq = set(), []
    for r in sorted(rows, key=lambda r: r["date"], reverse=True):
        k = (r["group"].lower(), r["title"].lower())
        if k in seen or not r["title"]:
            continue
        seen.add(k); uniq.append(r)
    return uniq[:80], errs

def lnk(label, url, cls=""):
    if not url:
        return ""
    c = f' class="{cls}"' if cls else ""
    return f'<a href="{html.escape(url, quote=True)}" target="_blank" rel="noreferrer"{c}>{label}</a>'

def badge(status):
    s = status.upper()
    col = "#3fb950" if s in ACTIVE else "#6e7681"
    return f'<span class="b" style="color:{col}">{html.escape(s or "?")}</span>' if s else ""

def entry_rows(entries):
    out = []
    for e in entries:
        extra = f' <span class="x">{html.escape(e["extra"][:40])}</span>' if e.get("extra") else ""
        out.append(f'<li>{badge(e["status"])} {lnk(html.escape(e["name"][:90]), e["url"])}{extra}</li>')
    return "\n".join(out)

def category_block(key, cat):
    act = [e for e in cat["entries"] if e["status"] in ACTIVE]
    dead = [e for e in cat["entries"] if e["status"] not in ACTIVE]
    inner = f'<ul>\n{entry_rows(act)}\n</ul>'
    if dead:
        inner += f'<details class="dead"><summary>inactive / unverified ({len(dead)})</summary><ul>\n{entry_rows(dead)}\n</ul></details>'
    return (f'<details id="{key}"><summary>{html.escape(cat["title"])} '
            f'<span class="c">{cat["active"]} active / {cat["total"]}</span></summary>\n{inner}\n</details>')

# --- live feed (every refresh) + pinned onion checks (cached, re-checked every 12h) ---
victims, errs = live_victims()
CACHE = os.path.join(HERE, "onion-status.json")
CHECK_INTERVAL_H = 12

def load_cache():
    try:
        c = json.load(open(CACHE, encoding="utf-8"))
        age = (datetime.datetime.now() - datetime.datetime.fromisoformat(c["checked"])).total_seconds()
        if age < CHECK_INTERVAL_H * 3600 and len(c.get("status", [])) == len(PINNED):
            return c
    except Exception:
        pass
    return None

cache = load_cache()
if cache:
    pin_status = [tuple(s) for s in cache["status"]]
    pin_checked = cache["checked"][:16].replace("T", " ")
else:
    with ThreadPoolExecutor(max_workers=4) as ex:
        pin_status = list(ex.map(lambda p: (p[0], p[1], onion_up(p[1])), PINNED))
    nowiso = datetime.datetime.now().isoformat()
    try:
        json.dump({"checked": nowiso, "status": [list(s) for s in pin_status]}, open(CACHE, "w"))
    except Exception:
        pass
    pin_checked = nowiso[:16].replace("T", " ")
now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")

def vrow(v):
    srcs = " ".join(filter(None, [lnk("details", v["details"], "ok"), lnk("claim", v["claim"]), lnk("shot", v["shot"])])) or "-"
    return (f'<tr><td class="d">{html.escape(v["date"])}</td><td class="g">{html.escape(v["group"][:24])}</td>'
            f'<td>{html.escape(v["title"][:60])}</td><td class="d">{html.escape(v["country"])}</td>'
            f'<td class="src">{srcs}</td></tr>')
vrows = "\n".join(vrow(v) for v in victims) or '<tr><td colspan="5">No live data this refresh.</td></tr>'

def pin_row(name, url, up):
    dot = '<span style="color:#3fb950">&#9679; live</span>' if up else '<span style="color:#f85149">&#9679; down now</span>'
    return f'<li>{dot} &nbsp;{lnk(html.escape(name), url)}</li>'
pins = "\n".join(pin_row(*p) for p in pin_status)

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
a{{color:#58a6ff;text-decoration:none}} a:hover{{text-decoration:underline}} a.ok{{color:#3fb950}}
table{{border-collapse:collapse;width:100%;font-size:13px}}
th,td{{text-align:left;padding:4px 8px;border-bottom:1px solid #21262d;vertical-align:top}}
th{{color:#8b949e;font-weight:600}} td.d{{color:#8b949e;white-space:nowrap}} td.g{{color:#f0883e;white-space:nowrap}} td.src a{{margin-right:8px;font-size:12px}}
.pin{{background:#161b22;border:1px solid #30363d;border-radius:6px;padding:8px 14px;margin:8px 0}}
.pin ul{{list-style:none;margin:4px 0;padding:0;columns:2}} .pin li{{padding:2px 0;break-inside:avoid}}
.nav{{margin:10px 0 4px;font-size:12px}} .nav a{{display:inline-block;background:#161b22;border:1px solid #21262d;border-radius:12px;padding:2px 9px;margin:2px 3px 2px 0}}
details{{background:#161b22;border:1px solid #21262d;border-radius:6px;margin:6px 0;padding:2px 10px}}
details summary{{cursor:pointer;font-weight:600;padding:6px 0}}
details.dead{{background:transparent;border:0;margin:4px 0}} details.dead summary{{color:#6e7681;font-weight:400;font-size:12px}}
ul.dir{{list-style:none;margin:4px 0 8px;padding:0;columns:2;column-gap:28px}} ul.dir li{{break-inside:avoid;padding:1px 0;font-size:13px}}
.b{{font-size:10px;font-weight:700}} .c{{color:#6e7681;font-weight:400;font-size:12px}} .x{{color:#6e7681;font-size:11px}}
.err{{color:#d29922;font-size:12px}} .foot{{color:#6e7681;font-size:11px;margin-top:30px;border-top:1px solid #21262d;padding-top:10px}}
@media(max-width:700px){{ul.dir,.pin ul{{columns:1}}}}
</style></head><body>
<h1>CTI Research Dashboard</h1>
<p class="sub">All traffic routed over Tor. Feed refreshed {now}. On any attack, <b>details</b> = ransomware.live writeup (reliable, has the screenshot) even when the gang onion is down.</p>
{errnote}
<h2>Pinned entry points &mdash; onion status checked {pin_checked} (every 12h)</h2>
<div class="pin"><ul>
{pins}
</ul></div>
<h2>Recent ransomware leak-site activity ({len(victims)})</h2>
<table><thead><tr><th>Discovered</th><th>Group</th><th>Victim</th><th>CC</th><th>Sources</th></tr></thead>
<tbody>
{vrows}
</tbody></table>
<h2>Source directory</h2>
<div class="nav">{nav}</div>
{cats}
<p class="foot">Sources: fastfire/deepdarkCTI (GPL-3.0) + ransomware.live + RansomLook. Run <code>python3 build-dashboard.py</code> to refresh. Onion leak sites are DDoS-prone and slow &mdash; first load can take 30-60s; retry, or use the clearnet <b>details</b> link.</p>
</body></html>"""

open(os.path.join(HERE, "dashboard.html"), "w", encoding="utf-8").write(HTMLDOC)
up = sum(1 for _, _, s in pin_status if s)
print(f"wrote dashboard.html | victims: {len(victims)} | pinned onions live: {up}/{len(PINNED)} | errors: {errs or 'none'}")
