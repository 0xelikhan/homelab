#!/usr/bin/env python3
"""Build the research-VM CTI dashboard (dashboard.html). On the Whonix Workstation
all traffic is transparently Tor-routed, so plain urllib is fine. No JavaScript
(works at Tor Browser 'Safest').  Run via refresh-all.sh on login, or manually.

Sections:
  - Pinned onion entry points, health-checked over Tor (cached, re-checked every 12h).
  - Recent ransomware leak-site activity (ransomware.live + RansomLook), each attack
    linked to its sources (details = ransomware.live writeup w/ screenshot, claim =
    gang leak site, shot). NEW badge = not seen in a previous run.
  - Telegram monitor: recent posts from public channels via t.me/s web preview over
    Tor (no account needed), cached, re-checked every 6h.
  - Deduped directory of ~2500 sources (collapsible).
"""
import json, os, re, html, datetime, glob, urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
QDIR = os.path.expanduser("~/quarantine")   # where triage.py parks verified executables
SRC = json.load(open(os.path.join(HERE, "sources.json"), encoding="utf-8"))
ACTIVE = {"ONLINE", "VALID"}
UA = "cti-dashboard"
TIMEOUT = 45
ONION_INTERVAL_H = 12
TG_INTERVAL_H = 6

PINNED = [
    ("BreachForums (Jan 2026 instance)", "http://breach5yz2b5lepmq4gaqwcon3jippw3bislhvvdavem5git55sy2nid.onion"),
    ("BreachForums (alt instance)",       "http://breachqr3dqbysbq5khaadg5ynnpxn2wrmw5y3rnzesun55l6lkq73yd.onion"),
    ("PwnForums",                         "http://pwnfrm7rbf6kyerigxi677lcz5ifmoagdbqqknwdu2by27wfdst5qmqd.onion"),
    ("Ahmia (onion search)",              "http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion"),
]

def get(url, raw=False):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    r = urllib.request.urlopen(req, timeout=TIMEOUT)
    return r.read().decode("utf-8", "replace") if raw else json.load(r)

def fetch_json(url):
    try:
        return get(url)
    except Exception as e:
        return {"__error__": str(e)[:120]}

def onion_up(url):
    try:
        urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": UA}), timeout=40)
        return True
    except urllib.error.HTTPError:
        return True
    except Exception:
        return False

def cached(name, interval_h, compute):
    """Return compute() but at most once per interval_h; cache in <name>.json."""
    path = os.path.join(HERE, name + ".json")
    try:
        c = json.load(open(path, encoding="utf-8"))
        age = (datetime.datetime.now() - datetime.datetime.fromisoformat(c["checked"])).total_seconds()
        if age < interval_h * 3600:
            return c["data"], c["checked"][:16].replace("T", " ")
    except Exception:
        pass
    data = compute()
    iso = datetime.datetime.now().isoformat()
    try:
        json.dump({"checked": iso, "data": data}, open(path, "w"))
    except Exception:
        pass
    return data, iso[:16].replace("T", " ")

def rl_group_map():
    """family/group name -> ransomware.live profile URL (cached 24h over Tor)."""
    data, _ = cached("rl-groups", 24, lambda: fetch_json("https://api.ransomware.live/v2/groups"))
    m = {}
    if isinstance(data, list):
        for grp in data:
            if not isinstance(grp, dict):
                continue
            u = grp.get("url") or ""
            if not u:
                continue
            nm = (grp.get("name") or "").strip().lower()
            if nm:
                m.setdefault(nm, u)
            alt = grp.get("altname")
            if isinstance(alt, str):
                for a in re.split(r"[,/|]", alt):
                    a = a.strip().lower()
                    if a:
                        m.setdefault(a, u)
    return m


# ---------- dark-web malware early-warning (verified executables) ----------
def verified_samples():
    """Executables that triage.py pulled, statically verified as malicious, and parked in
    ~/quarantine for the REs. Reads the triage table directly (triage runs before this)."""
    import sqlite3
    try:
        c = sqlite3.connect(os.path.join(HERE, "malware-findings.db"))
        return c.execute("SELECT sha256, source_name, filetype, known, family, last_seen "
                         "FROM (SELECT *, ts AS last_seen FROM triage WHERE kept=1) "
                         "ORDER BY last_seen DESC LIMIT 120").fetchall()
    except Exception:
        return []


def quarantine_path(sha):
    """Absolute path of the kept sample on disk (named <sha>.<ext>), or '' if pruned."""
    if not sha:
        return ""
    hits = glob.glob(os.path.join(QDIR, sha + ".*")) or glob.glob(os.path.join(QDIR, sha))
    return hits[0] if hits else ""


def malware_block():
    """Primary panel: verified malicious executables pulled + statically triaged for the REs."""
    path = os.path.join(HERE, "malware-findings.json")
    try:
        d = json.load(open(path, encoding="utf-8"))
    except Exception:
        return '<div class="mw"><p class="x">No findings yet.</p></div>'

    def srclinks(links, names):
        out = []
        for i, u in enumerate(links[:3]):
            lbl = names[i] if (i < len(names) and names[i]) else (u[:22] + "…")
            out.append(f'<a href="{html.escape(u)}">{html.escape(lbl)}</a>')
        return " ".join(out) or '<span class="x">?</span>'

    exrows = []
    for sha, src, ftype, known, fam, _ts in verified_samples():
        kb = '<span class="knownb">KNOWN</span> ' if known else ''
        famtxt = ''
        try:
            fl = json.loads(fam or "[]")
            if fl:
                famtxt = f' <span class="famb">{html.escape(str(fl[0]))}</span>'
        except Exception:
            pass
        qp = quarantine_path(sha or "")
        if qp:
            qloc = (f'<a class="qf" href="file://{html.escape(qp, quote=True)}" '
                    f'title="click to open, or copy this path on the box">&#128193; {html.escape(qp)}</a>')
        else:
            qloc = '<span class="x">(pruned from quarantine)</span>'
        exrows.append(f'<li>{kb}<span class="mono">{html.escape((sha or "")[:20])}</span>{famtxt} '
                      f'<span class="x">({html.escape((ftype or "")[:34])} · {html.escape((src or "?")[:24])})</span>'
                      f'<br>{qloc}</li>')
    exblock = (f'<details open><summary>Executables</summary>'
               f'<ul class="dir exe">{"".join(exrows)}</ul></details>' if exrows else '')

    fams = d.get("sample_families", [])
    famline = ''
    if fams:
        gmap = rl_group_map()
        def _flink(nm):
            u = gmap.get(nm.lower())
            return u or ("https://malpedia.caad.fkie.fraunhofer.de/search?q=" + nm.replace(" ", "+"))
        tags = " ".join(
            (('<span class="newb">NEW</span> ' if x.get("new") else '')
             + f'<a href="{html.escape(_flink(x["name"]), quote=True)}" target="_blank" rel="noreferrer">'
               f'<span class="famb">{html.escape(x["name"])} <span class="x">{x.get("count", 0)}</span></span></a>')
            for x in fams[:30])
        famline = f'<div class="fams">{tags}</div>'

    tkrows = []
    for t in d.get("tokens", [])[:60]:
        nb = '<span class="newb">NEW</span> ' if t.get("new") else ''
        tkrows.append(f'<li>{nb}<span class="mono">{html.escape(t["token"])}</span> '
                      f'<span class="x">({t.get("site_count",1)} site, {html.escape(t.get("last",""))})</span> '
                      f'{srclinks(t.get("links",[]), t.get("sources",[]))}</li>')
    tkblock = (f'<details open><summary>Telegram bot C2 tokens</summary>'
               f'<ul class="dir">{"".join(tkrows)}</ul></details>' if tkrows else '')
    exmain = exblock or '<p class="x">No verified executables yet.</p>'
    return ('<div class="mw">' + famline + exmain + tkblock + '</div>')


# ---------- live ransomware feed + new-since-last ----------
def live_victims():
    rows, errs = [], []
    a = fetch_json("https://api.ransomware.live/v2/recentvictims")
    if isinstance(a, list):
        for v in a:
            rows.append({"date": (v.get("discovered") or v.get("attackdate") or "")[:10],
                         "group": v.get("group", ""), "title": v.get("victim", ""), "country": v.get("country", ""),
                         "details": v.get("url", ""), "claim": v.get("claim_url", ""), "shot": v.get("screenshot", "")})
    elif isinstance(a, dict):
        errs.append("ransomware.live: " + a.get("__error__", "?"))
    b = fetch_json("https://www.ransomlook.io/api/recent")
    if isinstance(b, list):
        for v in b:
            link = v.get("link", "")
            rows.append({"date": (v.get("discovered") or "")[:10], "group": v.get("group_name", ""),
                         "title": v.get("post_title", ""), "country": "",
                         "details": ("https://www.ransomlook.io/" + link.lstrip("/")) if link else "", "claim": "", "shot": ""})
    elif isinstance(b, dict):
        errs.append("ransomlook: " + b.get("__error__", "?"))
    seen_k, uniq = set(), []
    for r in sorted(rows, key=lambda r: r["date"], reverse=True):
        k = (r["group"].lower(), r["title"].lower())
        if k in seen_k or not r["title"]:
            continue
        seen_k.add(k); uniq.append(r)
    return uniq[:80], errs

def mark_new(victims):
    path = os.path.join(HERE, "seen.json")
    try:
        seen = json.load(open(path, encoding="utf-8"))
    except Exception:
        seen = {}
    now = datetime.datetime.now().isoformat()
    newc = 0
    for v in victims:
        k = (v["group"] + "|" + v["title"]).lower()
        v["new"] = k not in seen
        if v["new"]:
            seen[k] = now; newc += 1
    if len(seen) > 3000:   # prune oldest
        seen = dict(sorted(seen.items(), key=lambda x: x[1])[-2000:])
    try:
        json.dump(seen, open(path, "w"))
    except Exception:
        pass
    return newc

# ---------- telegram public-preview monitor ----------
def tg_channels():
    f = os.path.join(HERE, "tg-channels.txt")
    if os.path.exists(f):
        return [l.strip().lstrip("@") for l in open(f, encoding="utf-8") if l.strip() and not l.startswith("#")][:20]
    chans = []
    for e in SRC.get("telegram_ta", {}).get("entries", []):
        m = re.match(r"https?://t\.me/([A-Za-z0-9_]{4,})/?$", e["url"])
        if m and e["status"] in ACTIVE:
            chans.append(m.group(1))
        if len(chans) >= 12:
            break
    return chans

def fetch_tg(ch):
    try:
        h = get("https://t.me/s/" + ch, raw=True)
        posts = re.findall(r'tgme_widget_message_text js-message_text[^>]*>(.*?)</div>', h, re.S)
        dates = re.findall(r'datetime="([0-9T:+\-]+)"', h)
        clean = []
        for p in posts[-3:]:
            t = html.unescape(re.sub(r"<[^>]+>", " ", p)).strip()
            if t:
                clean.append(t[:200])
        return {"ch": ch, "last": (dates[-1][:16].replace("T", " ") if dates else ""), "posts": clean}
    except Exception as e:
        return {"ch": ch, "last": "", "posts": [], "err": str(e)[:50]}

# ---------- render ----------
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
    inner = f'<ul class="dir">\n{entry_rows(act)}\n</ul>'
    if dead:
        dr = "\n".join(f'<li><span class="b" style="color:#6e7681">OFFLINE</span> {html.escape(e["name"][:80])}</li>' for e in dead)
        inner += f'<details class="dead"><summary>offline / unverified ({len(dead)})</summary><ul class="dir">\n{dr}\n</ul></details>'
    return (f'<details id="{key}"><summary>{html.escape(cat["title"])} '
            f'<span class="c">{cat["active"]} active / {cat["total"]}</span></summary>\n{inner}\n</details>')

pin_status, pin_checked = cached("onion-status", ONION_INTERVAL_H,
    lambda: [list(x) for x in ThreadPoolExecutor(max_workers=4).map(lambda p: (p[0], p[1], onion_up(p[1])), PINNED)])
tg_data, tg_checked = cached("telegram", TG_INTERVAL_H,
    lambda: list(ThreadPoolExecutor(max_workers=6).map(fetch_tg, tg_channels())))
now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")

def vrow(v):
    srcs = " ".join(filter(None, [lnk("details", v["details"], "ok"), lnk("claim", v["claim"]), lnk("shot", v["shot"])])) or "-"
    nb = '<span class="new">NEW</span> ' if v.get("new") else ""
    return (f'<tr><td class="d">{nb}{html.escape(v["date"])}</td><td class="g">{html.escape(v["group"][:24])}</td>'
            f'<td>{html.escape(v["title"][:60])}</td><td class="d">{html.escape(v["country"])}</td>'
            f'<td class="src">{srcs}</td></tr>')
# ransomware leak-site feed removed (board is now malware-indicator focused)

def pin_row(name, url, up):
    dot = '<span style="color:#3fb950">&#9679; live</span>' if up else '<span style="color:#f85149">&#9679; down now</span>'
    return f'<li>{dot} &nbsp;{lnk(html.escape(name), url)}</li>'
pins = "\n".join(pin_row(*p) for p in pin_status)

def tg_block(d):
    posts = "".join(f'<li>{html.escape(p)}</li>' for p in d.get("posts", [])) or '<li class="x">no recent public posts / unreachable</li>'
    last = f' <span class="c">{html.escape(d["last"])}</span>' if d.get("last") else ""
    return (f'<details><summary>{lnk("@" + html.escape(d["ch"]), "https://t.me/s/" + d["ch"])}{last}</summary>'
            f'<ul class="tg">{posts}</ul></details>')
tgs = "\n".join(tg_block(d) for d in tg_data) or '<p class="x">No channels configured.</p>'

nav = " ".join(f'<a href="#{k}">{SRC[k]["title"].split(" - ")[0].split(" / ")[0]} ({SRC[k]["active"]})</a>' for k in SRC)
cats = "\n".join(category_block(k, SRC[k]) for k in SRC)
malware_panel = malware_block()

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
.new{{background:#1f6feb;color:#fff;font-size:9px;font-weight:700;padding:1px 4px;border-radius:3px;vertical-align:middle}}
.pin{{background:#161b22;border:1px solid #30363d;border-radius:6px;padding:8px 14px;margin:8px 0}}
.pin ul{{list-style:none;margin:4px 0;padding:0;columns:2}} .pin li{{padding:2px 0;break-inside:avoid}}
.nav{{margin:10px 0 4px;font-size:12px}} .nav a{{display:inline-block;background:#161b22;border:1px solid #21262d;border-radius:12px;padding:2px 9px;margin:2px 3px 2px 0}}
details{{background:#161b22;border:1px solid #21262d;border-radius:6px;margin:6px 0;padding:2px 10px}}
details summary{{cursor:pointer;font-weight:600;padding:6px 0}}
details.dead{{background:transparent;border:0;margin:4px 0}} details.dead summary{{color:#6e7681;font-weight:400;font-size:12px}}
ul.dir{{list-style:none;margin:4px 0 8px;padding:0;columns:2;column-gap:28px}} ul.dir li{{break-inside:avoid;padding:1px 0;font-size:13px}}
ul.exe{{columns:1}} ul.exe li{{padding:4px 0}}
a.qf{{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:11px;color:#3fb950;word-break:break-all}}
ul.tg{{margin:4px 0 8px;padding-left:18px;font-size:12px;color:#adbac7}} ul.tg li{{padding:2px 0}}
.b{{font-size:10px;font-weight:700}} .c{{color:#6e7681;font-weight:400;font-size:12px}} .x{{color:#6e7681;font-size:11px}}
.err{{color:#d29922;font-size:12px}} .foot{{color:#6e7681;font-size:11px;margin-top:30px;border-top:1px solid #21262d;padding-top:10px}}
.mw{{background:#161b22;border:1px solid #30363d;border-left:3px solid #f85149;border-radius:6px;padding:4px 14px 10px;margin:6px 0 14px}}
.mw .sub{{margin:6px 0 10px}} .ctxb{{background:#da3633;color:#fff;font-size:9px;font-weight:700;padding:1px 5px;border-radius:3px}}
.mono{{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:11px;word-break:break-all;color:#e6edf3}}
code{{background:#0d1117;border:1px solid #21262d;border-radius:4px;padding:1px 4px;font-size:11px;color:#79c0ff}}
.newb{{background:#238636;color:#fff;font-size:9px;font-weight:700;padding:1px 5px;border-radius:3px}}
.knownb{{background:#6e5494;color:#fff;font-size:9px;font-weight:700;padding:1px 5px;border-radius:3px}}
.famb{{background:#30363d;color:#d29922;font-size:10px;padding:1px 6px;border-radius:3px;border:1px solid #3d4350}}
.fams{{margin:2px 0 10px}} .fams span{{margin:0 4px 5px 0;display:inline-block}}
.tierh{{background:#da3633;color:#fff;font-size:9px;font-weight:700;padding:1px 5px;border-radius:3px}}
.tierm{{background:#9e6a03;color:#fff;font-size:9px;font-weight:700;padding:1px 5px;border-radius:3px}}
@media(max-width:700px){{ul.dir,.pin ul{{columns:1}}}}
</style></head><body>
<h1>Dark Web Monitoring</h1>
{malware_panel}
<h2>Telegram monitor</h2>
{tgs}
<h2>Source directory</h2>
<div class="nav">{nav}</div>
{cats}
</body></html>"""
HTMLDOC = HTMLDOC.replace("—", "-").replace("–", "-")

open(os.path.join(HERE, "dashboard.html"), "w", encoding="utf-8").write(HTMLDOC)
up = sum(1 for _, _, s in pin_status if s)
print(f"wrote dashboard.html | onions live: {up}/{len(PINNED)} | tg channels: {len(tg_data)}")
