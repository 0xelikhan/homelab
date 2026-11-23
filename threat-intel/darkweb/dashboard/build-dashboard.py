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


# ---------- dark-web sample pipeline: samples, funnel, sources ----------
import sqlite3, time as _time
DBPATH = os.path.join(HERE, "malware-findings.db")
WEEK = 7 * 86400
QPORT = 8777                                  # local-only quarantine file server (serve-quarantine.sh)
QBASE = "http://127.0.0.1:%d" % QPORT         # Tor Browser blocks file://, but reaches localhost
RDIR = os.path.expanduser("~/quarantine-review")
DEAD_SKIP, DEAD_EMPTY = 4, 12                 # mirrors crawl-sources.py: retired crawl sources


def _db():
    try:
        return sqlite3.connect("file:%s?mode=ro" % DBPATH, uri=True, timeout=30)
    except Exception:
        return None


def _q(c, sql, args=()):
    try:
        return c.execute(sql, args).fetchall()
    except Exception:
        return []


def _vt():
    """vt-status.json is written by the pve bridge (VirusTotal lookups happen on pve, so the
    key never sits on this VM). {sha256: {"status": "...", "detail": "..."}}"""
    try:
        return json.load(open(os.path.join(HERE, "vt-status.json"), encoding="utf-8"))
    except Exception:
        return {}


def _ago(ts):
    if not ts:
        return ""
    return datetime.datetime.fromtimestamp(ts).strftime("%m-%d %H:%M")


def _pill(text, cls):
    return f'<span class="pill {cls}">{html.escape(text)}</span>'


def _mb_cell(mb):
    mb = mb or "unchecked"
    if mb == "novel":
        return _pill("not in MB", "hot")
    if mb == "known:feed":
        return _pill("from MB", "mute")
    if mb.startswith("known:"):
        return _pill("MB: " + mb.split(":", 1)[1], "known")
    return _pill("unchecked", "mute")


def _vt_cell(v):
    if not v:
        return _pill("pending", "mute")
    st = v.get("status", "")
    if st == "not-found":
        return _pill("not in VT", "hot")
    if st == "found":
        return _pill(v.get("detail", "in VT"), "known")
    return _pill(st or "?", "mute")


def samples_block():
    c = _db()
    if not c:
        return '<p class="x">No database yet.</p>'
    vt = _vt()
    cut = _time.time() - WEEK
    rows = _q(c, "SELECT sha256,origin,source_name,category,filetype,kept,known,family,reasons,"
                 "mb_status,capa_state,caps,attack,ts,pruned FROM triage WHERE kept IN (1,2) AND ts>=? "
                 "ORDER BY (origin='known-feed'), ts DESC", (cut,))
    dw = [r for r in rows if r[1] in ("darkweb", "telegram")]
    kn = [r for r in rows if r[1] == "known-feed"]
    novel = sum(1 for r in rows if r[9] == "novel" or vt.get(r[0], {}).get("status") == "not-found")
    pend = _q(c, "SELECT count(*) FROM triage WHERE capa_state='pending'")
    pend = pend[0][0] if pend else 0
    summ = (f'<div class="kpis">'
            f'<div><b>{sum(1 for r in dw if r[5] == 1)}</b><span>dark web kept</span></div>'
            f'<div><b>{sum(1 for r in dw if r[5] == 2)}</b><span>dark web review</span></div>'
            f'<div><b>{len(kn)}</b><span>known feed</span></div>'
            f'<div><b>{novel}</b><span>not in MB or VT</span></div>'
            f'<div><b>{pend}</b><span>in the capa queue</span></div></div>')

    def row(r):
        sha, origin, src, cat, ftype, kept, known, fam, reasons, mb, cst, caps, atk, ts, pruned = r
        fams = ", ".join(json.loads(fam or "[]")[:2]) or "-"
        why = [x for x in (reasons or "").split(";") if x and not x.startswith(("mb:", "capa:err"))]
        atk = json.loads(atk or "[]")
        ncaps = len(json.loads(caps or "[]"))
        if cat not in ("pe", "elf"):
            capa = '<span class="x">n/a</span>'
        elif cst == "pending":
            capa = _pill("queued", "mute")
        elif cst in ("timeout", "err"):
            capa = _pill(cst, "warn")
        else:
            capa = (f'{ncaps} caps' + (f'<br><span class="x">{html.escape(" ".join(atk[:6]))}'
                                       f'{" +%d" % (len(atk) - 6) if len(atk) > 6 else ""}</span>' if atk else ""))
        org = {"darkweb": _pill("DARK WEB", "dw"), "telegram": _pill("TELEGRAM", "dw"),
               "known-feed": _pill("KNOWN FEED", "mute")}.get(origin, _pill(origin or "?", "mute"))
        if kept == 2:
            org += " " + _pill("REVIEW", "warn")
        base = QDIR if kept == 1 else RDIR
        if pruned or not os.path.isdir(os.path.join(base, sha)):
            loc = '<span class="x">pruned</span>'
        elif kept == 1:
            loc = f'<a class="qf" href="{QBASE}/{sha}/findings.txt">findings</a> <a class="qf" href="{QBASE}/{sha}/">files</a>'
        else:
            loc = f'<span class="qf">{html.escape(os.path.join(base, sha))}</span>'
        return (f'<tr><td class="d">{_ago(ts)}</td><td>{org}</td><td>{html.escape((src or "-")[:28])}</td>'
                f'<td class="x">{html.escape(cat or "")}</td><td>{html.escape(fams[:60])}</td>'
                f'<td class="x">{html.escape(", ".join(why)[:90])}</td><td>{_mb_cell(mb)}</td>'
                f'<td>{_vt_cell(vt.get(sha))}</td><td>{capa}</td><td>{loc}<br>'
                f'<span class="mono">{sha[:16]}</span></td></tr>')

    head = ('<tr><th>Seen</th><th>Origin</th><th>Source</th><th>Type</th><th>Family / signature</th>'
            '<th>Why kept</th><th>MalwareBazaar</th><th>VirusTotal</th><th>capa</th><th>Sample</th></tr>')
    body = "".join(row(r) for r in rows) or '<tr><td colspan="10" class="x">Nothing kept in the last 7 days.</td></tr>'
    return summ + f'<div class="tw"><table class="st">{head}{body}</table></div>'


def funnel_block():
    c = _db()
    if not c:
        return ""
    cut = _time.time() - WEEK

    def one(sql, args=()):
        r = _q(c, sql, args)
        return (r[0][0] or 0) if r else 0

    def stage_counts(since):
        a = (since,)
        out = []
        out.append(("Download links found", one("SELECT count(*) FROM candidates WHERE ts>=?", a)))
        out.append(("Fetched", one("SELECT count(*) FROM fetch_log WHERE outcome='fetched' AND ts>=?", a)))
        out.append(("Files analysed (dark web + Telegram)",
                    one("SELECT count(*) FROM triage WHERE origin!='known-feed' AND ts>=?", a)))
        out.append(("Archives opened", one("SELECT count(*) FROM triage WHERE origin!='known-feed' AND "
                                           "category='archive' AND reasons LIKE 'archive:%-inner%' AND ts>=?", a)))
        out.append(("Executables and scripts analysed",
                    one("SELECT count(*) FROM triage WHERE origin!='known-feed' AND "
                        "category IN ('pe','elf','macho','script') AND ts>=?", a)))
        out.append(("Unflagged binaries waiting for a capa verdict",
                    one("SELECT count(*) FROM triage WHERE kept=3 AND ts>=?", a)))
        out.append(("Review", one("SELECT count(*) FROM triage WHERE origin!='known-feed' AND kept=2 AND ts>=?", a)))
        out.append(("Kept for RE", one("SELECT count(*) FROM triage WHERE origin!='known-feed' AND kept=1 AND ts>=?", a)))
        return out

    wk, al = stage_counts(cut), stage_counts(0)
    top = max([v for _, v in al] + [1])
    trs = []
    for (lbl, w), (_, a) in zip(wk, al):
        trs.append(f'<tr><td>{html.escape(lbl)}</td><td class="n">{w}</td><td class="n">{a}</td>'
                   f'<td class="barc"><div class="bar" style="width:{max(1, int(100 * a / top))}%"></div></td></tr>')
    fails = _q(c, "SELECT outcome, count(*) FROM fetch_log WHERE outcome!='fetched' GROUP BY 1 ORDER BY 2 DESC")
    unx = one("SELECT count(*) FROM triage WHERE reasons='archive:unextractable' AND ts>=?", (cut,))
    since = one("SELECT min(ts) FROM fetch_log")
    fl = " &middot; ".join(f'{html.escape(o)} {n}' for o, n in fails) or "none yet"
    note = (f'<p class="x">Fetch outcomes are logged since {_ago(since) or "now"}, so "Fetched" all-time starts there. '
            f'Failures (latest outcome per link): {fl}. Archives that would not open this week: {unx}. '
            f'Before 2026-11-23 pruning deleted kept samples from the database, so older keeps are missing '
            f'from these counts.</p>')
    return (f'<table class="fn"><tr><th>Stage</th><th class="n">7 days</th><th class="n">All time</th><th></th></tr>'
            f'{"".join(trs)}</table>{note}')


def manual_block():
    c = _db()
    rows = _q(c, "SELECT url, source_name, password, ts FROM manual ORDER BY ts DESC LIMIT 60") if c else []
    if not rows:
        return '<p class="x">None.</p>'
    li = "".join(
        f'<li>{lnk(html.escape(u[:70]), u)} <span class="x">{html.escape(s or "")} &middot; {_ago(t)}'
        f'{" &middot; pw: " + html.escape(", ".join((p or "").split(chr(31)))) if p else ""}</span></li>'
        for u, s, p, t in rows)
    return (f'<p class="x">These hosts block automated downloads on purpose (gofile signs every request '
            f'and bans clients that do not). Open a link in Tor Browser, save the file into '
            f'<code>~/Desktop/manual-intake</code>, and it is triaged within 30 minutes with the passwords '
            f'listed here tried automatically.</p><ul class="dir">{li}</ul>')


def sources_block():
    """Per-source yield: what each source produced at every stage. The crawler already skips
    unreachable URLs (>= DEAD_SKIP straight failures) and demotes empty ones (>= DEAD_EMPTY
    empty fetches); this shows which ones those are."""
    c = _db()
    if not c:
        return ""
    name_urls = {}
    for cat in SRC.values():
        for e in cat.get("entries", []):
            name_urls.setdefault(e.get("name", ""), []).append(e.get("url", ""))
    crawled = {r[0]: r[1:] for r in _q(c, "SELECT url, status, fails, hits, empty, last FROM crawled")}
    stats = {}
    def s(n):
        return stats.setdefault(n or "(unnamed seed)", {"links": 0, "fetched": 0, "files": 0, "kept": 0,
                                                       "review": 0, "last": 0})
    for n, k, t in _q(c, "SELECT source_name, count(*), max(ts) FROM candidates GROUP BY 1"):
        s(n)["links"] += k; s(n)["last"] = max(s(n)["last"], t or 0)
    for n, k in _q(c, "SELECT source_name, count(*) FROM fetch_log WHERE outcome='fetched' GROUP BY 1"):
        s(n)["fetched"] += k
    for n, k, kp, rv in _q(c, "SELECT source_name, count(*), sum(kept=1), sum(kept=2) FROM triage "
                              "WHERE origin!='known-feed' GROUP BY 1"):
        s(n)["files"] += k; s(n)["kept"] += kp or 0; s(n)["review"] += rv or 0
    for n, k in _q(c, "SELECT source_name, count(DISTINCT hash) FROM hashes WHERE COALESCE(kind,'malware')='malware' GROUP BY 1"):
        s(n)["hashes"] = k
    rows = []
    for n, st in stats.items():
        cr = [crawled.get(u) for u in name_urls.get(n, []) if crawled.get(u)]
        fails = max((x[1] or 0) for x in cr) if cr else 0
        empty = min((x[3] or 0) for x in cr) if cr else 0
        if st["kept"]:
            status = _pill("producing", "known")
        elif cr and fails >= DEAD_SKIP:
            status = _pill("retired: unreachable", "mute")
        elif cr and empty >= DEAD_EMPTY:
            status = _pill("retired: empty", "mute")
        elif st["last"] and st["last"] >= _time.time() - 14 * 86400:
            status = _pill("posting links", "dw")
        else:
            status = _pill("quiet", "mute")
        rows.append((st["kept"], st["files"], st["links"], n, st, status))
    rows.sort(key=lambda x: (-x[0], -x[1], -x[2], x[3]))
    tr = "".join(
        f'<tr><td>{html.escape(n[:40])}</td><td class="n">{st["links"]}</td><td class="n">{st["fetched"]}</td>'
        f'<td class="n">{st["files"]}</td><td class="n">{st["kept"]}</td><td class="n">{st["review"]}</td>'
        f'<td class="n">{st.get("hashes", 0)}</td><td class="d">{_ago(st["last"])}</td><td>{status}</td></tr>'
        for _, _, _, n, st, status in rows[:40])
    ret_u = sum(1 for v in crawled.values() if (v[1] or 0) >= DEAD_SKIP)
    ret_e = sum(1 for v in crawled.values() if (v[3] or 0) >= DEAD_EMPTY and (v[1] or 0) < DEAD_SKIP)
    return (f'<p class="x">Crawler: {len(crawled)} URLs tracked, {ret_u} retired as unreachable '
            f'({DEAD_SKIP}+ straight failures, skipped), {ret_e} demoted as empty ({DEAD_EMPTY}+ empty fetches).</p>'
            f'<div class="tw"><table class="st"><tr><th>Source</th><th class="n">Links</th><th class="n">Fetched</th>'
            f'<th class="n">Files</th><th class="n">Kept</th><th class="n">Review</th><th class="n">Hashes</th>'
            f'<th>Last link</th><th>Status</th></tr>{tr}</table></div>')


def indicators_block():
    """Telegram bot C2 tokens + sample hashes announced in posts (malware context only)."""
    try:
        d = json.load(open(os.path.join(HERE, "malware-findings.json"), encoding="utf-8"))
    except Exception:
        return '<p class="x">No findings yet.</p>'

    def srclinks(links, names):
        out = []
        for i, u in enumerate(links[:3]):
            lbl = names[i] if (i < len(names) and names[i]) else (u[:22] + "...")
            out.append(lnk(html.escape(lbl), u))
        return " ".join(out) or '<span class="x">?</span>'
    tk = "".join(
        f'<li>{"<span class=newb>NEW</span> " if t.get("new") else ""}<span class="mono">{html.escape(t["token"])}</span> '
        f'<span class="x">({t.get("site_count", 1)} site, {html.escape(t.get("last", ""))})</span> '
        f'{srclinks(t.get("links", []), t.get("sources", []))}</li>' for t in d.get("tokens", [])[:60])
    hs = "".join(
        f'<li>{"<span class=newb>NEW</span> " if h.get("new") else ""}<span class="mono">{html.escape(h.get("hash", ""))}</span>'
        f'{" <span class=x>(" + html.escape(str(h["family"])) + ")</span>" if h.get("family") else ""} '
        f'<span class="x">{html.escape(h.get("type", ""))} &middot; {html.escape(h.get("last", "")[:10])}</span> '
        f'{srclinks(h.get("source_links", []), h.get("sources", []))}</li>'
        for h in d.get("hashes", [])[:60] if isinstance(h, dict))
    return ((f'<details open><summary>Sample hashes announced in posts ({len(d.get("hashes", []))})</summary>'
             f'<ul class="dir">{hs}</ul></details>' if hs else '<p class="x">No sample hashes in posts.</p>') +
            (f'<details><summary>Telegram bot C2 tokens ({len(d.get("tokens", []))})</summary>'
             f'<ul class="dir">{tk}</ul></details>' if tk else ''))


def mentions_page(css):
    """Secondary page: how often families / groups are MENTIONED (not samples), plus hashes
    of stolen-data archives on leak sites. Context, not RE work."""
    try:
        d = json.load(open(os.path.join(HERE, "malware-findings.json"), encoding="utf-8"))
    except Exception:
        d = {}
    gmap = rl_group_map()

    def flink(nm):
        return gmap.get(nm.lower()) or ("https://malpedia.caad.fkie.fraunhofer.de/search?q=" + nm.replace(" ", "+"))
    fm = "".join(f'<tr><td>{lnk(html.escape(f["name"]), flink(f["name"]))}</td><td class="n">{f.get("hits", 0)}</td>'
                 f'<td class="d">{html.escape(f.get("last", ""))}</td></tr>' for f in d.get("families", []))
    lk = "".join(f'<li><span class="mono">{html.escape(h["hash"])}</span> <span class="x">{html.escape(h.get("last", "")[:10])} '
                 f'{html.escape(", ".join(h.get("sources", [])))}</span></li>' for h in d.get("leak_hashes", []))
    ex = "".join(f'<li>{html.escape(e["ref"][:90])} <span class="x">{html.escape(", ".join(e.get("sources", [])))} '
                 f'{html.escape(e.get("last", "")[:10])}</span></li>' for e in d.get("executables", [])[:150])
    return (f'<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" '
            f'content="width=device-width, initial-scale=1"><title>Mentions</title><style>{css}</style></head><body>'
            f'<p><a href="dashboard.html">&larr; Dark Web Monitoring</a></p><h1>Mentions</h1>'
            f'<p class="sub">How often a family or group name appears next to malware wording on crawled pages. '
            f'These are mention counts, not samples.</p>'
            f'<h2>Families and groups</h2><table class="st"><tr><th>Name</th><th class="n">Pages</th><th>Last seen</th></tr>{fm}</table>'
            f'<h2>Executable and archive names in posts</h2><ul class="dir">{ex or "<li class=x>none</li>"}</ul>'
            f'<h2>Leak-site archive hashes</h2><p class="sub">SHA-256 of stolen-data archives published on leak sites. '
            f'Victim data, not malware.</p><ul class="dir">{lk or "<li class=x>none</li>"}</ul></body></html>')


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
samples_panel = samples_block()
funnel_panel = funnel_block()
manual_panel = manual_block()
sources_panel = sources_block()
indicators_panel = indicators_block()

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
details.why{{background:#0d1117;border:1px solid #21262d;margin:4px 0 2px;padding:0 8px}}
details.why summary{{color:#d29922;font-size:11px;font-weight:600;padding:4px 0}}
details.why pre{{white-space:pre-wrap;word-break:break-word;font:11px/1.45 ui-monospace,Menlo,Consolas,monospace;color:#adbac7;margin:2px 0 8px}}
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
.pill{{display:inline-block;font-size:10px;font-weight:700;padding:1px 6px;border-radius:3px;white-space:nowrap}}
.pill.hot{{background:#da3633;color:#fff}} .pill.known{{background:#30363d;color:#d2a8ff}} .pill.dw{{background:#1f6feb;color:#fff}}
.pill.warn{{background:#9e6a03;color:#fff}} .pill.mute{{background:#21262d;color:#8b949e}}
.kpis{{display:flex;flex-wrap:wrap;gap:10px;margin:8px 0 12px}} .kpis div{{background:#0d1117;border:1px solid #30363d;border-radius:6px;padding:6px 12px;min-width:110px}}
.kpis b{{display:block;font-size:20px;color:#e6edf3}} .kpis span{{color:#8b949e;font-size:11px}}
.tw{{overflow-x:auto}} table.st td,table.st th{{font-size:12px}} td.n,th.n{{text-align:right;font-variant-numeric:tabular-nums}}
table.fn{{max-width:760px}} td.barc{{width:40%}} .bar{{background:#1f6feb;height:9px;border-radius:2px}}
.topnav{{font-size:12px;margin:2px 0 8px}} .topnav a{{margin-right:12px}}
@media(max-width:700px){{ul.dir,.pin ul{{columns:1}}}}
</style></head><body>
<h1>Dark Web Monitoring</h1>
<p class="sub">Updated {now}. Goal: get dark-web malware to reverse engineering early.</p>
<div class="topnav"><a href="#samples">Samples</a><a href="#funnel">Pipeline</a><a href="#manual">Manual downloads</a><a href="#sources">Sources</a><a href="#indicators">Indicators</a><a href="mentions.html">Mentions</a><a href="#telegram">Telegram</a><a href="#directory">Directory</a></div>
<h2 id="samples">New samples this week</h2>
<div class="mw">{samples_panel}</div>
<h2 id="funnel">Pipeline</h2>
{funnel_panel}
<h2 id="manual">Manual downloads</h2>
{manual_panel}
<h2 id="sources">Yield per source</h2>
{sources_panel}
<h2 id="indicators">Indicators from posts</h2>
{indicators_panel}
<h2 id="telegram">Telegram monitor</h2>
{tgs}
<h2 id="directory">Source directory</h2>
<div class="nav">{nav}</div>
{cats}
</body></html>"""
HTMLDOC = HTMLDOC.replace("—", "-").replace("–", "-")

open(os.path.join(HERE, "dashboard.html"), "w", encoding="utf-8").write(HTMLDOC)
_css = re.search(r"<style>(.*?)</style>", HTMLDOC, re.S).group(1)
open(os.path.join(HERE, "mentions.html"), "w", encoding="utf-8").write(
    mentions_page(_css).replace("—", "-").replace("–", "-"))
up = sum(1 for _, _, s in pin_status if s)
print(f"wrote dashboard.html | onions live: {up}/{len(PINNED)} | tg channels: {len(tg_data)}")
