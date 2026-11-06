#!/usr/bin/env python3
"""
Dark-web monitoring crawler  -  STRICTLY READ-ONLY.

Crawls onion sites, Telegram channels and the source directory over Tor and
mines each page for file hashes, executables, and the malware families / loaders
/ crypters being traded, so samples can be pulled and analysed before or soon
after they are used.

SAFETY - never downloads or runs anything:
  * GET only; never POSTs, logs in, or executes.
  * Refuses any URL ending in an executable/archive (.exe .dll .ps1 .apk .elf
    .zip .7z ...): the link is recorded, never requested.
  * Content-Type checked (text/HTML only); binary responses abandoned unread.
  * Every fetch hard-capped at MAX_BYTES; no file is ever saved.
  * For any sample it stores the LINK + hash only.

Features:
  1. Link-following: from a source landing page it follows a few same-host
     thread/listing links (where the samples actually are). Search-engine
     result pages follow their result links cross-host (discovery).
  2. "new" flag: a hash/executable first seen in the last NEW_WINDOW_H.
  3. Telegram + malware-family parsing: recognises known families/loaders/
     crypters and tracks which are active.
  4. Search-engine discovery: queries onion search engines for malware terms
     and mines what they surface.
  5. Prioritised rotation: malware-relevant categories first; onions that are
     dead run after run are skipped so each run finds more.

Bounded: each run spends a fixed fetch budget, then stops. Automated via a
systemd --user timer.
"""
import os, re, json, time, sqlite3, datetime, urllib.request, urllib.error, socket
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

HERE    = os.path.dirname(os.path.abspath(__file__))
SOURCES = os.path.join(HERE, "sources.json")
SEEDS   = os.path.expanduser("~/onionclaw/research-seeds.txt")
DB      = os.path.join(HERE, "malware-findings.db")
OUT     = os.path.join(HERE, "malware-findings.json")

UA            = "cti-dashboard"
PAGE_TIMEOUT  = 25
MAX_BYTES     = 700_000
MAX_WORKERS   = 6
SOURCES_RUN   = 100          # source landing pages per run
CHILD_BUDGET  = 140          # extra thread/listing/result pages per run
CHILD_PER_SRC = 5           # max children followed from one page
DEAD_SKIP      = 4          # skip a URL after this many straight failures
NEW_WINDOW_H  = 36          # a finding is "new" if first seen within this many hours
RETENTION_DAYS = 30         # drop findings not seen in this many days

# malware-relevant categories first; the long tail of leak sites last
CAT_ORDER = ["telegram_ta", "forums", "telegram_is", "ransomware",
             "markets", "search", "others"]

# onion search engines + malware queries -> discovery (feature 4)
SEARCH_ENGINES = [
    "http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion/search/?q=%s",  # Ahmia
]
SEARCH_TERMS = ["malware+sample", "stealer+logs", "crypter+fud", "loader+builder",
                "ransomware+source"]

BINARY_EXT = re.compile(
    r"\.(exe|dll|scr|sys|msi|ps1|psm1|vbs|vbe|jse|wsf|hta|bat|cmd|pif|lnk|jar|apk|"
    r"dex|elf|ko|bin|iso|img|vhd|vmdk|7z|rar|zip|gz|bz2|xz|tar|tgz|cab|ace|arj|dmg|"
    r"pkg|deb|rpm|docm|xlsm|pptm)(\?|#|/|$)", re.I)

HASH_RE = [("sha256", re.compile(r"\b[a-fA-F0-9]{64}\b")),
           ("sha1",   re.compile(r"\b[a-fA-F0-9]{40}\b")),
           ("md5",    re.compile(r"\b[a-fA-F0-9]{32}\b"))]
_SAMPLE = (r"exe|dll|scr|sys|msi|ps1|psm1|vbs|vbe|jse|wsf|hta|bat|cmd|pif|lnk|jar|"
           r"apk|dex|elf|ko|bin|iso|img|vhd|7z|rar|dmg|deb|rpm|cab|ace|arj|docm|xlsm")
EXE_RE      = re.compile(r"\b([\w\-]{1,60}\.(?:%s))\b" % _SAMPLE, re.I)
SAMPLE_LINK = re.compile(r"\.(?:%s)(\?|#|$)" % _SAMPLE, re.I)
HREF_RE     = re.compile(r'href=["\']([^"\']+)["\']', re.I)
SRC_RE      = re.compile(r'src=["\']([^"\']+)["\']', re.I)
NOISE_RE = re.compile(
    r"(jquery|bootstrap|popper|clipboard|viewer|owl|slick|swiper|gsap|modernizr|"
    r"fontawesome|polyfill|runtime|vendor|chunk|manifest|service.?worker|analytics|"
    r"gtag|fbevents|hotjar|recaptcha|captcha|cdnjs|jsdelivr|unpkg|googleapis|gstatic|"
    r"cloudflare|\.min\.|/assets/|/static/|\btest\.(zip|rar|7z)\b)", re.I)
CTX_RE = re.compile(
    r"\b(sample|builder|stub|loader|payload|dropper|crypter|packer|obfuscat|fud|inject|xinject|kleenscan|scan_result|avcheck|clickfix|fake.?captcha|"
    r"undetect|0\s?day|zero[\s-]?day|ransomware|stealer|infostealer|keylog|\brat\b|"
    r"botnet|malware|trojan|backdoor|rootkit|worm|exploit|c2|c&c|source\s?code|"
    r"cracked|nulled|leak)\b", re.I)
# Russian / transliterated malware context (many actor channels are RU-language)
CTX_RU = re.compile(
    r"ботнет|стилер|лоадер|загрузчик|троян|бэкдор|вредонос|эксплойт|"
    r"шифровальщик|вымогател|кейлог|дроппер|инжект|криптор|закрипт|"
    r"недетект|обфуск|сборк|уязвимост", re.I)
# Non-English malware context (CJK/Arabic/Farsi need no word boundaries; latin uses stems)
CTX_INTL = re.compile(
    r"\u6728\u9a6c|\u75c5\u6bd2|\u52d2\u7d22|\u540e\u95e8|\u7a83\u5bc6|\u7a83\u53d6|\u52a0\u8f7d\u5668|\u50f5\u5c38\u7f51\u7edc|\u6076\u610f|\u6f0f\u6d1e|\u514d\u6740|\u8fdc\u63a7|\u76d7\u53f7|\u52a0\u5bc6\u5668|\u6837\u672c|"
    r"\uc545\uc131|\ub7a9\uc12c|\ud2b8\ub85c\uc774|\ubc31\ub3c4\uc5b4|\ubd07\ub137|\ud53c\uc2f1|\ucde8\uc57d\uc810|\uc775\uc2a4\ud50c\ub85c\uc787|\uc2a4\ud2f8\ub7ec|\ub85c\ub354|"
    r"\u0641\u062f\u064a\u0629|\u062a\u0631\u0648\u062c\u0627\u0646|\u0627\u062e\u062a\u0631\u0627\u0642|\u062b\u063a\u0631\u0629|\u0627\u0633\u062a\u063a\u0644\u0627\u0644|\u0633\u0627\u0631\u0642|\u0628\u0627\u0628 \u062e\u0644\u0641\u064a|\u0628\u0631\u0645\u062c\u064a\u0627\u062a \u062e\u0628\u064a\u062b\u0629|"
    r"\u0628\u062f\u0627\u0641\u0632\u0627\u0631|\u0628\u0627\u062c\u200c\u0627\u0641\u0632\u0627\u0631|\u0627\u06a9\u0633\u067e\u0644\u0648\u06cc\u062a|\u0627\u0633\u062a\u06cc\u0644\u0631|\u0644\u0648\u062f\u0631|"
    r"troyano|ran\u00e7ongiciel|ran\u00e7on|maliciel|malveillant|vulnerabilidad|explotaci|ladr\u00f3n|"
    r"puerta trasera|cargador|cheval de troie|porte d\u00e9rob\u00e9e|voleur|hame\u00e7on|software dannoso|caricatore|vulnerabilit\u00e0",
    re.I)
# actor / ransomware-group taxonomy (254 actors, 390 aliases from ThreatActors-TTPs)
try:
    import json as _json
    _ad = _json.load(open(os.path.join(HERE, "actors.json"), encoding="utf-8"))
    _ACTOR_CANON = {}
    for _nm in _ad.get("ransomware", []):
        _ACTOR_CANON[_nm.lower()] = _nm
    for _al, _canon in (_ad.get("aliases") or {}).items():
        _ACTOR_CANON.setdefault(_al.lower(), _canon)
    _STOP = {"play","royal","akira","medusa","storm","spider","bear","panda","kitten",
             "gold","inc","team","group","hunters","meta","mars","qilin","cl0p","clop",
             "dark halo","the dukes","cactus","money message","rhysida"}
    _terms = sorted({k for k in _ACTOR_CANON if len(k) >= 4 and k not in _STOP}, key=len, reverse=True)
    ACTOR_RE = re.compile(r"\b(" + "|".join(re.escape(t) for t in _terms) + r")\b", re.I) if _terms else None
except Exception:
    _ACTOR_CANON = {}
    ACTOR_RE = None
def _mal_ctx(s):
    return bool(CTX_RE.search(s) or CTX_RU.search(s) or CTX_INTL.search(s))
# strings that look like a hash but are web tokens / cache-busters, not malware
TOKEN_CTX = re.compile(
    r"csrf|cache|nonce|\btoken\b|session|integrity|etag|anti.?cache|_wpnonce|"
    r"apikey|api.key|secret|hmac|\btx\b|txid|transaction|blockchain|block\s?hash|"
    r"confirmation|escrow|\bcommit\b|\bblob\b|gitlab|github|"
    r"\.(png|jpe?g|gif|css|js|svg|woff2?|ico|map|webp)\b", re.I)
# known families / loaders / crypters / RAT / ransomware (feature 3)
FAMILIES = [
    "RedLine", "LummaC2", "Lumma", "Vidar", "Raccoon", "StealC", "Meta Stealer",
    "Rhadamanthys", "Amadey", "Azorult", "Mars Stealer", "Aurora", "Erbium",
    "Bandit", "Atomic", "AMOS", "Phemedrone", "WhiteSnake", "Mystic",
    "SmokeLoader", "GuLoader", "BumbleBee", "IcedID", "Emotet", "Qakbot",
    "PikaBot", "DarkGate", "Latrodectus", "Pikabot",
    "AsyncRAT", "Remcos", "njRAT", "QuasarRAT", "DarkComet", "XWorm", "NanoCore",
    "Venom RAT", "AgentTesla", "Agent Tesla", "FormBook", "SnakeKeylogger",
    "CobaltStrike", "Cobalt Strike", "Sliver", "Mythic", "Brute Ratel", "Havoc",
    "LockBit", "BlackCat", "ALPHV", "Cl0p", "Clop", "Akira", "BianLian", "Royal",
    "Qilin", "RansomHub", "Medusa", "Play", "Hunters", "INC Ransom",
    "Xinject", "DCRat", "RisePro", "Lumar", "Kematian",
    "Acreed", "ACRStealer", "RevStealer", "Eternidade", "MacSync",
    "DigitStealer", "Shub Stealer", "Remus", "Elysium",
    "POOLRAT", "PrivateLoader",
]
FAMILY_RE = re.compile(r"\b(" + "|".join(re.escape(f) for f in FAMILIES) + r")\b", re.I)
_FAM_CANON = {f.lower(): f for f in FAMILIES}
EXE_AMBIG = {"cmd", "img", "bin", "iso", "sys", "ko", "vhd", "com"}
# family names that are also common English words: require malware context
AMBIG_FAM = {"atomic", "play", "aurora", "bandit", "royal", "mystic", "havoc",
             "akira", "medusa", "qilin", "hunters", "mars", "meta", "erbium",
             "remus", "elysium"}
# links worth following into (threads / listings / releases), feature 1
FOLLOW_HINT = re.compile(
    r"(thread|topic|viewtopic|showthread|/t/|post|product|item|listing|release|"
    r"download|/dl/|sample|malware|stealer|loader|crypter|builder|market|shop|"
    r"forum|board|category|section)", re.I)

TAG_RE = re.compile(r"<[^>]+>")
WS_RE  = re.compile(r"\s+")


def init_db():
    c = sqlite3.connect(DB)
    c.executescript("""
    CREATE TABLE IF NOT EXISTS hashes(
        hash TEXT, htype TEXT, source_url TEXT, source_name TEXT, category TEXT,
        malware_ctx INTEGER, family TEXT, context TEXT, first_seen REAL, last_seen REAL,
        PRIMARY KEY(hash, source_url));
    CREATE TABLE IF NOT EXISTS exes(
        ref TEXT, source_url TEXT, source_name TEXT, category TEXT,
        first_seen REAL, last_seen REAL, PRIMARY KEY(ref, source_url));
    CREATE TABLE IF NOT EXISTS families(
        name TEXT PRIMARY KEY, hits INTEGER, first_seen REAL, last_seen REAL);
    CREATE TABLE IF NOT EXISTS crawl_state(k TEXT PRIMARY KEY, v TEXT);
    CREATE TABLE IF NOT EXISTS crawled(url TEXT PRIMARY KEY, last REAL, status TEXT, fails INTEGER DEFAULT 0);
    CREATE TABLE IF NOT EXISTS tokens(
        token TEXT, source_url TEXT, source_name TEXT, category TEXT, context TEXT,
        first_seen REAL, last_seen REAL, PRIMARY KEY(token, source_url));
    """)
    c.commit()
    return c


def directory_targets():
    out = []
    try:
        d = json.load(open(SOURCES, encoding="utf-8"))
        for cat in CAT_ORDER:
            cd = d.get(cat, {})
            for it in (cd.get("entries") or cd.get("items") or []):
                u = (it.get("url") or "").strip()
                if u:
                    out.append((cat, it.get("name", ""), u, False))
    except Exception:
        pass
    try:
        for ln in open(SEEDS, encoding="utf-8"):
            ln = ln.strip()
            if ln and not ln.startswith("#"):
                out.append(("seed", "", ln if "://" in ln else "http://" + ln, False))
    except Exception:
        pass
    return out


def search_targets():
    out = []
    for eng in SEARCH_ENGINES:
        for term in SEARCH_TERMS:
            out.append(("search-disc", "search:" + term.replace("+", " "), eng % term, True))
    return out


def to_fetchable(url):
    m = re.search(r"t\.me/(?:s/)?(@?[\w+]+)", url)
    if m:
        return "https://t.me/s/" + m.group(1).lstrip("@")
    return url


def read_only_get(url):
    """Fetch page TEXT only. Refuses binaries by extension and content-type; byte-capped."""
    if BINARY_EXT.search(url):
        return None, "binary-link (not fetched)"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA}, method="GET")
        with urllib.request.urlopen(req, timeout=PAGE_TIMEOUT) as r:
            ct = (r.headers.get("Content-Type") or "").lower()
            if ct and not any(t in ct for t in ("text/", "xhtml", "application/json", "xml")):
                return None, "non-text:" + ct[:24]
            return r.read(MAX_BYTES).decode("utf-8", "replace"), None
    except urllib.error.HTTPError as e:
        return None, "http%s" % e.code
    except (urllib.error.URLError, socket.timeout) as e:
        return None, str(getattr(e, "reason", e))[:50]
    except Exception as e:
        return None, str(e)[:50]


# Telegram bot token = live infostealer C2 (bot_id:35-char base64url)
BOT_TOKEN = re.compile(r"(?<![\w:])([0-9]{8,10}:[A-Za-z0-9_-]{35})(?![\w-])")

def mine(text):
    """Return (hashes, exes, families). hashes:[(hash,htype,ctx,fam,context)]."""
    clean = WS_RE.sub(" ", TAG_RE.sub(" ", text))
    low = clean.lower()
    hashes, seen = [], set()
    for htype, rx in HASH_RE:
        for m in rx.finditer(clean):
            h = m.group(0).lower()
            if h in seen:
                continue
            seen.add(h)
            i = low.find(h)
            ctx = clean[max(0, i - 90): i + len(h) + 90].strip()
            if TOKEN_CTX.search(ctx):               # csrf / cache key / session / asset buster
                continue
            is_mal = _mal_ctx(ctx)
            if htype in ("md5", "sha1") and not is_mal:   # short hashes need malware context
                continue
            fam = FAMILY_RE.search(ctx)
            fam_c = _FAM_CANON.get(fam.group(1).lower()) if fam else None
            if fam_c and fam_c.lower() in AMBIG_FAM and not is_mal:
                fam_c = None
            hashes.append((h, htype, is_mal, fam_c, ctx[:200]))
    exes = set()
    # bare filename tokens: must sit in malware context; ambiguous extensions
    # (.cmd/.img/.bin/.sys) only ever count with context (kills JS/CSS tokens)
    for m in EXE_RE.finditer(clean):
        ref = m.group(1)
        if NOISE_RE.search(ref):
            continue
        i = m.start()
        ctx = clean[max(0, i - 90): i + len(ref) + 90]
        if not _mal_ctx(ctx):
            continue
        exes.add(ref[:160])
    # real download links ending in a sample extension: strong signal kept,
    # but ambiguous extensions in a link still need malware context on the page
    for m in HREF_RE.finditer(text):
        link = m.group(1)
        if not (SAMPLE_LINK.search(link) and not NOISE_RE.search(link)):
            continue
        em = re.search(r"\.([a-z0-9]{1,5})(?:\?|#|$)", link.lower())
        if em and em.group(1) in EXE_AMBIG and not _mal_ctx(low):
            continue
        exes.add(link[:200])
    fams = set()
    for x in FAMILY_RE.finditer(clean):
        canon = _FAM_CANON.get(x.group(1).lower())
        if not canon:
            continue
        if canon.lower() in AMBIG_FAM:
            i = x.start()
            fctx = clean[max(0, i - 100): i + len(x.group(1)) + 100]
            if not _mal_ctx(fctx):
                continue
        fams.add(canon)
    if ACTOR_RE is not None:
        for am in ACTOR_RE.finditer(clean):
            ai = am.start()
            aw = clean[max(0, ai - 100): ai + len(am.group(1)) + 100]
            if _mal_ctx(aw):
                fams.add(_ACTOR_CANON.get(am.group(1).lower(), am.group(1)))
    return hashes, sorted(exes), fams


def child_links(text, base, is_search):
    """Eligible pages to follow. Search results: cross-host. Others: same host, thread-like."""
    host = urlparse(base).netloc
    out, seen = [], set()
    for m in HREF_RE.finditer(text):
        href = m.group(1).strip()
        if href.startswith(("#", "mailto:", "javascript:", "data:")):
            continue
        u = urljoin(base, href)
        pu = urlparse(u)
        if pu.scheme not in ("http", "https") or not pu.netloc:
            continue
        if BINARY_EXT.search(u):          # never queue a binary
            continue
        if u in seen:
            continue
        if is_search:
            if ".onion" in pu.netloc and pu.netloc != host:   # a discovered result site
                seen.add(u); out.append(u)
        else:
            if pu.netloc == host and FOLLOW_HINT.search(u):   # a thread/listing on the same site
                seen.add(u); out.append(u)
        if len(out) >= CHILD_PER_SRC:
            break
    return out


def pick_slice(c, targets):
    """Round-robin across categories so every run samples the hash-bearing
    clearnet sources (threat-actor telegram, forums) first, not whatever a
    single linear offset lands on. Dead URLs (>=DEAD_SKIP straight failures)
    are skipped. Each category keeps its own offset and advances per run."""
    dead = {r[0] for r in c.execute("SELECT url FROM crawled WHERE fails>=?", (DEAD_SKIP,))}
    buckets = {}
    for t in targets:
        if t[2] in dead:
            continue
        buckets.setdefault(t[0], []).append(t)
    if not buckets:
        for t in targets:
            buckets.setdefault(t[0], []).append(t)
    order = ([cat for cat in CAT_ORDER if cat in buckets] + [cat for cat in buckets if cat not in CAT_ORDER])
    if not order:
        return targets[:SOURCES_RUN]
    row = c.execute("SELECT v FROM crawl_state WHERE k='offsets'").fetchone()
    try:
        offs = json.loads(row[0]) if (row and row[0]) else {}
    except Exception:
        offs = {}
    sl, seen = [], set()
    maxlen = max(len(v) for v in buckets.values())
    cyc = 0
    while len(sl) < SOURCES_RUN and cyc < maxlen:
        for cat in order:
            if len(sl) >= SOURCES_RUN:
                break
            lst = buckets[cat]
            o = (int(offs.get(cat, 0)) + cyc) % len(lst)
            t = lst[o]
            if t[2] in seen:
                continue
            seen.add(t[2])
            sl.append(t)
        cyc += 1
    for cat in order:
        consumed = sum(1 for t in sl if t[0] == cat)
        offs[cat] = (int(offs.get(cat, 0)) + consumed) % max(len(buckets[cat]), 1)
    c.execute("INSERT OR REPLACE INTO crawl_state VALUES('offsets',?)", (json.dumps(offs),))
    return sl


def store_page(c, url, name, cat, text, now):
    hashes, exes, fams = mine(text)
    for h, htype, ctx, fam, context in hashes:
        c.execute(
            "INSERT INTO hashes VALUES(?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(hash,source_url) DO UPDATE SET last_seen=?, "
            "malware_ctx=max(malware_ctx,?), family=COALESCE(family,?)",
            (h, htype, url, name, cat, int(ctx), fam, context, now, now, now, int(ctx), fam))
    for ref in exes:
        c.execute("INSERT INTO exes VALUES(?,?,?,?,?,?) "
                  "ON CONFLICT(ref,source_url) DO UPDATE SET last_seen=?",
                  (ref, url, name, cat, now, now, now))
    for f in fams:
        c.execute("INSERT INTO families VALUES(?,?,?,?) "
                  "ON CONFLICT(name) DO UPDATE SET hits=hits+1, last_seen=?",
                  (f, 1, now, now, now))
    for tm in BOT_TOKEN.finditer(text):
        tok = tm.group(1); ti = tm.start()
        w = text[max(0, ti - 80): ti + len(tok) + 80]
        wl = w.lower()
        if "bot" in wl or "telegram" in wl or "t.me" in wl or _mal_ctx(w):
            c.execute("INSERT INTO tokens VALUES(?,?,?,?,?,?,?) "
                      "ON CONFLICT(token,source_url) DO UPDATE SET last_seen=?",
                      (tok, url, name, cat, w.strip()[:200], now, now, now))
    return len(hashes), len(exes), fams


def record(c, url, now, status):
    if status == "ok":
        c.execute("INSERT INTO crawled VALUES(?,?,?,0) ON CONFLICT(url) DO UPDATE SET last=?, status='ok', fails=0",
                  (url, now, "ok", now))
    else:
        c.execute("INSERT INTO crawled VALUES(?,?,?,1) ON CONFLICT(url) DO UPDATE SET last=?, status=?, fails=fails+1",
                  (url, now, status, now, status))


def main():
    c = init_db()
    targets = directory_targets()
    run_no = int((c.execute("SELECT v FROM crawl_state WHERE k='run'").fetchone() or [0])[0] or 0) + 1
    c.execute("INSERT OR REPLACE INTO crawl_state VALUES('run',?)", (str(run_no),))
    sl = pick_slice(c, targets)
    if run_no % 3 == 0:                         # every 3rd run add search-engine discovery
        sl = search_targets() + sl
    now = time.time()

    def fetch(t):
        cat, name, url, is_search = t
        text, err = read_only_get(to_fetchable(url))
        return t, text, err

    pages = hh = ee = 0
    kids = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        for (cat, name, url, is_search), text, err in (f.result() for f in
                as_completed([ex.submit(fetch, t) for t in sl])):
            record(c, url, now, err or "ok")
            if not text:
                continue
            pages += 1
            a, b, _ = store_page(c, url, name, cat, text, now)
            hh += a; ee += b
            for ku in child_links(text, to_fetchable(url), is_search):
                if ku not in {k[0] for k in kids}:
                    kids.append((ku, name, cat))
    # phase 2: bounded follow of thread/listing/result pages (feature 1)
    kids = kids[:CHILD_BUDGET]

    def fetch_k(k):
        text, err = read_only_get(k[0])
        return k, text, err

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        for (ku, name, cat), text, err in (f.result() for f in
                as_completed([ex.submit(fetch_k, k) for k in kids])):
            record(c, ku, now, err or "ok")
            if not text:
                continue
            pages += 1
            a, b, _ = store_page(c, ku, name or "(followed)", cat, text, now)
            hh += a; ee += b
    sweep(c, now)
    c.commit()
    export(c, len(targets), pages)
    print("run %d: pages=%d (sources+%d children) hash_hits=%d exe_hits=%d"
          % (run_no, pages, len(kids), hh, ee))


def sweep(c, now):
    """Retention: drop findings and dead-site rows not seen in RETENTION_DAYS."""
    cut = now - RETENTION_DAYS * 86400
    c.execute("DELETE FROM hashes   WHERE last_seen < ?", (cut,))
    c.execute("DELETE FROM exes     WHERE last_seen < ?", (cut,))
    c.execute("DELETE FROM families WHERE last_seen < ?", (cut,))
    c.execute("DELETE FROM tokens   WHERE last_seen < ?", (cut,))
    c.execute("DELETE FROM crawled  WHERE last < ? AND status != 'ok'", (cut,))


def iso(ts):
    try:
        return datetime.datetime.fromtimestamp(float(ts), datetime.timezone.utc).strftime("%Y-%m-%d %H:%M")
    except Exception:
        return ""


def export(c, n_sources, pages):
    now = time.time()
    newcut = now - NEW_WINDOW_H * 3600
    hrows = []
    for r in c.execute(
            "SELECT hash,htype,max(malware_ctx),max(family),"
            "group_concat(DISTINCT source_name),group_concat(DISTINCT source_url),"
            "max(context),min(first_seen),max(last_seen),count(DISTINCT source_url) "
            "FROM hashes GROUP BY hash"):
        new = bool(r[7] and r[7] >= newcut)
        # confidence: malware context + known family + how many sites + recency
        sc = (3 if r[2] else 0) + (3 if r[3] else 0) + min(r[9], 4) + (2 if new else 0)
        if r[8] and r[8] >= now - 7 * 86400:
            sc += 1
        tier = "high" if sc >= 6 else ("med" if sc >= 3 else "low")
        hrows.append({"hash": r[0], "type": r[1], "malware_context": bool(r[2]),
                      "family": r[3], "score": sc, "tier": tier,
                      "sources": [s for s in (r[4] or "").split(",") if s][:4],
                      "source_links": [u for u in (r[5] or "").split(",") if u][:4],
                      "context": r[6] or "", "new": new,
                      "first": iso(r[7]), "last": iso(r[8]), "site_count": r[9]})
    hrows.sort(key=lambda h: (h["score"], h["new"], h["last"]), reverse=True)
    hrows = hrows[:800]
    erows = []
    for r in c.execute(
            "SELECT ref,group_concat(DISTINCT source_url),group_concat(DISTINCT source_name),"
            "min(first_seen),max(last_seen),count(DISTINCT source_url) FROM exes GROUP BY ref "
            "ORDER BY (min(first_seen)>=%f) DESC, max(last_seen) DESC LIMIT 400" % newcut):
        erows.append({"ref": r[0], "links": [u for u in (r[1] or "").split(",") if u][:4],
                      "sources": [s for s in (r[2] or "").split(",") if s][:3],
                      "new": bool(r[3] and r[3] >= newcut),
                      "last": iso(r[4]), "site_count": r[5]})
    fams = [{"name": r[0], "hits": r[1], "last": iso(r[2]), "new": bool(r[3] and r[3] >= newcut)}
            for r in c.execute("SELECT name,hits,last_seen,first_seen FROM families "
                               "ORDER BY (first_seen>=%f) DESC, last_seen DESC LIMIT 40" % newcut)]
    sites_ok = c.execute("SELECT count(*) FROM crawled WHERE status='ok'").fetchone()[0]
    trows = []
    for r in c.execute("SELECT token,group_concat(DISTINCT source_url),group_concat(DISTINCT source_name),"
                       "min(first_seen),max(last_seen),count(DISTINCT source_url) FROM tokens GROUP BY token "
                       "ORDER BY max(last_seen) DESC LIMIT 200"):
        trows.append({"token": r[0], "links": [u for u in (r[1] or "").split(",") if u][:3],
                      "sources": [s for s in (r[2] or "").split(",") if s][:3],
                      "new": bool(r[3] and r[3] >= newcut), "last": iso(r[4]), "site_count": r[5]})
    out = {"generated": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
           "sources_total": n_sources, "sites_with_data": sites_ok,
           "hash_count": len(hrows), "new_hashes": sum(1 for h in hrows if h["new"]),
           "context_hits": sum(1 for h in hrows if h["malware_context"]),
           "exe_count": len(erows), "new_exes": sum(1 for e in erows if e["new"]),
           "families": fams, "hashes": hrows, "executables": erows, "token_count": len(trows), "tokens": trows}
    json.dump(out, open(OUT, "w"), indent=2)


if __name__ == "__main__":
    main()
