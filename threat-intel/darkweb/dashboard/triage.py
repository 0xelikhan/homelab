#!/usr/bin/env python3
"""
triage.py  -  download + statically triage crawler-flagged executables for the RE team.

Pipeline (cheapest-first so the slow tool runs on a fraction):
  fetch(byte-capped) -> sha256 dedup -> `file` magic -> pefile anomaly -> DIE packer/
  toolchain -> YARA family (attribution) -> capa (LAZY: only for a PE that none of the
  fast checks already decided).  KEEP if any strong malicious indicator fires; otherwise
  DELETE on the spot.  No scoring is surfaced; the decision is binary.

Throughput: the keep/delete decision uses only sub-second tools (file/pefile/DIE/YARA);
capa (the bottleneck, bounded by a timeout) runs only on the ambiguous-benign PE middle.
SHA-256 dedup collapses re-posted floods.  Per-run + disk-budget caps bound CPU and disk.

Self-cleaning: false positives are deleted immediately; kept samples live in ~/quarantine
named by sha256; prune() enforces retention + a total-size budget (oldest-first).

SAFETY: samples are written and read as data only; nothing here ever executes them.
"""
import os, re, json, time, sqlite3, hashlib, subprocess, shutil, sys, urllib.request, urllib.error, socket

HERE   = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import fetchers                       # resolve() + unpack() live next to this file
TG_INTAKE = os.path.expanduser("~/tg-intake")   # files the Telegram collector drops here
ARCHIVE_DESC = re.compile(r"7-zip|rar archive|zip archive|gzip|tar archive|cabinet|"
                          r"ace archive|arj|xz compressed|bzip2", re.I)
DB     = os.path.join(HERE, "malware-findings.db")
QDIR   = os.path.expanduser("~/quarantine")
UA     = "cti-dashboard"

MAX_FILE_MB      = 50
BUDGET_MB        = 2048
MAX_PULL_PER_RUN = 12
RETENTION_DAYS   = 14
FETCH_TIMEOUT    = 60
CAPA_TIMEOUT     = 120
CAPA_BIN   = os.path.expanduser("~/.local/bin/capa")
CAPA_RULES = os.path.expanduser("~/capa-rules")
CAPA_SIGS  = os.path.expanduser("~/capa-sigs")
YARC       = os.path.expanduser("~/signature-base.yarc")
YARA_EXT   = {"filename": "", "filepath": "", "extension": "", "filetype": "", "owner": "", "md5": ""}
ENTROPY_PACKED = 7.2          # max PE section entropy above this = likely packed
MIN_IMPORTS    = 3            # <= this many imported funcs = APIs resolved at runtime

# capa rule namespaces that indicate malicious behaviour (vs generic "contain loop")
CAPA_MAL_NS = ("anti-analysis", "/inject", "injection", "communication/c2", "communication/http",
               "credential", "/password", "impact/", "persistence/", "encrypt", "load-code",
               "shellcode", "keylog", "host-interaction/process/create", "data-manipulation/encode")

# --- lazy singletons ---
_yrules = None
def yara_rules():
    global _yrules
    if _yrules is None:
        try:
            import yara; _yrules = yara.load(YARC)
        except Exception:
            _yrules = False
    return _yrules


def categorize(desc):
    d = desc.lower()
    if "pe32" in d or "ms-dos executable" in d or ".net assembly" in d or "mono/.net" in d:
        return "pe"
    if "elf " in d or d.startswith("elf"):
        return "elf"
    if "mach-o" in d:
        return "macho"
    if ("script" in d or "powershell" in d or "batch file" in d or "python script" in d
            or "javascript" in d or "vbscript" in d):
        return "script"
    if "zip archive" in d:
        return "zip"
    return "data"

KEEP_EXE = {"pe", "elf", "macho", "script"}


def init_db(c):
    c.executescript("""
    CREATE TABLE IF NOT EXISTS triage(
        sha256 TEXT PRIMARY KEY, url TEXT, source_name TEXT, size INTEGER,
        filetype TEXT, category TEXT, kept INTEGER, known INTEGER, family TEXT,
        reasons TEXT, caps TEXT, imphash TEXT, max_entropy REAL, packed INTEGER, ts REAL);
    CREATE TABLE IF NOT EXISTS triage_seen(url TEXT PRIMARY KEY, ts REAL);
    CREATE TABLE IF NOT EXISTS triage_try(url TEXT PRIMARY KEY, n INTEGER, ts REAL);
    """)
    c.commit()


def quarantine_mb():
    t = 0
    for f in os.listdir(QDIR):
        try: t += os.path.getsize(os.path.join(QDIR, f))
        except OSError: pass
    return t / (1024 * 1024)


def fetch_capped(url, dest):
    cap = MAX_FILE_MB * 1024 * 1024
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA}, method="GET")
        with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT) as r:
            clen = r.headers.get("Content-Length")
            if clen and int(clen) > cap:
                return False, int(clen), "too-big"
            got = 0
            with open(dest, "wb") as out:
                while True:
                    chunk = r.read(65536)
                    if not chunk: break
                    got += len(chunk)
                    if got > cap:
                        out.close(); os.remove(dest); return False, got, "exceeded-cap"
                    out.write(chunk)
            return True, got, None
    except Exception as e:
        return False, 0, str(getattr(e, "reason", e))[:50]


def file_type(path):
    try:
        return subprocess.run(["file", "-b", path], capture_output=True, text=True, timeout=20).stdout.strip()
    except Exception:
        return "unknown"


def pe_anomaly(path):
    """(imphash, max_entropy, packed, n_imports, has_tls, anomalous)."""
    try:
        import pefile
        pe = pefile.PE(path, fast_load=True)
        pe.parse_data_directories()
        ent = [s.get_entropy() for s in pe.sections]
        mx = round(max(ent), 2) if ent else 0.0
        n_imp = sum(len(d.imports) for d in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or [])
        has_tls = hasattr(pe, "DIRECTORY_ENTRY_TLS") and pe.DIRECTORY_ENTRY_TLS is not None
        try: imp = pe.get_imphash()
        except Exception: imp = ""
        anom = bool(mx >= ENTROPY_PACKED or n_imp <= MIN_IMPORTS or has_tls)
        return imp, mx, bool(mx >= ENTROPY_PACKED), n_imp, has_tls, anom
    except Exception:
        return "", 0.0, False, 0, False, False


def die_scan(path):
    """(packer_or_protector, exotic_lang, labels[])."""
    try:
        import die
        flags = die.ScanFlags.RESULT_AS_JSON | die.ScanFlags.DEEP_SCAN | die.ScanFlags.HEURISTIC_SCAN
        d = json.loads(die.scan_file(path, flags, ""))
    except Exception:
        return False, False, []
    pk = exo = False; labels = []
    EXOTIC = ("nim", "go ", "golang", "rust", "autoit", "pyinstaller", "nuitka", "electron", "dub")
    for det in d.get("detects", []):
        for v in det.get("values", []):
            typ = (v.get("type") or "").lower(); nm = (v.get("name") or "")
            labels.append("%s:%s" % (typ, nm))
            if typ in ("packer", "protector"):
                pk = True
            if typ in ("compiler", "linker") and any(x in nm.lower() for x in EXOTIC):
                exo = True
    return pk, exo, labels[:8]


def yara_families(path):
    r = yara_rules()
    if not r:
        return []
    try:
        m = r.match(path, externals=YARA_EXT, timeout=20)
    except Exception:
        return []
    fams = []
    for x in m:
        nm = x.rule
        if nm.lower().startswith(("susp_", "anomaly", "generic")):   # suspicion, not attribution
            continue
        fams.append(nm)
    return fams[:6]


def capa_malicious(path):
    """Lazy, bounded. (malicious_bool, capability_names[])."""
    if not os.path.exists(CAPA_BIN):
        return False, []
    cmd = [CAPA_BIN, "-r", CAPA_RULES, "-s", CAPA_SIGS, "-j", path]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=CAPA_TIMEOUT)
        d = json.loads(p.stdout)
    except Exception:
        return False, []
    caps, mal = [], False
    for name, rule in (d.get("rules") or {}).items():
        meta = rule.get("meta", {}) if isinstance(rule, dict) else {}
        caps.append(meta.get("name", name))
        ns = (meta.get("namespace") or "").lower()
        if any(k in ns for k in CAPA_MAL_NS):
            mal = True
    return mal, caps[:30]


def decide(path, cat):
    """Return (keep_bool, known_bool, family[], reasons[], caps[], imphash, max_entropy, packed)."""
    reasons, family, caps = [], [], []
    imp, ent, packed = "", 0.0, False
    family = yara_families(path)                       # fast: attribution
    known = bool(family)
    if known:
        reasons.append("yara:" + family[0])
    if cat == "pe":
        imp, ent, packed, nimp, tls, anom = pe_anomaly(path)
        if anom:
            reasons.append("pe:ent%.1f/imp%d%s" % (ent, nimp, "/tls" if tls else ""))
    else:
        anom = False
    pk, exo, labels = die_scan(path)                  # fast: packer / toolchain
    if pk:  reasons.append("die:packed")
    if exo: reasons.append("die:exotic")
    keep = bool(known or anom or pk or exo)
    if cat == "pe" and not keep:                      # LAZY capa: only the ambiguous middle
        mal, caps = capa_malicious(path)
        if mal:
            keep = True; reasons.append("capa:malicious")
    return keep, known, family, reasons, caps, imp, ent, packed


def prune(c):
    now = time.time()
    files = []
    for f in os.listdir(QDIR):
        p = os.path.join(QDIR, f)
        try: files.append((os.path.getmtime(p), os.path.getsize(p), p))
        except OSError: pass
    for mt, _s, p in files:
        if mt < now - RETENTION_DAYS * 86400:
            try: os.remove(p)
            except OSError: pass
    files = sorted((x for x in files if os.path.exists(x[2])), key=lambda x: x[0])
    used = sum(x[1] for x in files); i = 0
    while used > BUDGET_MB * 1024 * 1024 and i < len(files):
        try: os.remove(files[i][2]); used -= files[i][1]
        except OSError: pass
        i += 1


def candidates(c):
    """Flagged download links not yet attempted, with any password hint. Reads the
    crawler's `candidates` table if present, else falls back to exe URLs."""
    seen = {r[0] for r in c.execute("SELECT url FROM triage_seen")}
    out = []
    try:
        rows = c.execute("SELECT url, source_name, password FROM candidates "
                         "ORDER BY ts DESC LIMIT 300").fetchall()
        for u, s, pw in rows:
            if u not in seen and not re.search(r"/$", u):
                out.append((u, s or "", [p for p in (pw or "").split("\x1f") if p]))
    except sqlite3.OperationalError:
        for u, s in c.execute("SELECT DISTINCT ref, source_name FROM exes WHERE ref LIKE 'http%' "
                              "ORDER BY last_seen DESC LIMIT 200"):
            if u not in seen and not re.search(r"/$", u):
                out.append((u, s or "", []))
    return out


def store(c, sha, url, src, size, desc, cat, keep, known, fam, reasons, caps, imp, ent, packed):
    c.execute("INSERT OR REPLACE INTO triage VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
              (sha, url, src, size, desc[:120], cat, int(keep), int(known), json.dumps(fam),
               ";".join(reasons) if isinstance(reasons, list) else reasons,
               json.dumps(caps), imp, ent, int(packed), time.time()))


def triage_one(c, path, url, src, passwords, depth=0):
    """Dedup -> file-type -> archive(unpack+recurse) | executable(decide). Returns kept count."""
    sha = hashlib.sha256(open(path, "rb").read()).hexdigest()
    if c.execute("SELECT 1 FROM triage WHERE sha256=?", (sha,)).fetchone():
        os.remove(path); return 0                       # dedup
    size = os.path.getsize(path)
    desc = file_type(path)
    if depth < 2 and ARCHIVE_DESC.search(desc):         # archive -> unpack, triage contents
        exdir = path + ".x"
        inner = fetchers.unpack(path, exdir, passwords)
        try: os.remove(path)
        except OSError: pass
        kept = sum(triage_one(c, f, url, src, passwords, depth + 1)
                   for f in inner if os.path.isfile(f))
        shutil.rmtree(exdir, ignore_errors=True)        # drop leftover extracted junk
        return kept
    cat = categorize(desc)
    if cat not in KEEP_EXE:                              # not an executable -> delete now
        os.remove(path); store(c, sha, url, src, size, desc, cat, 0, 0, [], "not-exe", [], "", 0.0, 0)
        return 0
    keep, known, fam, reasons, caps, imp, ent, packed = decide(path, cat)
    if not keep:
        os.remove(path)                                 # false positive -> delete
        store(c, sha, url, src, size, desc, cat, 0, 0, [], "benign", caps, imp, ent, packed)
        return 0
    ext = os.path.splitext(path)[1][:5] or ext_for(cat, url)
    dest = os.path.join(QDIR, sha + ext)
    os.replace(path, dest)
    store(c, sha, url, src, size, desc, cat, 1, known, fam, reasons, caps, imp, ent, packed)
    print("KEEP %s known=%s %s" % (sha[:12], known, reasons))
    return 1


def intake_local(c):
    """Triage files dropped into ~/tg-intake by the Telegram collector (already fetched,
    so no resolve/fetch - just the same dedup -> file-type -> unpack -> decide path)."""
    if not os.path.isdir(TG_INTAKE):
        return 0
    kept = 0
    for f in sorted(os.listdir(TG_INTAKE)):
        p = os.path.join(TG_INTAKE, f)
        if f.startswith(".") or not os.path.isfile(p):
            continue
        if quarantine_mb() >= BUDGET_MB:
            break
        kept += triage_one(c, p, "telegram://" + f, "telegram", [])
        c.commit()
    return kept


MAX_TRIES = 4        # transient fetch failures to tolerate before giving up on a candidate

def _seen(c, url):
    c.execute("INSERT OR REPLACE INTO triage_seen VALUES(?,?)", (url, time.time()))

def _definitive(err):
    """A fetch outcome that will not change on retry -> stop trying this URL."""
    if err in ("too-big", "exceeded-cap"):
        return True
    e = (err or "").lower()
    return any(k in e for k in ("not found", "forbidden", "gone", "bad request",
                                "unauthorized", "404", "403", "410", "400", "401"))

def main():
    os.makedirs(QDIR, exist_ok=True)
    c = sqlite3.connect(DB); init_db(c); prune(c)
    pulled = kept = 0
    kept += intake_local(c)             # Telegram-collected samples first (already downloaded)
    for url, src, pw in candidates(c):
        if pulled >= MAX_PULL_PER_RUN or quarantine_mb() >= BUDGET_MB:
            break
        durls = fetchers.resolve(url)
        if not durls:
            _seen(c, url); c.commit(); continue         # host we can't resolve (yet) -> skip
        outcome = None                                  # 'ok' | 'definitive' | 'transient'
        for durl in durls:
            if pulled >= MAX_PULL_PER_RUN:
                break
            tmp = os.path.join(QDIR, ".incoming")
            ok, size, err = fetch_capped(durl, tmp)
            if ok:
                pulled += 1
                kept += triage_one(c, tmp, url, src, pw)
                outcome = "ok"; c.commit(); continue
            print("skip %s (%s)" % (durl[:50], err))
            if outcome != "ok":
                outcome = "definitive" if _definitive(err) else "transient"
        # Only burn the candidate on a settled outcome; retry transient (flaky-Tor) failures.
        if outcome in ("ok", "definitive"):
            _seen(c, url)
        elif outcome == "transient":
            n = (c.execute("SELECT n FROM triage_try WHERE url=?", (url,)).fetchone() or [0])[0] + 1
            c.execute("INSERT OR REPLACE INTO triage_try VALUES(?,?,?)", (url, n, time.time()))
            if n >= MAX_TRIES:
                _seen(c, url)                           # give up after repeated transient failures
        c.commit()
    prune(c); c.commit()
    print("triage: pulled=%d kept=%d quarantine=%.0fMB" % (pulled, kept, quarantine_mb()))


def ext_for(cat, url):
    m = re.search(r"\.([a-z0-9]{1,4})(?:\?|#|$)", url.lower())
    if m: return "." + m.group(1)
    return {"pe": ".bin", "elf": ".elf", "macho": ".macho", "script": ".txt"}.get(cat, ".bin")


if __name__ == "__main__":
    main()
