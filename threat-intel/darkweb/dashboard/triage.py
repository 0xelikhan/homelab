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
import os, re, json, time, sqlite3, hashlib, subprocess, shutil, sys
import urllib.request, urllib.error, urllib.parse, socket

HERE   = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import fetchers                       # resolve() + unpack() live next to this file
TG_INTAKE = os.path.expanduser("~/tg-intake")   # files the Telegram collector drops here
ARCHIVE_DESC = re.compile(r"7-zip|rar archive|zip archive|gzip|tar archive|cabinet|"
                          r"ace archive|arj|xz compressed|bzip2", re.I)
# PE self-extractors / installers: 7z can crack most open, exposing the real payload
INSTALLER_DESC = re.compile(r"nullsoft|self-extract|inno setup|installshield|wise install|"
                            r"setup factory|advanced installer|7-?zip sfx|rar sfx|sfx:|\bsfx\b", re.I)
YARA_MAX_BYTES = 25 * 1024 * 1024   # YARA-scan dropped non-exe up to this (skip giant combolists)
DB     = os.path.join(HERE, "malware-findings.db")
QDIR   = os.path.expanduser("~/quarantine")
UA     = "cti-dashboard"

MAX_FILE_MB      = 50
BUDGET_MB        = 2048
MAX_PULL_PER_RUN = 12
RETENTION_HOURS  = 36         # dark-web finds: ~36h so REs have a weekend's worth
KNOWN_RETENTION_HOURS = 8     # known-feed baseline backstop (the count cap below does the work)
KNOWN_MAX        = 10         # keep at most this many known-feed samples (it is a small reference)
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
    for dp, _, fs in os.walk(QDIR):
        for f in fs:
            try: t += os.path.getsize(os.path.join(dp, f))
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
    if cat in ("pe", "elf"):                           # capa on EVERY analyzable binary (not lazy)
        mal, caps = capa_malicious(path)               # -> caps always recorded, for real fidelity
        if mal:
            keep = True
            if "capa:malicious" not in reasons:
                reasons.append("capa:malicious")
    return keep, known, family, reasons, caps, imp, ent, packed


def _rm(p):
    if os.path.isdir(p):
        shutil.rmtree(p, ignore_errors=True)
    else:
        try: os.remove(p)
        except OSError: pass


def prune(c):
    now = time.time()
    try:                                                 # known-feed samples age out faster
        known = {r[0] for r in c.execute(
            "SELECT sha256 FROM triage WHERE source_name IN ('MalwareBazaar','MalShare')")}
    except Exception:
        known = set()
    items = []                                           # each sample lives in its own folder now
    for name in os.listdir(QDIR):
        if name.startswith("."):
            continue
        p = os.path.join(QDIR, name)
        try:
            if os.path.isdir(p):
                sz = sum(os.path.getsize(os.path.join(dp, f))
                         for dp, _, fs in os.walk(p) for f in fs)
            else:
                sz = os.path.getsize(p)
            items.append((os.path.getmtime(p), sz, p))
        except OSError:
            pass
    def drop(p):                                          # remove files AND the board (DB) row
        _rm(p)
        try:
            c.execute("DELETE FROM triage WHERE sha256=?", (os.path.basename(p.rstrip("/")),))
        except Exception:
            pass
    for mt, _s, p in items:
        hrs = KNOWN_RETENTION_HOURS if os.path.basename(p.rstrip("/")) in known else RETENTION_HOURS
        if mt < now - hrs * 3600:
            drop(p)
    # hard count cap on known-feed samples: keep only the most recent KNOWN_MAX
    kn = sorted((it for it in items if os.path.exists(it[2])
                 and os.path.basename(it[2].rstrip("/")) in known),
                key=lambda x: x[0], reverse=True)
    for _mt, _s, p in kn[KNOWN_MAX:]:
        drop(p)
    items = sorted((x for x in items if os.path.exists(x[2])), key=lambda x: x[0])
    used = sum(x[1] for x in items); i = 0
    while used > BUDGET_MB * 1024 * 1024 and i < len(items):
        drop(items[i][2]); used -= items[i][1]; i += 1
    c.commit()


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


# crypto constant signatures (distinctive, low false positive): name -> magic bytes
_CRYPTO_SIGS = [
    ("AES s-box",        bytes.fromhex("637c777bf26b6fc53001672bfed7ab76")),
    ("AES inverse s-box",bytes.fromhex("52096ad53036a538bf40a39e81f3d7fb")),
    ("SHA-256 constants", bytes.fromhex("428a2f98713744918b")),
    ("SHA-512 constants", bytes.fromhex("428a2f98d728ae22")),
    ("MD5 init",          bytes.fromhex("0123456789abcdeffedcba9876543210")),
    ("CRC32 table",       bytes.fromhex("00000000963007772c610eeeba51099919")),
    ("base64 alphabet",   b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"),
    ("base64 url alphabet", b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"),
    ("ChaCha/Salsa20 sigma", b"expand 32-byte k"),
    ("ChaCha/Salsa20 tau",   b"expand 16-byte k"),
]


def _crypto_constants(path):
    try:
        with open(path, "rb") as f:
            b = f.read(40 * 1024 * 1024)
    except Exception:
        return []
    out = []
    for name, sig in _CRYPTO_SIGS:
        i = b.find(sig)
        if i >= 0:
            out.append("%s at 0x%x" % (name, i))
    return out


def _pe_tls(path):
    try:
        import pefile
        pe = pefile.PE(path, fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_TLS"]])
        tls = getattr(pe, "DIRECTORY_ENTRY_TLS", None)
        return bool(tls and tls.struct and tls.struct.AddressOfCallBacks)
    except Exception:
        return False


def _pe_cert(path):
    """Authenticode signer: (subject_cn, issuer_cn, serial_hex) or None."""
    try:
        import pefile
        pe = pefile.PE(path, fast_load=True)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]])
        sec = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]]
        if not sec.VirtualAddress or not sec.Size:
            return None
        der = pe.__data__[sec.VirtualAddress + 8: sec.VirtualAddress + sec.Size]  # skip WIN_CERT hdr
        from cryptography.hazmat.primitives.serialization import pkcs7
        certs = pkcs7.load_der_pkcs7_certificates(der)
        if not certs:
            return None
        c0 = certs[0]
        def _cn(name):
            from cryptography.x509.oid import NameOID
            a = name.get_attributes_for_oid(NameOID.COMMON_NAME)
            return a[0].value if a else ""
        return (_cn(c0.subject), _cn(c0.issuer), format(c0.serial_number, "X"))
    except Exception:
        return None


def _cscb_list():
    """MalwareBazaar Code Signing Certificate Blocklist as {serial_upper: reason}. Cached on
    disk and refreshed at most once per 24h, so findings writes never hammer the API."""
    key = _keys().get("abuse_ch")
    if not key:
        return None
    try:
        if os.path.exists(CSCB_CACHE) and time.time() - os.path.getmtime(CSCB_CACHE) < 86400:
            return json.load(open(CSCB_CACHE, encoding="utf-8"))
    except Exception:
        pass
    try:
        d = _mb_post(key, {"query": "get_cscb"}, 60)
        rows = d.get("data") if isinstance(d, dict) else d
        serials = {(r.get("serial_number") or "").upper(): (r.get("cscb_reason") or "blocklisted")
                   for r in (rows or []) if isinstance(r, dict) and r.get("serial_number")}
        json.dump(serials, open(CSCB_CACHE, "w"))
        return serials
    except Exception:
        return None


def _cscb_status(serial_hex):
    """Is this code-signing serial on the MalwareBazaar blocklist? Uses the cached list."""
    if not serial_hex:
        return ""
    lst = _cscb_list()
    if not lst:
        return ""
    return "LISTED (%s)" % lst[serial_hex.upper()] if serial_hex.upper() in lst else "not listed"


_IOC_URL  = re.compile(rb"https?://[A-Za-z0-9.\-_~:/?#\[\]@!$&'()*+,;=%]{4,120}")
_IOC_IP   = re.compile(rb"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_IOC_REG  = re.compile(rb"(?:HKLM|HKCU|HKEY_[A-Z_]+|SOFTWARE\\|SYSTEM\\CurrentControlSet)[\\A-Za-z0-9_.\- ]{3,120}")
_IOC_WPATH= re.compile(rb"[A-Za-z]:\\[\\A-Za-z0-9_.\- ]{3,120}|%[A-Za-z]+%\\[\\A-Za-z0-9_.\- ]{2,120}")
_IOC_DOM  = re.compile(rb"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:com|net|org|ru|cn|io|info|biz|top|xyz|online|site|shop|su|cc|me|tk|pw|club|pro|app|dev|gg)\b")
_IOC_SKIP = re.compile(rb"(?:microsoft|windows|msvcrt|kernel32|schema|w3\.org|example\.|sysinternals|verisign|digicert|sectigo|globalsign|comodo|mozilla|gnu\.org)", re.I)


def _extract_iocs(path):
    """Evidence-first IOCs lifted from the sample's own strings. Returns {category: [values]}."""
    try:
        raw = subprocess.run(["strings", "-a", "-n", "6", path], stdin=subprocess.DEVNULL,
                             capture_output=True, timeout=60).stdout[:4 * 1024 * 1024]
    except Exception:
        return {}
    def grab(rx, n=40):
        seen, out = set(), []
        for m in rx.finditer(raw):
            v = m.group(0)
            if _IOC_SKIP.search(v):
                continue
            s = v.decode("utf-8", "replace")
            if s not in seen:
                seen.add(s); out.append(s)
            if len(out) >= n:
                break
        return out
    def _ok_ip(ip):
        o = ip.split(".")
        if ip.startswith(("0.", "127.", "255.", "10.", "192.168.", "169.254.")):
            return False
        if o[1] == "0" and o[2] == "0":                  # version-number artifacts e.g. 1.0.0.0
            return False
        return True
    urls = grab(_IOC_URL)
    ips = [ip for ip in grab(_IOC_IP, 60) if _ok_ip(ip)]
    return {"urls": urls, "ips": ips, "domains": grab(_IOC_DOM),
            "registry": grab(_IOC_REG, 25), "paths": grab(_IOC_WPATH, 25)}


_YARA_NOISE = re.compile(
    rb"kernel32|user32|ntdll|advapi32|gdi32|ole32|shell32|ws2_32|msvcr|GetProc|LoadLibrary|"
    rb"VirtualAlloc|microsoft|windows|program files|system32|\.dll|\.exe|mscoree|assembly|"
    rb"this program|GetModuleHandle|CreateFile|RegOpenKey|http://schemas|w3\.org|xmlns", re.I)


def _yara_strings(path, n=8):
    try:
        raw = subprocess.run(["strings", "-a", "-n", "8", path], stdin=subprocess.DEVNULL,
                             capture_output=True, timeout=60).stdout[:2 * 1024 * 1024]
    except Exception:
        return []
    seen, cand = set(), []
    for line in raw.split(b"\n"):
        s = line.strip()
        if not (8 <= len(s) <= 60) or not re.fullmatch(rb"[\x20-\x7e]+", s):
            continue
        if _YARA_NOISE.search(s) or s in seen:
            continue
        seen.add(s); cand.append(s)
        if len(cand) >= 60:
            break
    cand.sort(key=lambda s: (-len(s), -sum(1 for ch in s if not chr(ch).isalpha())))
    return cand[:n]


def write_yara_rule(folder, sample, sha, src, imp):
    """Draft a starting YARA rule (imphash + distinctive strings) next to the sample, as a
    head start for the RE / detection side. Explicitly marked auto-drafted."""
    strs = _yara_strings(sample)
    if not strs:
        return
    out = ["// Auto-drafted starting signature. Heuristic (strings + imphash). Verify and tighten."]
    if imp:
        out.append('import "pe"')
    out.append("")
    out.append("rule novel_%s" % sha[:12])
    out.append("{")
    out.append("    meta:")
    out.append('        sha256 = "%s"' % sha)
    out.append('        source = "%s"' % (src or "unknown"))
    out.append('        generated = "%s"' % time.strftime("%Y-%m-%d", time.gmtime()))
    out.append('        note = "auto-drafted; confirm before deploying"')
    out.append("    strings:")
    for i, s in enumerate(strs):
        esc = s.decode("latin-1").replace("\\", "\\\\").replace('"', '\\"')
        out.append('        $s%d = "%s" ascii' % (i, esc))
    cond = ["uint16(0) == 0x5A4D"]
    if imp:
        cond.append('pe.imphash() == "%s"' % imp)
    cond.append("%d of ($s*)" % max(3, len(strs) // 2))
    out.append("    condition:")
    out.append("        " + " and ".join(cond))
    out.append("}")
    with open(os.path.join(folder, "rule.yar"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(out) + "\n")


def write_findings(folder, sample, sha, url, src, size, desc, cat, known, fam, reasons, caps, imp, ent, packed):
    """Plain-text, category-based record of why this sample is on the dashboard.
    No prose, no em/en dashes: just the facts and the flags that fired. `sample` is the
    on-disk sample path (inside `folder`), used for the static extractions below."""
    rs = reasons if isinstance(reasons, list) else [r for r in (reasons or "").split(";") if r]
    fams = fam if isinstance(fam, list) else []
    cps = caps if isinstance(caps, list) else []
    L = []
    L.append("SAMPLE %s" % sha)
    L.append("")
    L.append("[ FILE ]")
    L.append("  type:   %s" % (desc or "unknown"))
    L.append("  size:   %.2f MB (%d bytes)" % (size / 1048576.0, size))
    L.append("  source: %s" % (src or "unknown"))
    L.append("  origin: %s" % (url or "unknown"))
    L.append("  triaged: %s" % time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime()))
    L.append("")
    L.append("[ ATTRIBUTION ]")
    L.append("  status:  %s" % ("KNOWN" if known else "NEW (no known signature match)"))
    L.append("  family:  %s" % (", ".join(fams) if fams else "none"))
    L.append("  imphash: %s" % (imp or "none"))
    L.append("")
    L.append("[ WHY IT WAS FLAGGED ]")
    if packed or (ent and ent >= ENTROPY_PACKED):
        L.append("  packing:        high section entropy %.2f (packed or compressed)" % (ent or 0.0))
    pe = [r for r in rs if r.startswith("pe:")]
    if pe:
        L.append("  pe anomaly:     %s" % ", ".join(pe))
    die = [r.split(":", 1)[1] for r in rs if r.startswith("die:")]
    if die:
        L.append("  packer:         %s" % ", ".join(die))
    ya = [r.split(":", 1)[1] for r in rs if r.startswith("yara:")]
    if ya:
        L.append("  yara signature: %s" % ", ".join(ya))
    mb = [r.split(":", 1)[1] for r in rs if r.startswith("mb:")]
    if mb:
        L.append("  malwarebazaar:  %s" % ", ".join(mb))
    is_pe = cat == "pe" and os.path.exists(sample)
    if is_pe and _pe_tls(sample):
        L.append("  tls callback:   present (code runs before main; common anti-debug)")
    crypto = _crypto_constants(sample) if os.path.exists(sample) else []
    if crypto:
        L.append("  crypto constants:")
        for cc in crypto:
            L.append("    %s" % cc)
    if cps:
        L.append("  capa behaviors:")
        for cap in cps:
            L.append("    %s" % cap)
    if not (pe or die or ya or mb or cps or packed or crypto):
        L.append("  flagged on: %s" % (", ".join(rs) if rs else "triage heuristics"))
    if is_pe:
        cert = _pe_cert(sample)
        L.append("")
        L.append("[ CODE SIGNING ]")
        if cert:
            L.append("  subject: %s" % (cert[0] or "none"))
            L.append("  issuer:  %s" % (cert[1] or "none"))
            L.append("  serial:  %s" % (cert[2] or "none"))
            cscb = _cscb_status(cert[2])
            if cscb:
                L.append("  blocklist (MalwareBazaar CSCB): %s" % cscb)
        else:
            L.append("  not signed")
    iocs = _extract_iocs(sample) if os.path.exists(sample) else {}
    if any(iocs.values()):
        L.append("")
        L.append("[ INDICATORS ]  (strings present in the sample; verify before use)")
        for label, key in (("urls", "urls"), ("ip addresses", "ips"), ("domains", "domains"),
                           ("registry", "registry"), ("file paths", "paths")):
            vals = iocs.get(key) or []
            if vals:
                L.append("  %s:" % label)
                for v in vals:
                    L.append("    %s" % v)
    L.append("")
    L.append("[ RAW REASONS ]")
    L.append("  %s" % ";".join(rs))
    txt = "\n".join(L).replace("—", "-").replace("–", "-")
    with open(os.path.join(folder, "findings.txt"), "w", encoding="utf-8") as fh:
        fh.write(txt + "\n")


def _keep_file(c, path, sha, url, src, size, desc, cat, known, fam, reasons, caps, imp, ent, packed):
    """Park a verified sample in its own quarantine folder next to a findings.txt that
    explains, by category, why it is on the dashboard."""
    ext = os.path.splitext(path)[1][:5] or ext_for(cat, url)
    folder = os.path.join(QDIR, sha)
    os.makedirs(folder, exist_ok=True)
    dest = os.path.join(folder, sha + ext)
    shutil.move(path, dest)                              # move (handles cross-filesystem)
    write_findings(folder, dest, sha, url, src, size, desc, cat, known, fam, reasons, caps, imp, ent, packed)
    if not known and cat == "pe":                        # novel: draft a starting YARA rule
        write_yara_rule(folder, dest, sha, src, imp)
    store(c, sha, url, src, size, desc, cat, 1, known, fam, reasons, caps, imp, ent, packed)
    print("KEEP %s known=%s %s" % (sha[:12], known, reasons))


def triage_one(c, path, url, src, passwords, depth=0):
    """Dedup -> file-type -> (archive/installer: unpack+recurse) + (binary: decide) +
    (non-exe: YARA for known-bad maldoc/webshell/skimmer). Returns kept count."""
    sha = hashlib.sha256(open(path, "rb").read()).hexdigest()
    if c.execute("SELECT 1 FROM triage WHERE sha256=?", (sha,)).fetchone():
        os.remove(path); return 0                       # dedup
    size = os.path.getsize(path)
    desc = file_type(path)
    cat = categorize(desc)

    # Archives AND PE self-extractors/installers: crack open with 7z, triage the real payload.
    inner_kept = 0
    is_installer = INSTALLER_DESC.search(desc) and cat == "pe"
    if depth < 2 and (ARCHIVE_DESC.search(desc) or is_installer):
        exdir = path + ".x"
        inner = fetchers.unpack(path, exdir, passwords)
        nfiles = sum(1 for f in inner if os.path.isfile(f))
        inner_kept = sum(triage_one(c, f, url, src, passwords, depth + 1)
                         for f in inner if os.path.isfile(f))
        shutil.rmtree(exdir, ignore_errors=True)        # drop leftover extracted junk
        if cat not in KEEP_EXE:                          # pure archive: no stub binary to analyse
            try: os.remove(path)
            except OSError: pass
            if inner_kept == 0:                          # auditable drop + content-dedup
                reason = "archive:%d-inner/0-exe" % nfiles if nfiles else "archive:unextractable"
                store(c, sha, url, src, size, desc, "archive", 0, 0, [], reason, [], "", 0.0, 0)
            return inner_kept
        # installer IS a PE stub -> fall through and analyse the stub too (payload already done)

    # Non-executable: still worth a YARA pass for known-bad maldocs / webshells / skimmers.
    if cat not in KEEP_EXE:
        fam = yara_families(path) if size <= YARA_MAX_BYTES else []
        if fam:                                          # known-malicious document / script / data
            _keep_file(c, path, sha, url, src, size, desc, cat, 1, fam, ["yara:" + fam[0]], [], "", 0.0, 0)
            return 1 + inner_kept
        os.remove(path); store(c, sha, url, src, size, desc, cat, 0, 0, [], "not-exe", [], "", 0.0, 0)
        return inner_kept

    # Executable: full verdict (YARA attribution + PE anomaly + DIE packer + capa behaviour).
    keep, known, fam, reasons, caps, imp, ent, packed = decide(path, cat)
    if not keep:
        os.remove(path)                                 # false positive -> delete
        store(c, sha, url, src, size, desc, cat, 0, known, fam, reasons or ["benign"], caps, imp, ent, packed)
        return inner_kept
    if not known:                                       # authoritative known/new via MalwareBazaar
        info = mb_lookup(sha)                            # None=no key, {}=novel, {...}=known
        if info:
            known = 1
            if info.get("family"):
                fam = [info["family"]]
            reasons = list(reasons) + ["mb:" + (info.get("family") or "known")]
        elif info == {}:
            reasons = list(reasons) + ["mb:novel"]      # confirmed not in MalwareBazaar
    _keep_file(c, path, sha, url, src, size, desc, cat, known, fam, reasons, caps, imp, ent, packed)
    return 1 + inner_kept


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


# --------------------------------------------------------------- known-malware intel (key-gated)
KEYS_FILE    = os.path.expanduser("~/.cti-keys.json")   # {"abuse_ch":"...","malshare":"..."}
KNOWN_INTAKE = os.path.expanduser("~/known-intake")
CSCB_CACHE   = os.path.expanduser("~/.cti-cscb.json")   # cached code-sign blocklist (refreshed 24h)
FEED_TS      = os.path.expanduser("~/.cti-feed-ts")     # throttle marker for the known feed
FEED_PER_RUN = 3             # known samples/run (small; the board only keeps KNOWN_MAX anyway)
FEED_MIN_INTERVAL = 6 * 3600 # don't pull the known feed more than once per this many seconds
MB_API       = "https://mb-api.abuse.ch/api/v1/"
FEED_FAM_OFF = os.path.expanduser("~/.cti-feed-fam-off")   # rotation cursor over the families
# families the REs care about (stealers / loaders / RATs), rotated one per feed run so the
# baseline is relevant rather than MalwareBazaar's random recent additions
FEED_FAMILIES = ["RedLineStealer", "LummaStealer", "Vidar", "Stealc", "AsyncRAT", "RemcosRAT",
                 "SmokeLoader", "Amadey", "AgentTesla", "Formbook", "QuasarRAT", "NjRAT",
                 "Rhadamanthys", "DCRat", "GuLoader"]


def _next_family():
    try:
        off = int(open(FEED_FAM_OFF).read().strip())
    except Exception:
        off = 0
    fam = FEED_FAMILIES[off % len(FEED_FAMILIES)]
    try:
        open(FEED_FAM_OFF, "w").write(str((off + 1) % len(FEED_FAMILIES)))
    except Exception:
        pass
    return fam


def _keys():
    try:
        return json.load(open(KEYS_FILE, encoding="utf-8"))
    except Exception:
        return {}


MB_COOLDOWN = os.path.expanduser("~/.cti-mb-cooldown")   # set on a 403/429, pauses all MB calls
MB_COOLDOWN_SECS = 6 * 3600


def _mb_blocked():
    try:
        return os.path.exists(MB_COOLDOWN) and time.time() - os.path.getmtime(MB_COOLDOWN) < MB_COOLDOWN_SECS
    except Exception:
        return False


def _mb_post(key, fields, timeout=40, raw=False):
    if _mb_blocked():                                    # backing off after a rate-limit response
        raise RuntimeError("mb-cooldown")
    data = urllib.parse.urlencode(fields).encode()
    req = urllib.request.Request(MB_API, data=data,
                                 headers={"Auth-Key": key, "User-Agent": "cti-dashboard"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            b = r.read(80 * 1024 * 1024)
    except urllib.error.HTTPError as e:
        if e.code in (403, 429):                         # Fair Use limit: stop querying for a while
            try: open(MB_COOLDOWN, "w").write(str(time.time()))
            except Exception: pass
        raise
    return b if raw else json.loads(b)


def mb_lookup(sha):
    """MalwareBazaar get_info by hash: dict(family,first_seen,...) if KNOWN, {} if abuse.ch
    has never seen it (NOVEL), None if no key / unreachable. No sample is uploaded."""
    key = _keys().get("abuse_ch")
    if not key:
        return None
    try:
        d = _mb_post(key, {"query": "get_info", "hash": sha})
    except Exception:
        return None
    st = d.get("query_status")
    if st == "ok" and d.get("data"):
        row = d["data"][0]
        return {"family": row.get("signature") or "", "first_seen": row.get("first_seen") or "",
                "imphash": row.get("imphash") or "", "tags": row.get("tags") or []}
    if st == "hash_not_found":
        return {}                                       # confirmed not in MalwareBazaar
    return None


def feed_known(c):
    """Pull a bounded batch of recent KNOWN malware (MalwareBazaar + MalShare) into quarantine
    through the normal triage path, so the board carries a current known-malware baseline.
    Key-gated: with no ~/.cti-keys.json it is a clean no-op."""
    keys = _keys()
    if not keys:
        return 0
    try:                                                 # throttle: respect abuse.ch Fair Use
        if os.path.exists(FEED_TS) and time.time() - os.path.getmtime(FEED_TS) < FEED_MIN_INTERVAL:
            return 0
    except Exception:
        pass
    open(FEED_TS, "w").write(str(time.time()))
    os.makedirs(KNOWN_INTAKE, exist_ok=True)
    kept = 0
    mbk = keys.get("abuse_ch")
    if mbk:
        fam = _next_family()                             # one RE-relevant family per run, rotating
        try:
            rows = (_mb_post(mbk, {"query": "get_siginfo", "signature": fam,
                                   "limit": str(FEED_PER_RUN * 4)}, 60).get("data") or [])
        except Exception:
            rows = []
        pulled = 0
        for row in rows:
            if pulled >= FEED_PER_RUN or quarantine_mb() >= BUDGET_MB:
                break
            sha = row.get("sha256_hash") or ""
            if not sha or c.execute("SELECT 1 FROM triage_seen WHERE url=?", ("mb://" + sha,)).fetchone():
                continue
            _seen(c, "mb://" + sha)
            zp = os.path.join(KNOWN_INTAKE, sha + ".zip")
            try:
                b = _mb_post(mbk, {"query": "get_file", "sha256_hash": sha}, 90, raw=True)
            except Exception:
                continue
            if b[:2] != b"PK":                          # expected the password zip, got an error
                continue
            open(zp, "wb").write(b)
            kept += triage_one(c, zp, "malwarebazaar://" + sha, "MalwareBazaar", ["infected"])
            pulled += 1
            c.commit()
    msk = keys.get("malshare")
    if msk:
        try:
            lst = json.loads(urllib.request.urlopen(urllib.request.Request(
                "https://malshare.com/api.php?api_key=%s&action=getlist" % msk,
                headers={"User-Agent": "cti-dashboard"}), timeout=60).read())
        except Exception:
            lst = []
        for row in (lst or [])[:FEED_PER_RUN]:
            if quarantine_mb() >= BUDGET_MB:
                break
            sha = (row.get("sha256") if isinstance(row, dict) else "") or ""
            if not sha or c.execute("SELECT 1 FROM triage_seen WHERE url=?", ("ms://" + sha,)).fetchone():
                continue
            _seen(c, "ms://" + sha)
            fp = os.path.join(KNOWN_INTAKE, sha + ".bin")
            try:
                b = urllib.request.urlopen(urllib.request.Request(
                    "https://malshare.com/api.php?api_key=%s&action=getfile&hash=%s" % (msk, sha),
                    headers={"User-Agent": "cti-dashboard"}), timeout=90).read(80 * 1024 * 1024)
            except Exception:
                continue
            open(fp, "wb").write(b)
            kept += triage_one(c, fp, "malshare://" + sha, "MalShare", [])
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
        tmp = os.path.join(QDIR, ".incoming")
        ok, size, err = fetchers.download(url, tmp, pw)  # resolve + fetch + decrypt, all hosts
        if ok:
            pulled += 1
            kept += triage_one(c, tmp, url, src, pw)
            _seen(c, url); c.commit(); continue
        print("skip %s (%s)" % (url[:50], err))
        if err == "unresolved" or err == "no-link" or _definitive(err):
            _seen(c, url)                               # host we can't fetch, or dead link -> done
        else:                                            # transient (flaky Tor) -> retry a few times
            n = (c.execute("SELECT n FROM triage_try WHERE url=?", (url,)).fetchone() or [0])[0] + 1
            c.execute("INSERT OR REPLACE INTO triage_try VALUES(?,?,?)", (url, n, time.time()))
            if n >= MAX_TRIES:
                _seen(c, url)
        c.commit()
    kept += feed_known(c)               # known-malware baseline feeds (MalwareBazaar/MalShare)
    prune(c); c.commit()
    print("triage: pulled=%d kept=%d quarantine=%.0fMB" % (pulled, kept, quarantine_mb()))


def ext_for(cat, url):
    m = re.search(r"\.([a-z0-9]{1,4})(?:\?|#|$)", url.lower())
    if m: return "." + m.group(1)
    return {"pe": ".bin", "elf": ".elf", "macho": ".macho", "script": ".txt"}.get(cat, ".bin")


if __name__ == "__main__":
    main()
