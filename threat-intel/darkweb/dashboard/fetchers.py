#!/usr/bin/env python3
"""
fetchers.py  -  account-free sample acquisition helpers for triage.py.

  download(url, dest, pws) -> (ok, size, err): resolve a posted link to its real
                              file and fetch it (size-capped) into dest, handling
                              the file hosts that hide the file behind a landing
                              page or encryption. err == "unresolved" means the
                              host isn't one we can fetch from (triage skips it).
  unpack(path, out, pws)   -> extract an archive with 7z, trying the post's
                              password hint + a common-malware-password list.

Everything here only reads the web and writes local files; it never executes a
sample. All HTTP goes out over the box's Tor transport.
"""
import os, re, json, base64, struct, subprocess, urllib.request, urllib.parse, urllib.error

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")
# passwords malware channels use for "pass-protected" drops (hint from the post is tried first)
COMMON_PW = ["infected", "malware", "virus", "123", "1234", "12345", "password", "pass",
             "unpack", "changeme", "bagja", "malwar3", "clean", "2024", "2025", "2026"]
MAX_UNPACK_MB = 500           # zip-bomb guard: refuse archives that expand past this
MAX_FETCH_MB  = 200           # host-fetch cap (triage re-checks its own smaller cap on disk)
FETCH_TIMEOUT = 90
SAMPLE_EXT = re.compile(r"\.(exe|dll|scr|sys|7z|zip|rar|gz|tar|bin|img|iso|js|jse|vbs|ps1|"
                        r"bat|cmd|hta|jar|apk|dex|elf|msi|cab|lnk|com|ace|arj)(\?|#|$)", re.I)


# ----------------------------------------------------------------------------- helpers
def _req(url, data=None, headers=None, method=None):
    h = {"User-Agent": UA}
    if headers:
        h.update(headers)
    return urllib.request.Request(url, data=data, headers=h, method=method)


def _get_text(url, headers=None, limit=600000):
    with urllib.request.urlopen(_req(url, headers=headers), timeout=FETCH_TIMEOUT) as r:
        return r.read(limit).decode("utf-8", "replace")


def _capped_get(url, dest, headers=None, transform=None):
    """GET url -> dest, capped at MAX_FETCH_MB. transform(bytes)->bytes decrypts a stream
    (mega). Returns (ok, size, err)."""
    cap = MAX_FETCH_MB * 1024 * 1024
    try:
        with urllib.request.urlopen(_req(url, headers=headers), timeout=FETCH_TIMEOUT) as r:
            clen = r.headers.get("Content-Length")
            if clen and int(clen) > cap:
                return False, int(clen), "too-big"
            got = 0
            with open(dest, "wb") as out:
                while True:
                    chunk = r.read(262144)
                    if not chunk:
                        break
                    got += len(chunk)
                    if got > cap:
                        out.close(); os.remove(dest); return False, got, "exceeded-cap"
                    out.write(transform(chunk) if transform else chunk)
            return True, got, None
    except urllib.error.HTTPError as e:
        return False, 0, "http-%s" % e.code
    except Exception as e:
        return False, 0, str(getattr(e, "reason", e))[:50]


def extract_password(text):
    """Pull a password hint out of a post's text (pass: xxx / пароль: xxx / pwd=xxx)."""
    if not text:
        return []
    pws = []
    for m in re.finditer(r"(?:pass(?:word)?|pwd|pw|пароль|key)\s*[:=]\s*"
                         r"[\"'`]?([^\s\"'`<>]{1,40})", text, re.I):
        pws.append(m.group(1))
    return pws[:5]


# ----------------------------------------------------------------------------- per-host resolvers
# Each returns a list of "jobs": {"url":<direct>, "headers":{...}, "transform":<fn|None>}.
# None  -> host recognised but resolution failed transiently (caller may retry).
# []    -> host recognised, nothing to fetch (dead link).

def _direct(url):
    return [{"url": url, "headers": None, "transform": None}]


def _mediafire(url):
    try:
        h = _get_text(url)
    except Exception:
        return None
    m = re.search(r"https?://download[0-9]*\.mediafire\.com/[^\"'\s]+", h)
    if m:
        return [{"url": m.group(0), "headers": None, "transform": None}]
    sc = re.search(r'data-scrambled-url="([^"]+)"', h)   # newer mediafire obfuscation
    if sc:
        try:
            return [{"url": base64.b64decode(sc.group(1)).decode("utf-8", "replace"),
                     "headers": None, "transform": None}]
        except Exception:
            pass
    return []


def _megafile(url):
    try:
        h = _get_text(url)
    except Exception:
        return None
    for pat in (r'href="(https?://[^"]+/d/[^"]+)"',
                r'href="(https?://[^"]+\.(?:zip|rar|exe|7z|bin|dll|scr|msi)[^"]*)"',
                r'(https?://[^"\'\s]+/download/[^"\'\s]+)'):
        m = re.search(pat, h, re.I)
        if m:
            return [{"url": m.group(1), "headers": None, "transform": None}]
    return []


def _anonfiles(url):
    try:
        h = _get_text(url)
    except Exception:
        return None
    for pat in (r'id="download-url"[^>]*href="([^"]+)"',
                r'href="(https?://cdn[^"]+)"',
                r'href="(https?://[^"]+\.(?:zip|rar|exe|7z|bin|dll|apk|scr)[^"]*)"'):
        m = re.search(pat, h, re.I)
        if m:
            return [{"url": m.group(1), "headers": None, "transform": None}]
    return []


def _gofile(url):
    m = re.search(r"gofile\.io/d/([A-Za-z0-9]+)", url)
    if not m:
        return []
    cid = m.group(1)
    try:
        tok = json.loads(_get_text("https://api.gofile.io/accounts", limit=20000))["data"]["token"]
    except Exception:
        return None
    wt = ""
    try:
        js = _get_text("https://gofile.io/dist/js/global.js", limit=200000)
        wm = re.search(r'wt\s*[:=]\s*"([^"]+)"', js)
        wt = wm.group(1) if wm else ""
    except Exception:
        pass
    try:
        api = "https://api.gofile.io/contents/%s?wt=%s" % (cid, wt)
        d = json.loads(_get_text(api, headers={"Authorization": "Bearer " + tok}, limit=200000))
    except Exception:
        return None
    jobs, children = [], (d.get("data", {}).get("children") or {})
    cookie = {"Cookie": "accountToken=" + tok, "Authorization": "Bearer " + tok}
    for ch in children.values():
        link = ch.get("link")
        if link:
            jobs.append({"url": link, "headers": cookie, "transform": None})
    return jobs


def _b64url(s):
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s.replace("-", "+").replace("_", "/"))


def _mega(url):
    m = re.search(r"mega(?:\.nz|\.co\.nz)/file/([A-Za-z0-9_-]+)#([A-Za-z0-9_-]+)", url)
    if not m:                                            # folder links need extra crypto -> skip
        return []
    fid, key_b64 = m.group(1), m.group(2)
    try:
        a = struct.unpack(">8I", _b64url(key_b64)[:32])
    except Exception:
        return []
    aes_key = struct.pack(">4I", a[0] ^ a[4], a[1] ^ a[5], a[2] ^ a[6], a[3] ^ a[7])
    iv = struct.pack(">2I", a[4], a[5]) + b"\x00" * 8    # AES-CTR nonce + 64-bit counter
    try:
        body = json.dumps([{"a": "g", "g": 1, "p": fid}]).encode()
        req = _req("https://g.api.mega.co.nz/cs?id=0", data=body,
                   headers={"Content-Type": "application/json"}, method="POST")
        info = json.loads(urllib.request.urlopen(req, timeout=FETCH_TIMEOUT).read())[0]
    except Exception:
        return None
    if not isinstance(info, dict) or "g" not in info:
        return []
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        dec = Cipher(algorithms.AES(aes_key), modes.CTR(iv)).decryptor()
    except Exception:
        return []
    return [{"url": info["g"], "headers": None, "transform": dec.update}]


def _resolve_jobs(url):
    u = url.strip()
    if re.search(r"pixeldrain\.com/(?:u|file)/([a-z0-9]+)", u, re.I):
        fid = re.search(r"pixeldrain\.com/(?:u|file)/([a-z0-9]+)", u, re.I).group(1)
        return _direct("https://pixeldrain.com/api/file/%s" % fid)
    if "mediafire" in u:
        return _mediafire(u)
    if "gofile.io" in u:
        return _gofile(u)
    if re.search(r"mega(?:\.nz|\.co\.nz)", u):
        return _mega(u)
    if "megafile" in u:
        return _megafile(u)
    if re.search(r"anonfile", u, re.I):
        return _anonfiles(u)
    if SAMPLE_EXT.search(u.lower()):                     # already a direct file link
        return _direct(u)
    return "UNKNOWN"                                      # host we don't handle


def download(url, dest, passwords=None):
    """Resolve a posted link and fetch the real file into dest (size-capped, decrypted
    if needed). Returns (ok, size, err):
      'unresolved'    -> host we don't handle (give up)
      'no-link'       -> known host, dead/empty link (give up)
      'resolve-failed'-> known host, resolution failed transiently (retry)"""
    jobs = _resolve_jobs(url)
    if jobs == "UNKNOWN":
        return False, 0, "unresolved"
    if jobs is None:
        return False, 0, "resolve-failed"                # known host, transient -> caller retries
    if jobs == []:
        return False, 0, "no-link"                       # recognised host, dead/empty link
    last = "no-jobs"
    for job in jobs:
        ok, size, err = _capped_get(job["url"], dest, headers=job.get("headers"),
                                    transform=job.get("transform"))
        if ok:
            return True, size, None
        last = err
    return False, 0, last


# backward-compatible shim (some probes import resolve()); returns direct URLs only
def resolve(url):
    jobs = _resolve_jobs(url)
    return [j["url"] for j in jobs] if jobs else []


# ----------------------------------------------------------------------------- archive unpack
def _archive_mb(path):
    try:
        out = subprocess.run(["7z", "l", "-slt", path], stdin=subprocess.DEVNULL,
                             capture_output=True, text=True, timeout=30).stdout
        return sum(int(x) for x in re.findall(r"^Size = (\d+)", out, re.M)) / (1024 * 1024)
    except Exception:
        return 0.0


def unpack(path, outdir, passwords=None):
    """Extract with 7z (handles encrypted zip/7z/rar). Returns extracted file paths, or []."""
    if _archive_mb(path) > MAX_UNPACK_MB:                # zip-bomb guard
        return []
    os.makedirs(outdir, exist_ok=True)
    tries = [None] + list(dict.fromkeys((passwords or []) + COMMON_PW))
    for pw in tries:
        cmd = ["7z", "x", "-y", "-o" + outdir, ("-p" + pw) if pw is not None else "-p", path]
        try:
            r = subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, timeout=180)
        except Exception:
            continue
        files = [os.path.join(dp, f) for dp, _, fs in os.walk(outdir) for f in fs]
        if r.returncode == 0 and files:
            return files
        for f in files:                                  # clear partial before next password
            try: os.remove(f)
            except OSError: pass
    return []
