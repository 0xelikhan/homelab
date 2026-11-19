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
    try:                                                 # guest account: POST (not GET)
        req = _req("https://api.gofile.io/accounts", data=b"", method="POST")
        tok = json.loads(urllib.request.urlopen(req, timeout=FETCH_TIMEOUT).read())["data"]["token"]
    except Exception:
        return None
    wt = ""                                              # rotating website token (gofile moves it)
    for src in ("https://gofile.io/dist/js/global.js", "https://gofile.io/dist/js/alljs.js",
                "https://gofile.io"):
        try:
            js = _get_text(src, limit=500000)
            wm = re.search(r'(?:appdata\.)?wt\s*[:=]\s*"([0-9A-Za-z]{6,})"', js)
            if wm:
                wt = wm.group(1); break
        except Exception:
            continue
    auth = {"Cookie": "accountToken=" + tok, "Authorization": "Bearer " + tok}

    def contents(content_id):
        api = "https://api.gofile.io/contents/%s?wt=%s" % (content_id, wt)
        return json.loads(_get_text(api, headers=auth, limit=400000)).get("data", {})

    jobs = []
    try:
        root = contents(cid)
    except Exception:
        return None
    queue = [root]
    while queue and len(jobs) < MAX_FOLDER_FILES:
        node = queue.pop(0)
        for ch in (node.get("children") or {}).values():
            if len(jobs) >= MAX_FOLDER_FILES:
                break
            if ch.get("type") == "folder":               # recurse one directory deep
                try:
                    queue.append(contents(ch.get("id")))
                except Exception:
                    pass
            elif ch.get("link"):
                jobs.append({"url": ch["link"], "headers": auth, "transform": None})
    return jobs


def _b64url(s):
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s.replace("-", "+").replace("_", "/"))


MAX_FOLDER_FILES = 25           # cap files pulled from one folder link (mega folder / gofile)


def _mega_api(folder, body):
    q = "?id=0" + ("&n=" + folder if folder else "")
    req = _req("https://g.api.mega.co.nz/cs" + q, data=json.dumps(body).encode(),
               headers={"Content-Type": "application/json"}, method="POST")
    return json.loads(urllib.request.urlopen(req, timeout=FETCH_TIMEOUT).read())


def _mega_filekey(raw):
    """8-uint32 file key -> (aes_key, ctr_iv)."""
    a = struct.unpack(">8I", raw[:32])
    aes = struct.pack(">4I", a[0] ^ a[4], a[1] ^ a[5], a[2] ^ a[6], a[3] ^ a[7])
    iv = struct.pack(">2I", a[4], a[5]) + b"\x00" * 8    # CTR nonce + 64-bit counter
    return aes, iv


def _ctr(aes, iv):
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    return Cipher(algorithms.AES(aes), modes.CTR(iv)).decryptor()


def _mega_file(fid, key_b64):
    try:
        aes, iv = _mega_filekey(_b64url(key_b64))
    except Exception:
        return []
    try:
        info = _mega_api("", [{"a": "g", "g": 1, "p": fid}])[0]
    except Exception:
        return None
    if not isinstance(info, dict) or "g" not in info:
        return []
    try:
        return [{"url": info["g"], "headers": None, "transform": _ctr(aes, iv).update}]
    except Exception:
        return []


def _mega_folder(folder, key_b64):
    """Decrypt a shared folder's node list and resolve each file to a download job."""
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        mk = _b64url(key_b64)[:16]                       # 16-byte folder master key
    except Exception:
        return []
    try:
        res = _mega_api(folder, [{"a": "f", "c": 1, "r": 1, "ca": 1}])
    except Exception:
        return None
    if not isinstance(res, list) or not res or not isinstance(res[0], dict):
        return []
    jobs = []
    for node in (res[0].get("f") or []):
        if node.get("t") != 0 or len(jobs) >= MAX_FOLDER_FILES:   # files only
            continue
        enc = next((p.split(":", 1)[1] for p in (node.get("k") or "").split("/") if ":" in p), "")
        if not enc:
            continue
        try:
            dec = Cipher(algorithms.AES(mk), modes.ECB()).decryptor()
            raw = dec.update(_b64url(enc)) + dec.finalize()
            if len(raw) < 32:
                continue
            aes, iv = _mega_filekey(raw)
            info = _mega_api(folder, [{"a": "g", "g": 1, "n": node.get("h")}])[0]
        except Exception:
            continue
        if isinstance(info, dict) and "g" in info:
            try:
                jobs.append({"url": info["g"], "headers": None, "transform": _ctr(aes, iv).update})
            except Exception:
                pass
    return jobs


def _mega(url):
    mf = re.search(r"mega(?:\.nz|\.co\.nz)/folder/([A-Za-z0-9_-]+)#([A-Za-z0-9_-]+)", url)
    if mf:
        return _mega_folder(mf.group(1), mf.group(2))
    m = re.search(r"mega(?:\.nz|\.co\.nz)/file/([A-Za-z0-9_-]+)#([A-Za-z0-9_-]+)", url)
    if m:
        return _mega_file(m.group(1), m.group(2))
    return []


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


def download_samples(url, workdir, passwords=None):
    """Resolve a posted link and fetch EVERY file it points at (a folder link yields many)
    into workdir, decrypting as needed. Returns (paths, err):
      paths            -> local temp files downloaded (empty on failure)
      'unresolved'     -> host we don't handle (give up)
      'no-link'        -> known host, dead/empty link (give up)
      'resolve-failed' -> known host, resolution failed transiently (retry)"""
    jobs = _resolve_jobs(url)
    if jobs == "UNKNOWN":
        return [], "unresolved"
    if jobs is None:
        return [], "resolve-failed"
    if jobs == []:
        return [], "no-link"
    paths, last = [], None
    for i, job in enumerate(jobs):
        dest = os.path.join(workdir, ".incoming_%d" % i)
        ok, size, err = _capped_get(job["url"], dest, headers=job.get("headers"),
                                    transform=job.get("transform"))
        if ok:
            paths.append(dest)
        else:
            last = err
    return (paths, None) if paths else ([], last or "no-jobs")


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
