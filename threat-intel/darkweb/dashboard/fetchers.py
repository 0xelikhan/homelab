#!/usr/bin/env python3
"""
fetchers.py  -  account-free sample acquisition helpers for triage.py.

  resolve(url)              -> list of direct-download URLs for a posted link
                               (direct file links + pixeldrain; extensible per host).
  unpack(path, out, pws)    -> extract an archive with 7z, trying the post's password
                               hint + a common-malware-password list; zip-bomb guarded.

Everything here only reads the web and writes local files; it never executes a sample.
All HTTP goes out over the box's Tor transport.
"""
import os, re, subprocess

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")
# passwords malware channels use for "pass-protected" drops (hint from the post is tried first)
COMMON_PW = ["infected", "malware", "virus", "123", "1234", "12345", "password", "pass",
             "unpack", "changeme", "bagja", "malwar3", "clean", "2024", "2025"]
MAX_UNPACK_MB = 500           # zip-bomb guard: refuse archives that expand past this
SAMPLE_EXT = re.compile(r"\.(exe|dll|scr|sys|7z|zip|rar|gz|tar|bin|img|iso|js|jse|vbs|ps1|"
                        r"bat|cmd|hta|jar|apk|dex|elf|msi|cab|lnk|com|ace|arj)(\?|#|$)", re.I)


def resolve(url):
    """Posted link -> list of direct-download URLs (best-effort, account-free)."""
    u = url.strip()
    m = re.search(r"pixeldrain\.com/(?:u|file)/([a-z0-9]+)", u, re.I)
    if m:
        return ["https://pixeldrain.com/api/file/%s" % m.group(1)]
    if SAMPLE_EXT.search(u.lower()):                 # already a direct file link
        return [u]
    # gofile / mega / mediafire need host-specific flows (guest token / crypto / scrape);
    # left as TODO resolvers so the pipeline degrades instead of guessing.
    return []


def extract_password(text):
    """Pull a password hint out of a post's text (pass: xxx / пароль: xxx / pwd=xxx)."""
    if not text:
        return []
    pws = []
    for m in re.finditer(r"(?:pass(?:word)?|pwd|pw|пароль|key)\s*[:=]\s*"
                         r"[\"'`]?([^\s\"'`<>]{1,40})", text, re.I):
        pws.append(m.group(1))
    return pws[:5]


def _archive_mb(path):
    try:
        out = subprocess.run(["7z", "l", "-slt", path], stdin=subprocess.DEVNULL,
                             capture_output=True, text=True, timeout=30).stdout
        return sum(int(x) for x in re.findall(r"^Size = (\d+)", out, re.M)) / (1024 * 1024)
    except Exception:
        return 0.0


def unpack(path, outdir, passwords=None):
    """Extract with 7z (handles encrypted zip/7z/rar). Returns extracted file paths, or []."""
    if _archive_mb(path) > MAX_UNPACK_MB:            # zip-bomb guard
        return []
    os.makedirs(outdir, exist_ok=True)
    tries = [None] + list(dict.fromkeys((passwords or []) + COMMON_PW))
    for pw in tries:
        cmd = ["7z", "x", "-y", "-o" + outdir, ("-p" + pw) if pw is not None else "-p", path]
        try:
            r = subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, timeout=120)
        except Exception:
            continue
        files = [os.path.join(dp, f) for dp, _, fs in os.walk(outdir) for f in fs]
        if r.returncode == 0 and files:
            return files
        for f in files:                              # clear partial before next password
            try: os.remove(f)
            except OSError: pass
    return []
