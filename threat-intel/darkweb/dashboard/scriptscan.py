#!/usr/bin/env python3
"""scriptscan.py - static verdict for script malware (PowerShell, JScript/WSH, VBScript, batch, HTA).

YARA (signature-base) and capa catch almost no script loaders, and `file` labels most of them
"ASCII text", so triage dropped them as not-exe. This scores what a loader has to do and what
it does to hide it:

  exec      run code or a process: IEX, [ScriptBlock]::Create, Assembly::Load, WScript.Shell,
            Shell.Application, Win32_Process, VBS Execute, LOLBins (mshta, regsvr32, certutil...)
  download  pull a stage: Net.WebClient, Invoke-WebRequest, XMLHTTP, WinHttp, URL to an executable
  drop      write to disk from a script host: ADODB.Stream, SaveToFile, FileSystemObject
  decode    unwrap a payload: FromBase64String, GZip/Deflate, AES/CreateDecryptor, -bxor
  obf       hide it: a big encoded blob, obfuscator.io hex arithmetic / _0x names, batch
            %var:~n,m% slicing, caret splitting
  host      runs under Windows Script Host (WScript., ActiveXObject, CreateObject)

Browser-JS primitives (eval, new Function, String.fromCharCode) only count as weak signal, and
data: URI blobs (inline fonts and images) never count as an encoded payload, so minified web
libraries stay below the bar. Read-only; never executes anything.

  scriptscan.py FILE...      print score, verdict and hits per file (for tuning)
"""
import re, sys

MAX_BYTES = 20 * 1024 * 1024
KEEP_SCORE = 5

def _r(p):
    return re.compile(p, re.I)

# (group, weight, label, regex)
RULES = [
    ("exec", 3, "ps-iex", _r(r"\binvoke-expression\b|(?<![\w-])iex\s*[\(\$'\"]|\|\s*iex\b")),
    ("exec", 3, "ps-scriptblock", _r(r"\[scriptblock\]::create|\.invokecommand\.invokescript|newscriptblock")),
    ("exec", 3, "ps-assembly-load", _r(r"\[(system\.)?reflection\.assembly\]::(un)?safe?load|assembly\]::load\s*\(")),
    ("exec", 3, "ps-encoded", _r(r"-e(nc(odedcommand)?)?\s+[A-Za-z0-9+/]{40,}")),
    ("exec", 3, "wsh-shell", _r(r"wscript\.shell")),
    ("exec", 2, "shell-app", _r(r"shell\.application|shellexecute")),   # also used to unzip by installers
    ("exec", 3, "wmi-process", _r(r"win32_process|winmgmts:")),
    ("exec", 3, "vbs-execute", _r(r"(?m)executeglobal\b|^\s*execute\s+[\w\"(]")),
    ("exec", 3, "lolbin", _r(r"\b(mshta(\.exe)?\s+(https?:|vbscript:|javascript:)|regsvr32(\.exe)?\s+.*?/i:\s*https?:|"
                             r"rundll32(\.exe)?\s+.*?javascript:|certutil(\.exe)?\s+.*?-(urlcache|decode)|"
                             r"bitsadmin(\.exe)?\s+/transfer)")),
    ("exec", 3, "ps-hidden", _r(r"powershell(\.exe)?[^\r\n]{0,80}\s-w(indowstyle)?\s+h(idden)?\b|-windowstyle\s+hidden")),
    ("exec", 1, "ps-bypass", _r(r"-(ep|executionpolicy)\s+bypass")),           # installers do this too
    ("exec", 2, "persist", _r(r"schtasks(\.exe)?\s+/create|currentversion\\+run\b|add-mppreference\s+-exclusion|"
                              r"\\startup\\|new-scheduledtask")),
    ("exec", 2, "native-api", _r(r"virtualalloc|createthread|getdelegateforfunctionpointer|ntprotectvirtualmemory")),
    ("download", 2, "ps-download", _r(r"net\.webclient|downloadstring|downloaddata|downloadfile|invoke-webrequest|"
                                      r"invoke-restmethod|start-bitstransfer|(?<![\w-])(iwr|irm)\s+['\"]?https?:")),
    ("download", 2, "wsh-http", _r(r"msxml2\.(server)?xmlhttp|winhttp\.winhttprequest|microsoft\.xmlhttp")),
    ("download", 2, "url-to-exe", _r(r"https?://[^\s\"'<>]+\.(ps1|exe|dll|hta|vbs|vbe|bat|cmd|scr|msi)\b")),
    ("drop", 2, "adodb-stream", _r(r"adodb\.stream|\.savetofile\b")),
    ("drop", 1, "fso", _r(r"scripting\.filesystemobject")),
    ("decode", 2, "b64-decode", _r(r"frombase64string|\[convert\]::frombase64|base64decode|\.decodebase64")),
    ("decode", 1, "decompress", _r(r"gzipstream|deflatestream|io\.compression")),   # installers unzip too
    ("decode", 2, "crypto", _r(r"security\.cryptography|aesmanaged|\[aes\]::create|createdecryptor|rijndael")),
    ("decode", 2, "xor", _r(r"-bxor\b")),
    ("host", 1, "wsh", _r(r"\bwscript\.|activexobject\s*\(|\bcreateobject\s*\(")),
]
WEAK = [  # browser-common; each worth 1, together capped at 2
    ("eval", _r(r"\beval\s*\(")),
    ("new-function", _r(r"\bnew\s+function\s*\(")),
    ("fromcharcode", _r(r"string\.fromcharcode")),
]
BLOB = re.compile(r"[A-Za-z0-9+/]{80,}={0,2}|[0-9a-fA-F]{80,}")
DATA_URI = re.compile(r"base64,\s*$|data:[\w/+.-]*;?\s*$", re.I)
HEX_ARITH = re.compile(r"0x[0-9a-f]+\s*\*\s*-?0x[0-9a-f]+|-0x[0-9a-f]+\s*\+\s*-?0x[0-9a-f]+", re.I)
OBF_IDENT = re.compile(r"\b_0x[0-9a-f]{4,6}\b", re.I)
BAT_SLICE = re.compile(r"%[\w#$@]+:~-?\d+,\d+%")
CARET = re.compile(r"(?:\w\^){4,}\w")


def read_text(path, limit=MAX_BYTES):
    b = open(path, "rb").read(limit)
    if b[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return b.decode("utf-16", "replace")
    if len(b) > 64 and b[1:64:2].count(0) > 24:          # UTF-16LE without a BOM
        return b.decode("utf-16-le", "replace")
    return b.decode("utf-8", "replace")


def _blob_stats(t):
    total = longest = 0
    for m in BLOB.finditer(t):
        if DATA_URI.search(t[max(0, m.start() - 40):m.start()]):
            continue                                     # inline font/image, not a payload
        n = m.end() - m.start()
        total += n
        longest = max(longest, n)
    return total, longest


def scan_text(t):
    """(score, hits[], groups set)."""
    hits, groups, score = [], set(), 0
    for g, w, label, rx in RULES:
        if rx.search(t):
            hits.append(label); groups.add(g); score += w
    weak = [label for label, rx in WEAK if rx.search(t)]
    if weak:
        hits += weak; score += min(2, len(weak))
    n = max(1, len(t))
    blob, longest = _blob_stats(t)
    # Multi-line base64 (PowerShell here-strings) breaks into 76-char lines: count lines that are pure blob.
    blob_lines = sum(len(l) for l in t.splitlines() if len(l) >= 60 and BLOB.fullmatch(l.strip().strip("\"',")))
    blob = max(blob, blob_lines)
    if (blob >= 20000 and blob / n >= 0.4) or longest >= 100000:
        hits.append("obf:blob%dk" % (blob // 1000)); groups.add("obf"); score += 3
    ha, oi = len(HEX_ARITH.findall(t)), len(OBF_IDENT.findall(t))
    if ha >= 20 or oi >= 20:                             # minifiers never emit 0x..*-0x.. arithmetic
        hits.append("obf:jsobf(hex%d,_0x%d)" % (ha, oi)); groups.add("obf"); score += 4
    bs, ca = len(BAT_SLICE.findall(t)), len(CARET.findall(t))
    if bs >= 10 or ca >= 10:
        hits.append("obf:batch(slice%d,caret%d)" % (bs, ca)); groups.add("obf"); score += 3
    if {"exec", "download"} <= groups and len(t) < 4000:  # one-liner download cradle, not an installer
        hits.append("cradle"); score += 1
    return score, hits, groups


# What separates a loader from an installer (Chocolatey, Scoop, vcpkg also download and IEX):
# payload handling, stealth, or obfuscation. Download + execute alone is not enough.
PAYLOAD = {"b64-decode", "crypto", "xor", "adodb-stream"}
STEALTH = {"wsh-shell", "wmi-process", "ps-hidden", "ps-encoded", "lolbin", "persist", "native-api",
           "ps-assembly-load", "cradle"}


def verdict(path):
    """(malicious_bool, hits[]). Malicious = score >= KEEP_SCORE and at least one payload,
    stealth or obfuscation hit."""
    try:
        t = read_text(path)
    except Exception:
        return False, []
    score, hits, groups = scan_text(t)
    mal = score >= KEEP_SCORE and ("obf" in groups or bool(set(hits) & (PAYLOAD | STEALTH)))
    return mal, ["s%d" % score] + hits


def is_scriptish(desc, path):
    """Worth a script scan: text per `file`, or a script extension on something `file` calls data."""
    d = (desc or "").lower()
    if any(k in d for k in ("text", "script", "html", "xml", "source")):
        return not any(k in d for k in ("pdf", "rich text format", "postscript"))
    return bool(re.search(r"\.(ps1|psm1|vbs|vbe|jse?|wsf|hta|bat|cmd)$", path, re.I))


if __name__ == "__main__":
    for p in sys.argv[1:]:
        mal, hits = verdict(p)
        print("%s %s %s" % ("MAL " if mal else "pass", p.rsplit("/", 1)[-1][:40], " ".join(hits)))
