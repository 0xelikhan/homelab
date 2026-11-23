#!/usr/bin/env python3
"""
darkweb-flash.py  -  Hermes script-only job (no model). Prints one Telegram message when the
dark-web pipeline keeps a new sample; prints nothing otherwise.

Input: /srv/intel/darkweb-keeps.jsonl, appended by darkweb-bridge.py on pve (one sanitised
JSON line per new dark-web / Telegram keep). State: ~/.cache/darkweb-flash.json (byte offset).
"""
import json, os, sys

SRC   = "/srv/intel/darkweb-keeps.jsonl"
STATE = os.path.expanduser("~/.cache/darkweb-flash.json")


def main():
    try:
        off = json.load(open(STATE)).get("offset", 0)
    except Exception:
        off = 0
    try:
        size = os.path.getsize(SRC)
    except OSError:
        return 0                                         # bridge has not written anything yet
    if size < off:                                       # file was rotated / recreated
        off = 0
    with open(SRC, encoding="utf-8", errors="replace") as f:
        f.seek(off)
        data = f.read()
        off = f.tell()
    items = []
    for ln in data.splitlines():
        try:
            items.append(json.loads(ln))
        except Exception:
            continue
    os.makedirs(os.path.dirname(STATE), exist_ok=True)
    json.dump({"offset": off}, open(STATE, "w"))
    if not items:
        return 0
    out = ["Dark-web sample kept (%d)" % len(items)]
    for i, k in enumerate(items, 1):
        fam = ", ".join(k.get("family") or []) or "no signature match"
        mb = k.get("mb") or "unchecked"
        mb = "not in MalwareBazaar" if mb == "novel" else ("MalwareBazaar: " + mb.split(":", 1)[-1]
                                                          if mb.startswith("known:") else "MB " + mb)
        out.append("")
        out.append("%d. %s from %s (%s)" % (i, k.get("category", "?").upper(), k.get("source") or "?",
                                           k.get("origin", "")))
        out.append("   %s" % fam)
        out.append("   %s | %s" % (mb, k.get("vt") or "VT pending"))
        out.append("   why: %s" % (k.get("reasons") or "-")[:160])
        out.append("   sha256 %s" % k.get("sha256", ""))
    out.append("")
    out.append("On the research VM: ~/quarantine/<sha256>/findings.txt")
    print("\n".join(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
