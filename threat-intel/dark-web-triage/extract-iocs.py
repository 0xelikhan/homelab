#!/usr/bin/env python3
"""Extract IOCs from pasted dark-web text (leak post, forum thread, chat) and
export them for OpenCTI / MISP. Pure stdlib, no deps. Keeps the research VM
isolated: it writes files you carry to your CTI stack, it does not connect to it.

Usage:
  python3 extract-iocs.py            # reads ~/Desktop/cti/paste.txt
  python3 extract-iocs.py FILE       # reads FILE
  pbpaste | python3 extract-iocs.py -# reads stdin
Outputs (next to this script, in ./iocs/):
  iocs.csv         MISP import format (value,type,category,comment)
  iocs.stix.json   STIX 2.1 bundle (indicators)
"""
import sys, os, re, json, csv, uuid, datetime

HERE = os.path.dirname(os.path.abspath(__file__))

def refang(t):
    return (t.replace("[.]", ".").replace("(.)", ".").replace("[dot]", ".")
             .replace("hxxp", "http").replace("[:]", ":").replace("[@]", "@").replace("[at]", "@"))

PATTERNS = {
    "sha256": (r"\b[a-fA-F0-9]{64}\b", "sha256", "Payload delivery"),
    "sha1":   (r"\b[a-fA-F0-9]{40}\b", "sha1", "Payload delivery"),
    "md5":    (r"\b[a-fA-F0-9]{32}\b", "md5", "Payload delivery"),
    "ipv4":   (r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "ip-dst", "Network activity"),
    "url":    (r"\bhttps?://[^\s\"'<>)\]]{6,}", "url", "Network activity"),
    "email":  (r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b", "email-src", "Social network"),
    "btc":    (r"\b(?:bc1[a-z0-9]{20,}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b", "btc", "Financial fraud"),
    "eth":    (r"\b0x[a-fA-F0-9]{40}\b", "eth", "Financial fraud"),
    "cve":    (r"\bCVE-\d{4}-\d{4,7}\b", "vulnerability", "Payload delivery"),
    "onion":  (r"\b[a-z2-7]{56}\.onion\b", "domain", "Network activity"),
    "domain": (r"\b(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,24}\b", "domain", "Network activity"),
}
# STIX 2.1 pattern builders
STIX = {
    "sha256": lambda v: f"[file:hashes.'SHA-256' = '{v}']",
    "sha1":   lambda v: f"[file:hashes.'SHA-1' = '{v}']",
    "md5":    lambda v: f"[file:hashes.'MD5' = '{v}']",
    "ipv4":   lambda v: f"[ipv4-addr:value = '{v}']",
    "url":    lambda v: f"[url:value = '{v}']",
    "email":  lambda v: f"[email-addr:value = '{v}']",
    "cve":    lambda v: None,  # -> vulnerability SDO handled separately
    "onion":  lambda v: f"[domain-name:value = '{v}']",
    "domain": lambda v: f"[domain-name:value = '{v}']",
    "btc":    lambda v: None, "eth": lambda v: None,
}

def main():
    arg = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "paste.txt")
    text = sys.stdin.read() if arg == "-" else open(arg, encoding="utf-8", errors="replace").read()
    text = refang(text)

    found = {}          # (type) -> set(values)
    order = ["sha256", "sha1", "md5", "onion", "url", "ipv4", "email", "btc", "eth", "cve", "domain"]
    claimed = set()     # char spans already taken by a longer match, to avoid domain-in-url dupes
    for key in order:
        rx, _mtype, _cat = PATTERNS[key]
        for m in re.finditer(rx, text):
            v = m.group(0)
            # skip hashes mis-caught as shorter hash / domain-in-url/email
            if key == "domain" and (any(v in u for u in found.get("url", set())) or
                                    any(v.endswith(".onion") for _ in [0]) or
                                    any(v in e for e in found.get("email", set()))):
                continue
            if key in ("md5", "sha1") and any(v in h for h in found.get("sha256", set()) | found.get("sha1", set())):
                continue
            found.setdefault(key, set()).add(v)

    # de-noise: drop obvious version-number IPs is left to the analyst; keep raw.
    rows, stix_objs = [], []
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    for key in order:
        for v in sorted(found.get(key, set())):
            _rx, mtype, cat = PATTERNS[key]
            rows.append({"value": v, "type": mtype, "category": cat, "comment": "dark-web collection"})
            if key == "cve":
                stix_objs.append({"type": "vulnerability", "spec_version": "2.1",
                                  "id": "vulnerability--" + str(uuid.uuid4()), "created": now,
                                  "modified": now, "name": v})
                continue
            pat = STIX[key](v)
            if pat:
                stix_objs.append({"type": "indicator", "spec_version": "2.1",
                                  "id": "indicator--" + str(uuid.uuid4()), "created": now, "modified": now,
                                  "name": f"{key}: {v}", "pattern": pat, "pattern_type": "stix",
                                  "valid_from": now, "labels": ["malicious-activity"]})

    out = os.path.join(HERE, "iocs")
    os.makedirs(out, exist_ok=True)
    with open(os.path.join(out, "iocs.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["value", "type", "category", "comment"]); w.writeheader(); w.writerows(rows)
    bundle = {"type": "bundle", "id": "bundle--" + str(uuid.uuid4()), "objects": stix_objs}
    json.dump(bundle, open(os.path.join(out, "iocs.stix.json"), "w"), indent=2)

    counts = {k: len(found.get(k, set())) for k in order if found.get(k)}
    print(f"extracted {sum(counts.values())} IOCs: {counts}")
    print(f"  MISP CSV : {os.path.join(out, 'iocs.csv')}")
    print(f"  STIX 2.1 : {os.path.join(out, 'iocs.stix.json')}")

if __name__ == "__main__":
    main()
