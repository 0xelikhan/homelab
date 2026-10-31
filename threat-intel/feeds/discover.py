#!/usr/bin/env python3
"""Build a verified RSS/Atom feed list for OpenCTI RSS ingestion.
Sources: awesome_threat_intel_blogs (blog homepages, feed discovered), the vx-underground
ThreatIntelligenceDiscordBot RSS list, Google Cloud TI, and infosec.exchange hashtags.
Output: feeds.csv (name,category,feed_url). Only feeds that parse as RSS/Atom are kept."""
import csv, html, re, sys, urllib.parse, urllib.request
from concurrent.futures import ThreadPoolExecutor

UA = {"User-Agent": "Mozilla/5.0 (homelab feed discovery)"}
TIMEOUT = 20


def get(url, limit=400_000):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        return r.geturl(), r.read(limit).decode("utf-8", "replace")


def is_feed(url):
    try:
        _, body = get(url, 60_000)
    except Exception:
        return False
    head = body.lstrip()[:600].lower()
    return ("<rss" in head or "<feed" in head or "<rdf:rdf" in head) and "<html" not in head[:200]


def discover(blog):
    """Return a working feed URL for a blog homepage, or None."""
    try:
        final, body = get(blog)
    except Exception:
        final, body = blog, ""
    cands = []
    for tag in re.findall(r"<link[^>]+>", body, re.I):
        if re.search(r"application/(rss|atom)\+xml", tag, re.I):
            m = re.search(r"href=[\"']([^\"']+)", tag, re.I)
            if m:
                cands.append(urllib.parse.urljoin(final, html.unescape(m.group(1))))
    base = final if final.endswith("/") else final + "/"
    cands += [urllib.parse.urljoin(base, p) for p in
              ("feed", "feed/", "rss", "rss.xml", "atom.xml", "index.xml", "feed.xml", "feeds/posts/default")]
    seen = set()
    for c in cands:
        if c in seen or "comments" in c.lower():
            continue
        seen.add(c)
        if is_feed(c):
            return c
    return None


def main(out):
    _, readme = get("https://raw.githubusercontent.com/muchdogesec/awesome_threat_intel_blogs/main/README.md", 5_000_000)
    rows = re.findall(r"<tr>\s*<td>(.*?)</td>\s*<td>(.*?)</td>\s*<td><a href='([^']+)'", readme, re.S)
    blogs = [(html.unescape(n).strip(), t.strip(), u) for n, t, u in rows if n.strip() != "Name"]
    print(f"awesome_threat_intel_blogs: {len(blogs)} blogs", file=sys.stderr)

    direct = [  # already feed URLs
        ("Google Cloud Threat Intelligence", "Vendor", "https://cloud.google.com/blog/topics/threat-intelligence/rss/"),
        ("Google Online Security Blog", "Vendor", "http://feeds.feedburner.com/GoogleOnlineSecurityBlog"),
        ("The Hacker News", "News", "http://feeds.feedburner.com/TheHackersNews?format=xml"),
        ("ESET WeLiveSecurity", "Vendor", "http://feeds.feedburner.com/eset/blog"),
        ("Trend Micro Research", "Vendor", "http://feeds.trendmicro.com/TrendMicroResearch"),
        ("XPN InfoSec", "Analyst", "https://blog.xpnsec.com/rss.xml"),
        ("Cisco Security", "Vendor", "https://blogs.cisco.com/security/feed"),
        ("Graham Cluley", "News", "https://grahamcluley.com/feed/"),
        ("Krebs on Security", "News", "https://krebsonsecurity.com/feed/"),
        ("MSRC Blog", "Vendor", "https://msrc-blog.microsoft.com/feed/"),
        ("Red Canary", "Vendor", "https://redcanary.com/feed/"),
        ("Check Point Research", "Vendor", "https://research.checkpoint.com/feed/"),
        ("Securelist", "Vendor", "https://securelist.com/feed/"),
        ("Binary Defense", "Vendor", "https://www.binarydefense.com/feed/"),
        ("BleepingComputer", "News", "https://www.bleepingcomputer.com/feed/"),
        ("CISA Advisories", "Government", "https://www.cisa.gov/cybersecurity-advisories/all.xml"),
        ("CIS Advisories", "Government", "https://www.cisecurity.org/feed/advisories"),
        ("Dark Reading", "News", "https://www.darkreading.com/rss.xml"),
        ("Infosecurity Magazine", "News", "https://www.infosecurity-magazine.com/rss/news/"),
        ("NCSC UK Reports", "Government", "https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml"),
        ("Proofpoint", "Vendor", "https://www.proofpoint.com/us/rss.xml"),
        ("Recorded Future", "Vendor", "https://www.recordedfuture.com/feed"),
        ("Schneier on Security", "Analyst", "https://www.schneier.com/feed/atom/"),
        ("SentinelOne Labs", "Vendor", "https://www.sentinelone.com/labs/feed/"),
        ("Tyranid's Lair", "Analyst", "https://www.tiraniddo.dev/feeds/posts/default"),
        ("The DFIR Report", "Analyst", "https://thedfirreport.com/feed/"),
        ("Unit 42", "Vendor", "https://unit42.paloaltonetworks.com/feed/"),
        ("Microsoft Threat Intelligence", "Vendor", "https://www.microsoft.com/en-us/security/blog/topic/threat-intelligence/feed/"),
        ("FS-ISAC News", "ISAC", "https://www.fsisac.com/newsroom/rss.xml"),
        ("AboutDFIR", "Analyst", "https://aboutdfir.com/feed/"),
        ("Bitdefender Labs", "Vendor", "https://www.bitdefender.com/blog/api/rss/labs/"),
        ("CERT-EU Security Advisories", "Government", "https://cert.europa.eu/publications/security-advisories-rss"),
        ("CERT-SE", "Government", "https://www.cert.se/feed.rss"),
        ("CERT/CC Vulnerability Notes", "Government", "https://www.kb.cert.org/vulfeed"),
        ("CVEFeed.io Latest CVEs", "Community", "https://cvefeed.io/rssfeed/latest.xml"),
        ("Chrome Releases", "Vendor", "https://chromereleases.googleblog.com/feeds/posts/default"),
        ("Cyber Kendra", "Media", "https://www.cyberkendra.com/feeds/posts/default"),
        ("DFIR Diva", "Analyst", "https://dfirdiva.com/feed/"),
        ("Daily Dark Web", "Media", "https://dailydarkweb.net/feed/"),
        ("Datadog Security Labs", "Vendor", "https://securitylabs.datadoghq.com/rss/feed.xml"),
        ("Debian Security Advisories", "Vendor", "https://www.debian.org/security/dsa"),
        ("Didier Stevens", "Analyst", "https://blog.didierstevens.com/feed/"),
        ("Emsisoft Blog", "Vendor", "https://www.emsisoft.com/en/blog/feed/"),
        ("Exploit-DB", "Community", "https://www.exploit-db.com/rss.xml"),
        ("FortiGuard Labs", "Vendor", "https://feeds.fortinet.com/fortinet/blog/threat-research"),
        ("Fortinet PSIRT Advisories", "Vendor", "https://filestore.fortinet.com/fortiguard/rss/ir.xml"),
        ("Hexacorn", "Analyst", "https://www.hexacorn.com/blog/feed/"),
        ("Horizon3.ai Attack Research", "Vendor", "https://www.horizon3.ai/feed/"),
        ("Inversecos", "Analyst", "https://www.inversecos.com/feeds/posts/default"),
        ("Invictus IR", "Vendor", "https://www.invictus-ir.com/news/rss.xml"),
        ("Jeffrey Appel", "Analyst", "https://jeffreyappel.nl/feed/"),
        ("Malware Traffic Analysis", "Analyst", "https://www.malware-traffic-analysis.net/blog-entries.rss"),
        ("Objective-See (Mac malware)", "Analyst", "https://objective-see.org/rss.xml"),
        ("OffSec Blog", "Vendor", "https://www.offsec.com/rss.xml"),
        ("PortSwigger Web Security Research", "Vendor", "https://portswigger.net/research/rss"),
        ("Praetorian Security", "Vendor", "https://www.praetorian.com/feed/"),
        ("Risky Bulletin", "Media", "https://risky.biz/feeds/risky-business-news/"),
        ("Sekoia.io Blog", "Vendor", "https://blog.sekoia.io/feed/"),
        ("Trail of Bits", "Vendor", "https://blog.trailofbits.com/feed/"),
        ("Ubuntu Security Notices", "Vendor", "https://ubuntu.com/security/notices/rss.xml"),
        ("Volexity", "Vendor", "https://www.volexity.com/feed/"),
        ("Windows Incident Response (Harlan Carvey)", "Analyst", "https://windowsir.blogspot.com/feeds/posts/default"),
        ("Wordfence", "Vendor", "https://www.wordfence.com/feed/"),
        ("Zscaler ThreatLabz", "Vendor", "https://www.zscaler.com/blogs/feeds/security-research"),
        ("watchTowr Labs", "Vendor", "https://labs.watchtowr.com/rss/"),
    ]
    for tag in ("threatintel", "cti", "malware", "ransomware", "ioc", "cve", "infosec", "dfir"):
        direct.append((f"infosec.exchange #{tag}", "Community", f"https://infosec.exchange/tags/{tag}.rss"))

    results = []
    with ThreadPoolExecutor(24) as ex:
        found = list(ex.map(lambda b: (b, discover(b[2])), blogs))
        checked = list(ex.map(lambda d: (d, is_feed(d[2])), direct))
    results += [(b[0], b[1], f) for b, f in found if f]
    results += [d for d, ok in checked if ok]
    dead = [b[0] for b, f in found if not f] + [d[0] for d, ok in checked if not ok]

    # de-duplicate by feed URL
    seen, final = set(), []
    for r in results:
        k = r[2].rstrip("/").lower()
        if k not in seen:
            seen.add(k); final.append(r)
    with open(out, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f); w.writerow(["name", "category", "feed_url"]); w.writerows(final)
    print(f"verified feeds: {len(final)}  (no feed found / dead: {len(dead)})", file=sys.stderr)
    with open(out.replace(".csv", "-dead.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(dead))


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "feeds.csv")
