# IOC export

| Item | Value |
|---|---|
| Runs on | Proxmox host, `/usr/local/bin/ioc-export` |
| Schedule | `ioc-export.timer`, every 4 hours, plus after the NSM sensor or Wazuh starts |
| Sources | MISP and OpenCTI, read-only accounts |
| Output | `/var/lib/ioc-export/` on the host |

Turns threat intel into detections. Pulls network indicators from the last 30 days and pushes them to the sensors and the SIEM.

## What it pulls

| Source | What |
|---|---|
| MISP | IDS-flagged `ip-dst`, `ip-src`, `domain`, `hostname`, `url`, `ip-dst|port`, warning lists applied. Paged, 2000 per request |
| OpenCTI | STIX indicators (IPv4, domain, URL) with a score of 40 or more, not revoked |

OpenCTI indicators go first, MISP fills the rest. Up to 100,000 IPs and 100,000 domains.

Dropped: private and reserved addresses, and shared CDN ranges (Cloudflare, Fastly, CloudFront, Google), which host thousands of unrelated sites.

If a source fails part way, the previous lists are kept.

## Where the lists go

| Destination | File | Used by |
|---|---|---|
| NSM sensor, Suricata | `/etc/suricata/ioc/cti-iprep.list` | IP reputation, rules 9100001 and 9100002 |
| NSM sensor, Suricata | `/etc/suricata/ioc/cti-domains.lst` | Dataset for DNS, TLS SNI and HTTP host, rules 9100003 to 9100005 |
| NSM sensor, Zeek | `/opt/zeek/share/zeek/site/cti.intel` | Intel framework, hits go to `intel.log` and `notice.log` |
| Wazuh | `/var/ossec/etc/lists/cti-ips`, `cti-domains` | CDB lists, rules 100390 to 100393 |

Suricata is restarted after a push (IP reputation is read at start). Wazuh is restarted only when a list changed.

## Self-test

The lists always contain one test IP (TEST-NET) and the domain `ioc-selftest.lab.invalid`. The [health check](../../infrastructure/monitoring/README.md) looks up the test domain and expects a Wazuh alert.

## Run it by hand

```bash
systemctl start ioc-export.service          # full export and push
/usr/local/bin/ioc-export --push-only       # push the current lists to running machines
cat /var/lib/ioc-export/status.json         # last run and counts
```
