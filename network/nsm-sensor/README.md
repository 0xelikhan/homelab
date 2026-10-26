# NSM sensor (Zeek + Suricata)

| Item | Value |
|---|---|
| VM | 114 `nsm-sensor`, 2 cores, 4 GB RAM, Ubuntu 22.04 |
| Group | `nsm` (off unless started) |
| NIC 1 | Management, SOC VLAN |
| NIC 2 | Capture only, no IP, on a bridge with no uplink |
| Suricata | 8.0, ET Open rules, JA3 and JA4 on TLS, JA4 on QUIC |
| Zeek | 8.0 with the FoxIO JA4+ package, JSON logs |

Watches every packet that crosses pfSense's LAN trunk: traffic between lab VLANs and from the lab to the internet.

## How traffic gets here

The Proxmox host copies pfSense's LAN interface (both directions) to the sensor's capture NIC with `tc mirred`. Packets keep their VLAN tags.

| Piece | Where | What it does |
|---|---|---|
| `nsm-mirror` | host, `/usr/local/sbin` | Sets up the mirror. Safe to rerun |
| `nsm-mirror-hook.sh` | host, snippets storage | Hookscript on VMs 100 and 114, reruns the mirror after either starts |
| `nsm-mirror.service` | host | Reruns the mirror at host boot |
| `capture-nic.service` | sensor | Brings the capture NIC up, promiscuous, offloads off |

## Logs

| Source | Location on the sensor | Sent to Wazuh |
|---|---|---|
| Suricata | `/var/log/suricata/eve.json` | yes, Wazuh decodes Suricata alerts |
| Zeek | `/opt/zeek/logs/current/*.log`, kept 3 days | `notice.log` only |

`community-id` is on in both, so a Suricata alert and the matching Zeek `conn.log` line share an ID.

## Maintenance

| Job | When |
|---|---|
| `suricata-update`, then `systemctl reload suricata` | daily 04:30 |
| logrotate (`copytruncate`, 3 days) | daily |
| `zeekctl cron` (restarts crashed workers, rotates logs) | every 5 minutes |

Disabled rules go in `/etc/suricata/disable.conf` (currently "Ethertype unknown", which fires on normal trunk traffic).

Per-host suppressions go in `/etc/suricata/threshold.config`. Hermes talking to the Telegram API is suppressed there, since that is how the briefs are delivered.

Zeek has `ignore_checksums` on. VM traffic on the mirror carries offloaded checksums and Zeek would drop it otherwise.

## Use

```bash
lab-profile nsm start
# on the sensor
jq 'select(.event_type=="alert") | .alert.signature' /var/log/suricata/eve.json | sort | uniq -c | sort -rn
jq -r 'select(.ja4 != "") | [.ja4, .server_name] | @tsv' /opt/zeek/logs/current/ssl.log | sort | uniq -c
```
