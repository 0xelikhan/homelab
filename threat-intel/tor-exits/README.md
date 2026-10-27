# Tor exit-node detection

Flags connections to or from Tor exit nodes in Wazuh. Ported from the
[secops-detection-rules](https://github.com/0xelikhan/secops-detection-rules) `threat_intel`
YARA-L rules (which target Google SecOps); this reimplements the useful logic for the lab's
Wazuh + CDB stack, alongside the MISP/OpenCTI IOC lists from [ioc-export](../ioc-export/README.md).

## What it does

| File | Role |
|---|---|
| [update-tor-exits.sh](update-tor-exits.sh) | Fetches the official Tor bulk exit list, writes `etc/lists/tor-exit-nodes` (CDB), reloads the manager |
| [tor-wazuh-rules.xml](tor-wazuh-rules.xml) | Rules 100600/100601: inbound/outbound Tor exit contact (T1090.003) |
| [tor-exits.service](tor-exits.service) / [.timer](tor-exits.timer) | Refreshes the list every 6 hours |

## Install (on the Wazuh manager)

```bash
install -m755 update-tor-exits.sh /usr/local/bin/update-tor-exits.sh
# declare the list in ossec.conf under <ruleset>:
#   <list>etc/lists/tor-exit-nodes</list>
# merge tor-wazuh-rules.xml into etc/rules/local_rules.xml, then:
/usr/local/bin/update-tor-exits.sh
cp tor-exits.service tor-exits.timer /etc/systemd/system/
systemctl enable --now tor-exits.timer
```

The IOC matching for IPs, domains and hashes (the rest of the `threat_intel` logic) is already
handled by [ioc-export](../ioc-export/README.md), which feeds `etc/lists/cti-ips` and `cti-domains`
from MISP and OpenCTI. Enrichment (VirusTotal and friends) is handled in Cortex and Hermes.
