#!/usr/bin/env bash
# Fetch the current Tor exit-node list and write it as a Wazuh CDB list.
# Runs on the Wazuh manager on a timer. Ported from the secops-detection-rules
# threat_intel YARA-L "Tor exit node contact" detections.
set -euo pipefail

LIST=/var/ossec/etc/lists/tor-exit-nodes
SRC="https://check.torproject.org/torbulkexitlist"   # official bulk exit list

tmp=$(mktemp)
if ! curl -fsS --max-time 60 "$SRC" -o "$tmp"; then
    echo "failed to fetch Tor exit list" >&2
    rm -f "$tmp"; exit 1
fi

# CDB format: one "ip:" key per line. Keep only valid IPv4 lines.
grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$' "$tmp" | sed 's/$/:/' > "${LIST}.new"
count=$(wc -l < "${LIST}.new")
if [ "$count" -lt 100 ]; then
    echo "only $count exits, refusing to overwrite (source may be down)" >&2
    rm -f "$tmp" "${LIST}.new"; exit 1
fi

mv "${LIST}.new" "$LIST"
/var/ossec/bin/wazuh-analysisd -t >/dev/null 2>&1 || true
# Recompile CDB lists and reload rules.
/var/ossec/bin/ossec-makelists || /var/ossec/bin/wazuh-analysisd -t
systemctl reload wazuh-manager 2>/dev/null || systemctl restart wazuh-manager
rm -f "$tmp"
echo "wrote $count Tor exit nodes to $LIST"
