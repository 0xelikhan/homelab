#!/bin/bash
# Run on the Proxmox host. Checks the always-on CTI stack and every scheduled job.
echo "== health check"
/usr/local/bin/lab-health --dry-run 2>&1 | grep -vE "^ok" ; echo "passing: $(/usr/local/bin/lab-health --dry-run 2>&1 | grep -c '^ok')"

echo "== backups (last run per VM)"
for f in /mnt/sandisk-1tb/dump /mnt/ssd-enclosure/dump; do ls -t $f/*.vma.zst $f/*.tar.zst 2>/dev/null; done \
  | sed -E 's/.*vzdump-(qemu|lxc)-([0-9]+)-([0-9_]+)-.*/\2 \3/' | sort -u -k1,1 | awk '{printf "%s:%s ", $1, $2} END{print ""}'
grep -lE "ERROR" /var/log/vzdump/*.log 2>/dev/null | head -3
pvesh get /cluster/backup --output-format json | python3 -c "import sys,json;[print(' job',j['id'],j['schedule'],'enabled' if j.get('enabled',1) else 'DISABLED') for j in json.load(sys.stdin)]"

echo "== timers"
systemctl list-timers --no-pager | grep -E "ioc-export|lab-health" | awk '{print "  "$NF, "next", $1, $2, $3, "last", $(NF-3), $(NF-2)}'
python3 -c "import json;d=json.load(open('/var/lib/ioc-export/status.json'));print('  ioc-export:',d)"

echo "== hermes"
pct exec 120 -- su - hermes -c "hermes gateway status 2>&1 | grep -iE 'running' | head -1; hermes cron list 2>&1 | grep -E 'Name:|Last run:|Next run:'" | sed 's/^/  /'
pct exec 120 -- systemctl show cti-collector.service -p Result -p ExecMainExitTimestamp --value | tr '\n' ' '; echo
pct exec 120 -- python3 -c "
import sqlite3
c=sqlite3.connect('file:/srv/intel/intel.db?mode=ro',uri=True)
for s,n,m in c.execute(\"select source,count(*),max(collected) from items where collected > datetime('now','-1 day') group by source\"): print('  last 24h', s, n, 'newest', m)"
pct exec 120 -- su - hermes -c "cve-status CVE-2021-44228 | python3 -c 'import sys,json;r=json.load(sys.stdin)[\"results\"][0];print(\"  cve-status:\",r[\"cve\"],\"KEV\",r[\"kev\"],\"EPSS\",r[\"epss\"])'"
