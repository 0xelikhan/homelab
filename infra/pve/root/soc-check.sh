#!/bin/bash
# Run on the Proxmox host after `lab-profile soc start`. One block per machine.
K="-i /root/.ssh/lab_ed25519 -o BatchMode=yes -o ConnectTimeout=10"
s() { ssh $K "$@" 2>&1; }

echo "== wazuh"
s labadmin@10.10.10.10 'for u in wazuh-manager wazuh-indexer wazuh-dashboard; do printf "%s=%s " $u $(systemctl is-active $u); done; echo
  sudo /var/ossec/bin/agent_control -l | grep -E "ID:" | sed -E "s/.*Name: ([^,]+).*, ([A-Za-z ]+)$/\1 \2/" | sort'
echo "== velociraptor"
s labadmin@10.10.10.11 'systemctl list-units --type=service --no-pager | grep -i velo | awk "{print \$1, \$3, \$4}"; ss -tln | grep -oE ":(8000|8001|8889)\b" | sort -u | tr "\n" " "; echo'
echo "== elastalert"
pct exec 103 -- bash -c 'systemctl list-units --type=service --no-pager | grep -i elastalert | awk "{print \$1, \$3, \$4}"; journalctl -u "elastalert*" --since -10min --no-pager | grep -ciE "error|exception" | sed "s/^/errors last 10 min: /"'
echo "== dfir-iris"
s labadmin@10.10.10.14 'sudo docker ps --format "{{.Names}} {{.Status}}"; curl -sk -m 10 -o /dev/null -w "web %{http_code}\n" https://127.0.0.1/'
echo "== n8n"
s ubuntu@10.10.10.12 'sudo docker ps --format "{{.Names}} {{.Status}}"; curl -s -m 10 -o /dev/null -w "web %{http_code}\n" http://127.0.0.1:5678/healthz'
echo "== opencanary / cowrie"
s ubuntu@10.10.20.99 'for u in opencanary cowrie wazuh-agent velociraptor-client; do printf "%s=%s " $u $(systemctl is-active $u 2>/dev/null); done; echo; ss -tln | grep -oE ":(21|22|23|80|3306|3389|5900|6379|2222)\b" | sort -u | tr "\n" " "; echo'
