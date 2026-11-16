#!/bin/bash
# Run on the Proxmox host after `lab-profile attack start`.
K="-i /root/.ssh/lab_ed25519 -o BatchMode=yes -o ConnectTimeout=10"
for i in $(seq 1 30); do timeout 3 bash -c "</dev/tcp/10.10.40.10/22" 2>/dev/null && break; sleep 5; done
echo "== web-01"
ssh $K labadmin@10.10.40.10 'for u in apache2 wazuh-agent; do printf "%s=%s " $u $(systemctl is-active $u); done; echo
  curl -s -o /dev/null -w "local web %{http_code}\n" http://127.0.0.1/
  sudo apache2ctl -M 2>/dev/null | grep -i security'
echo "== from kali"
ssh $K kali@10.10.30.100 'curl -s -m5 -o /dev/null -w "kali to web-01 %{http_code}\n" http://10.10.40.10/
  curl -s -m5 -o /dev/null -w "kali to web-01 with SQLi probe %{http_code}\n" "http://10.10.40.10/?id=1%27%20OR%201=1--"
  echo "victim VLAN hosts: $(nmap -sn -n 10.10.20.0/24 2>/dev/null | grep -oE "10\.10\.20\.[0-9]+" | tr "\n" " ")"'
