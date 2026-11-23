#!/bin/bash
# verify.sh — Lab health check. Run from Proxmox host or any host with access.
# Usage: bash verify.sh [--quick]

set -uo pipefail
QUICK=${1:-}
PASS=0; FAIL=0; SKIP_COUNT=0

C_GREEN='\033[0;32m'; C_RED='\033[0;31m'; C_YELLOW='\033[1;33m'; C_CYAN='\033[0;36m'; NC='\033[0m'

ok()   { echo -e " ${C_GREEN}✓${NC}  $*"; ((PASS++)); }
fail() { echo -e " ${C_RED}✗${NC}  $*"; ((FAIL++)); }
skip() { echo -e " ${C_YELLOW}~${NC}  $*"; ((SKIP_COUNT++)); }
hdr()  { echo -e "\n${C_CYAN}── $* ──${NC}"; }

check_ping() {
  local name=$1 ip=$2
  ping -c1 -W2 "$ip" &>/dev/null && ok "$name ($ip) reachable" || fail "$name ($ip) unreachable"
}

check_tcp() {
  local name=$1 ip=$2 port=$3
  timeout 3 bash -c "echo > /dev/tcp/$ip/$port" 2>/dev/null \
    && ok "$name ${ip}:${port} open" \
    || fail "$name ${ip}:${port} not responding"
}

check_http() {
  local name=$1 url=$2 expect_code=${3:-200}
  code=$(curl -sk -o /dev/null -w "%{http_code}" --connect-timeout 5 "$url" 2>/dev/null)
  [[ "$code" == "$expect_code" || "$code" =~ ^[23] ]] \
    && ok "$name → $url (HTTP $code)" \
    || fail "$name → $url (HTTP $code, expected $expect_code)"
}

check_service() {
  local name=$1 svc=$2 ip=$3
  ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -o BatchMode=yes root@"$ip" \
    "systemctl is-active --quiet $svc 2>/dev/null" 2>/dev/null \
    && ok "$name: $svc active" \
    || fail "$name: $svc not running"
}

echo ""
echo "╔══════════════════════════════════════╗"
echo "║   Home Lab Health Check              ║"
echo "║   $(date '+%Y-%m-%d %H:%M')                   ║"
echo "╚══════════════════════════════════════╝"

# ── PROXMOX ───────────────────────────────────────────────────────────────────
hdr "PROXMOX HOST"
check_ping "Proxmox host" "192.168.68.10"
check_tcp  "Proxmox Web"  "192.168.68.10" "8006"

# Check VM states
for VM in 100 101 102 103 104 105 106 107 108 109 110 111 112 113 114 115 116 117 118 124; do
  STATE=$(qm status "$VM" 2>/dev/null | awk '{print $2}')
  if [[ -z "$STATE" ]]; then skip "VM $VM not created"
  elif [[ "$STATE" == "running" ]]; then ok "VM $VM running"
  else fail "VM $VM state: $STATE"; fi
done

# ── NETWORK ──────────────────────────────────────────────────────────────────
hdr "NETWORK / pfSense"
check_ping "pfSense LAN"    "192.168.68.1"
check_tcp  "pfSense WebGUI" "192.168.68.1" "443"
check_ping "VLAN10 gateway" "10.10.10.1"
check_ping "VLAN20 gateway" "10.10.20.1"
check_ping "VLAN30 gateway" "10.10.30.1"
check_ping "VLAN40 gateway" "10.10.40.1"
check_ping "VLAN99 gateway" "10.10.99.1"

# ── SECURITY STACK ────────────────────────────────────────────────────────────
hdr "SECURITY MONITORING (VLAN 10)"
check_ping "Wazuh"          "10.10.10.10"
check_http "Wazuh Dashboard" "https://10.10.10.10" "200"
[[ -z "$QUICK" ]] && check_service "Wazuh" "wazuh-manager" "10.10.10.10"
[[ -z "$QUICK" ]] && check_service "Wazuh" "wazuh-indexer"  "10.10.10.10"

check_ping "Velociraptor"   "10.10.10.11"
check_tcp  "Velociraptor"   "10.10.10.11" "8889"

check_ping "n8n"            "10.10.10.12"
check_http "n8n"            "http://10.10.10.12:5678"

check_ping "ElastAlert"     "10.10.10.13"
[[ -z "$QUICK" ]] && check_service "ElastAlert" "elastalert" "10.10.10.13"

check_ping "DFIR-IRIS"      "10.10.10.14"
check_http "DFIR-IRIS"      "https://10.10.10.14"

check_ping "Graylog"        "10.10.10.20"
check_http "Graylog"        "http://10.10.10.20:9000"

check_ping "MISP"           "10.10.10.21"
check_http "MISP"           "https://10.10.10.21"

check_ping "TheHive"        "10.10.10.22"
check_http "TheHive"        "http://10.10.10.22:9000"

check_ping "Splunk"         "10.10.10.25"
check_http "Splunk"         "http://10.10.10.25:8000"

# ── WINDOWS DOMAIN ────────────────────────────────────────────────────────────
hdr "WINDOWS DOMAIN (VLAN 20)"
check_ping "DC01"           "10.10.20.10"
check_tcp  "DC01 RDP"       "10.10.20.10" "3389"
check_tcp  "DC01 LDAP"      "10.10.20.10" "389"
check_tcp  "DC01 SMB"       "10.10.20.10" "445"
check_tcp  "DC01 DNS"       "10.10.20.10" "53"
check_ping "win-victim"     "10.10.20.20"
check_tcp  "Victim RDP"     "10.10.20.20" "3389"
check_tcp  "Victim WinRM"   "10.10.20.20" "5985"
check_ping "Metasploitable" "10.10.20.50"
check_tcp  "Metasploitable FTP" "10.10.20.50" "21"
check_tcp  "Metasploitable SSH" "10.10.20.50" "22"
check_ping "OpenCanary"     "10.10.20.99"
check_tcp  "OpenCanary SSH" "10.10.20.99" "22"
check_tcp  "OpenCanary HTTP" "10.10.20.99" "80"

# ── RED TEAM ─────────────────────────────────────────────────────────────────
hdr "RED TEAM (VLAN 30)"
check_ping "Kali"           "10.10.30.10"
check_tcp  "CALDERA"        "10.10.30.10" "8888"

# ── WEB / DMZ ────────────────────────────────────────────────────────────────
hdr "WEB / DMZ (VLAN 40)"
check_ping "web-01"         "10.10.40.10"
check_http "DVWA"           "http://10.10.40.10/dvwa"
check_http "WebGoat"        "http://10.10.40.10:8080"
check_ping "k8s-01"         "10.10.40.20"

# ── SECURITY ONION ────────────────────────────────────────────────────────────
hdr "SECURITY ONION (VLAN 50)"
check_ping "Security Onion" "10.10.50.10"
check_http "Security Onion" "https://10.10.50.10"

# ── ISOLATED / MALWARE ────────────────────────────────────────────────────────
hdr "ISOLATED (VLAN 99)"
check_ping "FLARE-VM"       "10.10.99.10"
check_tcp  "FLARE RDP"      "10.10.99.10" "3389"
check_ping "Cuckoo"         "10.10.99.11"
check_http "Cuckoo Web"     "http://10.10.99.11:8080"

# ── SUMMARY ──────────────────────────────────────────────────────────────────
TOTAL=$((PASS + FAIL + SKIP_COUNT))
echo ""
echo "══════════════════════════════════════════"
printf " ${C_GREEN}✓ PASS${NC}: %-4d  ${C_RED}✗ FAIL${NC}: %-4d  ${C_YELLOW}~ SKIP${NC}: %d\n" $PASS $FAIL $SKIP_COUNT
echo " Total checks: $TOTAL"
echo "══════════════════════════════════════════"
if [[ $FAIL -eq 0 ]]; then
  echo -e " ${C_GREEN}All checks passed!${NC}"
else
  echo -e " ${C_RED}$FAIL check(s) failed.${NC} Check the VMs/services above."
fi
echo ""
exit $([[ $FAIL -eq 0 ]] && echo 0 || echo 1)
