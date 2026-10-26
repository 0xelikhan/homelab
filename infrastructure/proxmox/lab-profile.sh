#!/usr/bin/env bash
# lab-profile - start/stop groups of lab VMs (32 GB host can't run everything)
# Usage: lab-profile <group> <start|stop>
#        lab-profile status
#        lab-profile reset          stop everything except cti
set -uo pipefail

declare -A PROFILES=(
  [cti]="100 111 112 120"                    # always on (onboot=1): pfsense, misp, opencti/thehive/cortex, hermes
  [soc]="101 102 103 104 109 118"            # wazuh, velociraptor, elastalert, dfir-iris, n8n, opencanary
  [purple]="101 102 105 107 121"             # wazuh, velociraptor, win-dc01, kali, attack-tools
  [attack]="107 105 108 106 121"             # kali, win-dc01, metasploitable2, web-01, attack-tools
  [malware]="116 117"                        # flare-vm, cape (VLAN 99)
  [k8s]="115"                                # k8s-01
  [nsm]="114"                                # nsm-sensor (Zeek + Suricata)
)
ORDER="cti soc purple attack malware k8s nsm"

is_ct() { pct status "$1" &>/dev/null; }

vm_do() {
  local action=$1 id=$2
  if is_ct "$id"; then
    case $action in
      start) pct start "$id" ;;
      stop)  pct shutdown "$id" --timeout 120 --forceStop 1 ;;
    esac
  else
    case $action in
      start) qm start "$id" ;;
      stop)  qm shutdown "$id" --timeout 120 --forceStop 1 ;;
    esac
  fi
}

running() {
  if is_ct "$1"; then pct status "$1" | grep -q running; else qm status "$1" | grep -q running; fi
}

status_all() {
  for p in $ORDER; do
    printf "%-8s" "$p"
    for id in ${PROFILES[$p]}; do
      if is_ct "$id"; then s=$(pct status "$id" | awk '{print $2}'); n=$(pct config "$id" | awk '/^hostname:/{print $2}')
      else s=$(qm status "$id" 2>/dev/null | awk '{print $2}'); n=$(qm config "$id" 2>/dev/null | awk '/^name:/{print $2}'); fi
      printf " %s(%s)=%s" "$id" "$n" "$s"
    done
    echo
  done
  free -g | awk 'NR==2{printf "host RAM: %sG used, %sG available\n", $3, $7}'
}

case "${1:-}" in
  status) status_all; exit 0 ;;
  reset)
    for p in $ORDER; do
      [ "$p" = cti ] && continue
      for id in ${PROFILES[$p]}; do
        running "$id" && { echo "  stop $id"; vm_do stop "$id" & }
      done
    done
    wait; status_all; exit 0 ;;
esac

profile=${1:-}; action=${2:-}
[ -n "${PROFILES[$profile]:-}" ] && [[ "$action" =~ ^(start|stop|status)$ ]] || {
  echo "Usage: $0 <$ORDER> <start|stop> | $0 status | $0 reset"; exit 1; }

[ "$action" = status ] && { status_all; exit 0; }

if [ "$action" = start ]; then
  avail=$(free -m | awk 'NR==2{print $7}')
  need=0
  for id in ${PROFILES[$profile]}; do
    running "$id" && continue
    if is_ct "$id"; then m=$(pct config "$id" | awk '/^memory:/{print $2}')
    else m=$(qm config "$id" | awk '/^memory:/{m=$2} /^balloon:/{b=$2} END{print (b>0 ? b : m)}'); fi
    need=$((need + ${m:-0}))
  done
  if [ "$need" -gt "$avail" ]; then
    echo "[WARN] $profile needs ~${need}MB, host has ${avail}MB available."
    echo "       Stop another group first (or: $0 reset), or continue anyway? [y/N]"
    read -r ans; [ "$ans" = y ] || exit 1
  fi
fi

for id in ${PROFILES[$profile]}; do
  if [ "$action" = start ] && running "$id"; then echo "  $id already running"; continue; fi
  if [ "$action" = stop ] && ! running "$id"; then continue; fi
  echo "  $action $id"
  vm_do "$action" "$id" || echo "  [WARN] $action $id failed"
done
status_all
