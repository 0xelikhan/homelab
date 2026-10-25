#!/usr/bin/env bash
# lab-profile.sh - start/stop groups of lab VMs on pve (32 GB host can't run everything)
# Usage: lab-profile.sh <profile> <start|stop|status>
#        lab-profile.sh status
set -uo pipefail

declare -A PROFILES=(
  [core]="100 101 102 103 104 106 109 111 112 118 120"   # always on (onboot=1)
  [attack]="107 105 108"                             # kali, win-dc01, metasploitable2
  [malware]="116 117"                                # flare-vm, cuckoo (VLAN 99)
  [k8s]="115"                                        # k8s-01
  [siem]="110 113"                                   # graylog, splunk
  [nsm]="114"                                        # security-onion
)

is_ct() { pct status "$1" &>/dev/null; }

vm_do() {
  local action=$1 id=$2
  if is_ct "$id"; then
    case $action in
      start) pct start "$id" ;;
      stop)  pct shutdown "$id" --timeout 120 ;;
    esac
  else
    case $action in
      start) qm start "$id" ;;
      stop)  qm shutdown "$id" --timeout 120 --forceStop 1 ;;
    esac
  fi
}

status_all() {
  for p in core attack malware k8s siem nsm; do
    printf "%-8s" "$p"
    for id in ${PROFILES[$p]}; do
      if is_ct "$id"; then s=$(pct status "$id" | awk '{print $2}'); n=$(pct config "$id" | awk '/^hostname:/{print $2}')
      else s=$(qm status "$id" | awk '{print $2}'); n=$(qm config "$id" | awk '/^name:/{print $2}'); fi
      printf " %s(%s)=%s" "$id" "$n" "$s"
    done
    echo
  done
  free -g | awk 'NR==2{printf "host RAM: %sG used, %sG available\n", $3, $7}'
}

[ "${1:-}" = "status" ] && { status_all; exit 0; }
profile=${1:-}; action=${2:-}
[ -n "${PROFILES[$profile]:-}" ] && [[ "$action" =~ ^(start|stop|status)$ ]] || {
  echo "Usage: $0 <${!PROFILES[*]}> <start|stop|status> | $0 status"; exit 1; }

[ "$action" = status ] && { status_all; exit 0; }

if [ "$action" = start ]; then
  avail=$(free -m | awk 'NR==2{print $7}')
  need=0
  for id in ${PROFILES[$profile]}; do
    is_ct "$id" && continue
    need=$((need + $(qm config "$id" | awk '/^memory:/{print $2}')))
  done
  if [ "$need" -gt "$avail" ]; then
    echo "[WARN] $profile needs ~${need}MB, host has ${avail}MB available."
    echo "       Stop another profile first (e.g. $0 attack stop), or continue anyway? [y/N]"
    read -r ans; [ "$ans" = y ] || exit 1
  fi
fi

for id in ${PROFILES[$profile]}; do
  echo "  $action $id"
  vm_do "$action" "$id" || echo "  [WARN] $action $id failed"
done
status_all
