#!/bin/bash
# Run on the Proxmox host. Prints PASS/FAIL for each expected path through pfSense.
K="-i /root/.ssh/lab_ed25519 -o BatchMode=yes -o ConnectTimeout=8"
t() {  # host  description  remote-test  expect(open|closed)
  r=$(ssh $K "$1" "$3" 2>/dev/null && echo open || echo closed)
  [ "$r" = "$4" ] && s=PASS || s=FAIL
  printf "%s  %-55s %s\n" "$s" "$2" "$r"
}
tcp() { echo "timeout 4 bash -c '</dev/tcp/$1/$2'"; }
web() { echo "curl -s -m6 -o /dev/null https://github.com"; }

V=ubuntu@10.10.20.99     # honeypot, victim VLAN (real sshd on 2222 via ssh config)
S=labadmin@10.10.40.10   # web-01, servers VLAN
A=kali@10.10.30.100      # kali, attacker VLAN

t "$V" "victim  -> internet"                       "$(web)"                      open
t "$V" "victim  -> Wazuh agent port"               "$(tcp 10.10.10.10 1514)"     open
t "$V" "victim  -> Velociraptor client port"       "$(tcp 10.10.10.11 8000)"     open
t "$V" "victim  -> Wazuh dashboard (blocked)"      "$(tcp 10.10.10.10 443)"      closed
t "$V" "victim  -> MISP (blocked)"                 "$(tcp 10.10.10.21 443)"      closed
t "$V" "victim  -> web-01 (blocked)"               "$(tcp 10.10.40.10 80)"       closed
t "$V" "victim  -> home network (blocked)"         "$(tcp 192.168.68.1 80)"      closed
t "$V" "victim  -> attacker VLAN"                  "$(tcp 10.10.30.100 22)"      open
t "$S" "servers -> internet"                       "$(web)"                      open
t "$S" "servers -> Wazuh agent port"               "$(tcp 10.10.10.10 1514)"     open
t "$S" "servers -> OpenCTI (blocked)"              "$(tcp 10.10.10.22 8080)"     closed
t "$S" "servers -> victim VLAN (blocked)"          "$(tcp 10.10.20.99 21)"       closed
t "$A" "attacker -> internet"                      "$(web)"                      open
t "$A" "attacker -> victim VLAN"                   "$(tcp 10.10.20.99 21)"       open
t "$A" "attacker -> servers VLAN"                  "$(tcp 10.10.40.10 80)"       open
t "$A" "attacker -> SOC VLAN (blocked)"            "$(tcp 10.10.10.21 443)"      closed
t "$A" "attacker -> home network (blocked)"        "$(tcp 192.168.68.1 80)"      closed
t "$A" "attacker -> malware VLAN (blocked)"        "$(tcp 10.10.99.11 8000)"     closed
# management from the SOC side still works
r=$(timeout 5 bash -c '</dev/tcp/10.10.30.100/22' 2>/dev/null && echo open || echo closed); echo "$([ $r = open ] && echo PASS || echo FAIL)  host -> kali ssh (SOC side management)                     $r"
r=$(timeout 5 bash -c '</dev/tcp/10.10.40.10/22' 2>/dev/null && echo open || echo closed); echo "$([ $r = open ] && echo PASS || echo FAIL)  host -> web-01 ssh                                         $r"
