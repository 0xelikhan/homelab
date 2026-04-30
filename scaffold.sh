#!/bin/bash
# Run from inside your cloned homelab repo:
#   git clone git@github.com:YOUR-USERNAME/homelab.git
#   cd homelab && bash scaffold.sh

set -e
echo "Scaffolding homelab..."

mkdir -p architecture/screenshots
mkdir -p infrastructure/proxmox/screenshots
mkdir -p infrastructure/ansible/{playbooks,roles,inventory}
mkdir -p infrastructure/active-directory/screenshots
mkdir -p infrastructure/kubernetes/screenshots
mkdir -p infrastructure/tailscale/screenshots
mkdir -p siem/wazuh/screenshots
mkdir -p siem/graylog/screenshots
mkdir -p siem/elastalert/screenshots
mkdir -p network/pfsense-suricata/screenshots
mkdir -p network/security-onion-zeek/screenshots
mkdir -p network/wireshark/screenshots
mkdir -p dfir/velociraptor/screenshots
mkdir -p dfir/dfir-iris/screenshots
mkdir -p dfir/thehive-cortex/screenshots
mkdir -p dfir/malware-analysis/screenshots
mkdir -p threat-intel/misp/screenshots
mkdir -p threat-intel/n8n-soar/screenshots
mkdir -p adversary-simulation/atomic-red-team/screenshots
mkdir -p adversary-simulation/caldera/screenshots
mkdir -p adversary-simulation/metasploit/screenshots
mkdir -p adversary-simulation/ad-attacks/screenshots
mkdir -p endpoint-visibility/osquery/screenshots
mkdir -p deception/opencanary/screenshots
mkdir -p deception/canarytokens/screenshots
mkdir -p web-app/screenshots

# gitkeep all screenshot folders
find . -name "screenshots" -type d | while read d; do
  touch "$d/.gitkeep"
done

echo "Done."
echo ""
echo "Next: git add . && git commit -m 'Scaffold homelab repo' && git push"
