#!/bin/bash
# CAPEv2 host install on Ubuntu 24.04 (VM 117). Run as root.
# Needs: nested KVM, CPU type host (MongoDB needs AVX).
set -euo pipefail
exec > >(tee -a /var/log/cape-install.log) 2>&1
export DEBIAN_FRONTEND=noninteractive
PGPASS="${PGPASS:?set PGPASS}"

apt-get update -qq
apt-get install -y -qq git qemu-kvm libvirt-daemon-system libvirt-clients libvirt-dev virtinst \
  genisoimage pkg-config python3-dev locate jq >/dev/null
systemctl enable --now libvirtd
ls /dev/kvm

# Isolated host-only network for the analysis guest (no internet)
if ! virsh net-info cape >/dev/null 2>&1; then
  cat > /tmp/cape-net.xml <<'X'
<network>
  <name>cape</name>
  <bridge name='virbr1' stp='on' delay='0'/>
  <ip address='192.168.56.1' netmask='255.255.255.0'/>
</network>
X
  virsh net-define /tmp/cape-net.xml
  virsh net-autostart cape
  virsh net-start cape
fi
virsh net-autostart --disable default 2>/dev/null || true
virsh net-destroy default 2>/dev/null || true

# CAPE
cd /opt
[ -d CAPEv2 ] || git clone -q https://github.com/kevoreilly/CAPEv2.git
cd CAPEv2/installer
sed -i "s/^NETWORK_IFACE=.*/NETWORK_IFACE=virbr1/; s/^IFACE_IP=.*/IFACE_IP=\"192.168.56.1\"/; s/^PASSWD=.*/PASSWD=\"$PGPASS\"/" cape2.sh
bash cape2.sh base 192.168.56.1
echo "cape2 base done"
