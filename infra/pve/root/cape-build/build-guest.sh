#!/bin/bash
# Build the Windows analysis guest inside VM 117 and take the clean snapshot. Run as root.
# Needs /var/lib/libvirt/images/win.iso (Windows Server 2022 eval) and /root/cape-guest/{autounattend.xml,guest-setup.ps1}
set -euo pipefail
G=cape-win
IMG=/var/lib/libvirt/images
PYV=3.12.10
cd /root/cape-guest
[ -f python-x86.exe ] || curl -fsSL -o python-x86.exe https://www.python.org/ftp/python/$PYV/python-$PYV.exe
cp /opt/CAPEv2/agent/agent.py .
genisoimage -quiet -J -r -V CAPEANS -o $IMG/cape-answer.iso autounattend.xml guest-setup.ps1 agent.py python-x86.exe

if ! virsh dominfo $G >/dev/null 2>&1; then
  ( for i in $(seq 1 90); do sleep 1; virsh send-key $G KEY_ENTER >/dev/null 2>&1; done ) &
  virt-install --name $G --memory 2048 --vcpus 2 --cpu host-passthrough \
    --disk path=$IMG/$G.qcow2,size=40,format=qcow2,bus=sata \
    --cdrom $IMG/win.iso --disk path=$IMG/cape-answer.iso,device=cdrom,bus=sata \
    --network network=cape,model=e1000,mac=52:54:00:ca:fe:01 \
    --os-variant win2k22 --boot firmware=bios --graphics vnc,listen=127.0.0.1 \
    --noautoconsole --wait=-1
fi
# guest-setup.ps1 shuts the guest down when done
virsh domstate $G
# Remove install media, boot, wait for the agent, snapshot running state
for t in sda sdb sdc; do virsh change-media $G $t --eject --config 2>/dev/null || true; done
virsh start $G
for i in $(seq 1 60); do curl -s -m 3 http://192.168.56.101:8000/ >/dev/null && break; sleep 10; done
curl -s -m 3 http://192.168.56.101:8000/ | head -c 200; echo
sleep 60
virsh snapshot-create-as $G clean --description "agent running"
virsh shutdown $G || true
echo "guest ready"
