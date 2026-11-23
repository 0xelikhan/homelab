#!/bin/bash
echo "=== Fixing snippets ==="
mkdir -p /var/lib/vz/snippets
cp /var/lib/pve/snippets/*.yaml /var/lib/vz/snippets/
echo "  Snippets copied"

echo "=== Starting VMs ==="
for VM in 109 110 111 112 113 115 117 118; do
  qm start $VM 2>&1 && echo "  Started $VM" || echo "  Failed $VM"
  sleep 2
done

echo "=== Resizing disks ==="
for VM in 115 117; do
  qm disk resize $VM scsi0 60G && echo "  Resized VM $VM to 60G" || echo "  Resize failed VM $VM"
done
qm disk resize 118 scsi0 8G && echo "  Resized VM 118 to 8G" || echo "  Resize failed VM 118"

echo "=== Fixing VM 124 VLAN tag ==="
NET=$(qm config 124 | grep '^net0:' | cut -d: -f2- | sed 's/,tag=[0-9]*//')
qm set 124 --net0 "${NET},tag=20" && echo "  VM 124 VLAN set to 20" || echo "  Could not fix VM 124 VLAN — set manually in UI"

echo ""
echo "Done. VMs 109-118 are booting — cloud-init will install everything automatically."
echo "Check progress: tail -f /var/log/lab-build.log"
echo ""
echo "Next: configure pfSense VLANs (see MANUAL.md), then re-run build.sh to SSH into existing VMs."
