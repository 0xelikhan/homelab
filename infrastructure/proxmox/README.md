# Proxmox Hypervisor

Proxmox VE 8.x on a Lenovo ThinkCentre with 32GB RAM. VLAN-aware bridge (vmbr0) means each VM is assigned to a VLAN by tag at creation — no separate physical interfaces needed.

- Host IP: 192.168.1.10 | Web UI: https://192.168.1.10:8006
- Free community repo (paid enterprise repo disabled)
- Open vSwitch not used — native VLAN-aware bridge is simpler and sufficient

## Screenshots
<!-- Add after build -->
![Proxmox summary page](screenshots/proxmox-summary.png)
![VM list showing all 20 VMs](screenshots/proxmox-vm-list.png)
![vmbr0 with VLAN aware enabled](screenshots/vmbr0-vlan-aware.png)
