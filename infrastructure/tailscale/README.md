# Tailscale

Tailscale runs on the Proxmox host for remote access to the Proxmox UI.

To reach lab VMs over Tailscale, advertise the lab routes from the host and approve them in the Tailscale admin console. Keep the attack and malware VLANs off Tailscale.

The host must forward IPv4 for the advertised routes to work. It is set in two places so a network reload cannot turn it off: `net.ipv4.ip_forward = 1` in sysctl, and `ip-forward on` on the SOC VLAN interface in `/etc/network/interfaces`.
