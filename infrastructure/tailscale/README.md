# Tailscale

Tailscale runs on the Proxmox host for remote access to the Proxmox UI and the lab.

The host advertises these lab routes (approved in the Tailscale admin console):

| Route | VLAN |
|---|---|
| SOC | 10 |
| Victim | 20 |
| Attacker | 30 |
| Servers | 40 |
| Malware | 99 |

The attacker and malware VLANs are reachable from the tailnet so Kali, CAPE and FLARE-VM can be used remotely. pfSense stops both from opening connections back out, so this is one-way.

The host must forward IPv4 for the advertised routes to work. It is set in two places so a network reload cannot turn it off: `net.ipv4.ip_forward = 1` in sysctl, and `ip-forward on` on the SOC VLAN interface in `/etc/network/interfaces`.
