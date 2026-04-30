# Tailscale Remote Access

Tailscale installed on the ThinkCentre (Proxmox host) as a subnet router. Advertises all six lab subnets — every VM is reachable remotely without installing Tailscale on each one.

Advertised routes: 10.10.10.0/24, 10.10.20.0/24, 10.10.30.0/24, 10.10.40.0/24, 10.10.50.0/24, 10.10.99.0/24

## Screenshots
<!-- Add after build -->
![Tailscale admin — ThinkCentre as subnet router](screenshots/tailscale-subnet-router.png)
