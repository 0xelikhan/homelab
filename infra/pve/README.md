# infra/pve

Hand-written management and build scripts from the Proxmox host (`/root` and
`/opt`). Mirrors their on-host layout under `root/` and `opt/`.

- `root/cti-sweep.sh`, `root/soc-check.sh`, `root/attack-check.sh` — periodic lab checks.
- `root/initial-backups.sh`, `root/azure-sentinel-reclone.sh` — backup / re-clone helpers.
- `root/cape-build/`, `root/velociraptor/` — guest build and client-install scripts.
- `root/vlan-test.sh`, `root/whonix-guard-test.sh` — network/isolation checks.
- `opt/fix.sh`, `opt/lab-build/verify.sh` — lab build verification.

## Not in git

- Secrets: `lab-secrets.env`, `.homelable-pve-token`, `.ssh`, `.gnupg` — stay on the host.
- `/opt/lab-build/build.sh` and `proxmox-build.sh` — version-worthy but hardcode the
  shared lab VM password; externalize it to `lab-secrets.env` first, then add them here.
