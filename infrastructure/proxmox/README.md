# Proxmox

Proxmox VE 9.2 host on Debian 13 (trixie). Setup scripts and per-VM installers live on the host, not in this repo.

Updates come from the Proxmox `pve-no-subscription` repository for trixie (`/etc/apt/sources.list.d/proxmox.sources`) plus Debian's main and security repositories. Apply with `apt update && apt full-upgrade`. A new kernel takes effect after a reboot.

## Lab groups

32 GB RAM cannot run every VM. VMs are grouped. `cti` is always on, the rest are started for an exercise and stopped after. Script: [lab-profile.sh](lab-profile.sh), installed on the host as `lab-profile`.

```bash
lab-profile status              # every group, every VM, free host RAM
lab-profile <group> start       # checks free RAM first and asks if it will not fit
lab-profile <group> stop        # clean shutdown, forced after 120s
lab-profile reset               # stop everything except cti
```

| Group | Machines | Use it for |
|---|---|---|
| cti | pfSense, MISP, OpenCTI/TheHive/Cortex, Hermes | Always on |
| soc | Wazuh, Velociraptor, ElastAlert, DFIR-IRIS, n8n, OpenCanary | SIEM, hunting, forensics, honeypots |
| purple | Wazuh, Velociraptor, DC01, Kali, attack-tools | Attacks with detection running |
| attack | Kali, DC01, Metasploitable2, web-01, attack-tools | Offensive practice |
| malware | FLARE-VM, CAPE | Malware analysis on the isolated malware VLAN |
| k8s | k8s-01 | Kubernetes, Falco, Trivy |
| nsm | nsm-sensor | Zeek and Suricata on a mirror of pfSense's LAN |

Groups can overlap (purple shares machines with soc and attack). Starting a group skips machines already running. The RAM check counts a VM's balloon minimum when it has one.

Rule of thumb: cti plus one group. To switch, stop one first, or reset:

```bash
lab-profile reset          # everything except cti
lab-profile k8s start
```

## Boot order

Only the cti group starts with the host: pfSense first, then MISP and VM 112, then Hermes. Everything else stays off after a reboot.

## Backups

Proxmox backup jobs (Datacenter > Backup). Snapshot mode, zstd, one copy per VM (`keep-last=1`). Each VM is backed up to a different disk than the one it runs on.

| Job | When | Machines | Backup disk |
|---|---|---|---|
| cti-daily-usb1 | daily 03:00 | pfSense, Hermes | sandisk-1tb |
| cti-daily-usb2 | daily 03:15 | MISP, OpenCTI/TheHive/Cortex | ssd-enclosure |
| lab-weekly-usb1 | Sunday 04:00 | every other lab VM and LXC | sandisk-1tb |
| lab-weekly-usb2 | Sunday 04:00 | nsm-sensor | ssd-enclosure |

Restore to a new VM ID with the network unplugged, so the copy cannot clash with the original:

```bash
qmrestore /mnt/sandisk-1tb/dump/<file>.vma.zst 9100 --storage local-lvm --unique 1
qm set 9100 --net0 <model>,bridge=vmbr0,link_down=1     # repeat for every NIC, then start
```

## Hookscript

`lab-hook.sh` (snippets storage) is attached to VMs 100, 101 and 114.

| VM | After start |
|---|---|
| 100 pfSense | Rebuilds the NSM port mirror |
| 114 nsm-sensor | Rebuilds the port mirror, then pushes fresh CTI lists |
| 101 Wazuh | Pushes fresh CTI lists |

See [network/nsm-sensor](../../network/nsm-sensor/README.md) and [threat-intel/ioc-export](../../threat-intel/ioc-export/README.md).

## Timers on the host

| Timer | Every | What it does |
|---|---|---|
| `ioc-export.timer` | 4 hours | [threat-intel/ioc-export](../../threat-intel/ioc-export/README.md) |
| `lab-health.timer` | 15 minutes | [infrastructure/monitoring](../monitoring/README.md) |
| `nsm-mirror.service` | at boot | Port mirror for the NSM sensor |

## Memory

| Setting | Value |
|---|---|
| VM 112 (OpenCTI, TheHive, Cortex) | 20 GB plus a 4 GB swap file inside. OpenCTI Elasticsearch heap 4 GB (`ELASTIC_MEMORY_SIZE`), TheHive container 3 GB with `-Xmx2048M` |
| Running alongside the `cti` group | Barracuda, Homelable, FMD. Stop something before starting `k8s` (6 GB) or the attack VMs |
| Ballooning (host can reclaim) | Velociraptor, DFIR-IRIS, web-01, Kali, n8n |
| No ballooning | Wazuh, MISP, VM 112, OpenCanary, nsm-sensor, FLARE-VM, CAPE |

## CPU priority

When the host is busy, pfSense and Wazuh get CPU first. VM 112 (OpenCTI ingest is the heaviest load) yields.

| VM | cpuunits |
|---|---|
| pfSense | 200 |
| Wazuh | 150 |
| everything else | 100 (default) |
| VM 112 | 50 |

## CPU type

New and rebuilt VMs use `x86-64-v2-AES`. The old default `kvm64` hides SSE4.2 and breaks modern images (MinIO, Elasticsearch). CAPE uses `host`: it runs its own VMs (nested KVM) and MongoDB needs AVX.

```bash
qm set <vmid> --cpu x86-64-v2-AES
```
