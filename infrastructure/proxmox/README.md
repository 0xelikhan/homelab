# Proxmox

Proxmox VE 9.2 host. Setup scripts and per-VM installers live on the host, not in this repo.

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

## Hookscripts

VMs 100 and 114 run `nsm-mirror-hook.sh` after start to rebuild the port mirror. See [network/nsm-sensor](../../network/nsm-sensor/README.md).

## Memory

| Setting | Value |
|---|---|
| VM 112 (OpenCTI, TheHive, Cortex) | 16 GB plus a 4 GB swap file inside |
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
