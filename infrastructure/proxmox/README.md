# Proxmox

Proxmox VE 9.2 host. Setup scripts and per-VM installers live on the host, not in this repo.

## Lab groups

32 GB RAM cannot run every VM. VMs are grouped. `core` is always on, the rest are started for an exercise and stopped after. Script: [lab-profile.sh](lab-profile.sh), installed on the host as `lab-profile`.

```bash
lab-profile status              # every group, every VM, free host RAM
lab-profile <group> start       # checks free RAM first and asks if it will not fit
lab-profile <group> stop        # clean shutdown, forced after 120s
```

| Group | Machines | Use it for |
|---|---|---|
| core | pfSense, Wazuh, Velociraptor, ElastAlert, DFIR-IRIS, web-01, n8n, MISP, TheHive/OpenCTI/Cortex, OpenCanary, Hermes | Always on |
| attack | Kali, DC01, Metasploitable2 | Running attacks and checking detections |
| k8s | k8s-01 | Kubernetes, Falco, Trivy |

Rule of thumb: core plus one group. To switch, stop one first:

```bash
lab-profile attack stop
lab-profile k8s start
```

## Boot order

Only core machines start with the host: pfSense first, then Wazuh, then the rest of core, then the LXCs. Other groups stay off after a reboot.

## Memory

| Setting | Value |
|---|---|
| VM 112 (OpenCTI, TheHive, Cortex) | 16 GB plus a 4 GB swap file inside |
| Ballooning (host can reclaim) | Velociraptor, DFIR-IRIS, web-01, Kali, n8n |
| No ballooning | Wazuh, MISP, VM 112, OpenCanary |

## CPU type

New and rebuilt VMs use `x86-64-v2-AES`. The old default `kvm64` hides SSE4.2 and breaks modern images (MinIO/Silo, Security Onion 2.4).

```bash
qm set <vmid> --cpu x86-64-v2-AES
```
