# Kubernetes

| Item | Value |
|---|---|
| VM | 115 `k8s-01`, VLAN 40, 4 cores, 6 GB RAM, CPU type `x86-64-v2-AES` |
| Group | k8s (`lab-profile k8s start`) |
| Cluster | MicroK8s, single node (`sudo microk8s kubectl get pods -A`) |

Running in the cluster: Falco (modern eBPF driver), Falcosidekick, Fluent Bit, Trivy operator, Calico, CoreDNS, hostpath provisioner, metrics-server.

## Falco to Wazuh

| Piece | Where | What it does |
|---|---|---|
| Falco file output | `/var/log/falco/events.json` on the node (hostPath) | One JSON line per Falco alert |
| Wazuh agent | k8s-01 | Ships `events.json` plus auditd |
| Wazuh rules 100380 to 100383 | [siem/wazuh](../../siem/wazuh/README.md) | Notice = level 5, Warning = 8, Error and above = 12 |

Falco needs a CPU with x86-64-v2. On the old `kvm64` CPU type its init container fails and Falco never starts.

Test it:

```bash
sudo microk8s kubectl run falco-test --image=busybox:1.36 --restart=Never -- sleep 120
sudo microk8s kubectl exec falco-test -- cat /etc/shadow      # "Read sensitive file untrusted" in Wazuh
sudo microk8s kubectl delete pod falco-test
```

## Planned Falco rules

| Rule | MITRE |
|---|---|
| Privileged container spawned | T1611 |
| kubectl exec into a running pod | T1609 |
| Unexpected outbound connection | T1071 |
