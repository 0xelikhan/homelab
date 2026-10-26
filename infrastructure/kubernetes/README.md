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

Falco needs a CPU with x86-64-v2. On the old `kvm64` CPU type it never starts.

Falco uses the rules bundled in its image. The falcoctl rule download is turned off (`falcoctl.artifact.install.enabled=false`) so Falco starts without internet access right after a boot.

`/var/log/falco/events.json` is rotated daily, 3 days kept (`/etc/logrotate.d/falco-events`).

Test it:

```bash
sudo microk8s kubectl run falco-test --image=busybox:1.36 --restart=Never -- sleep 120
sudo microk8s kubectl exec falco-test -- cat /etc/shadow      # "Read sensitive file untrusted" in Wazuh
sudo microk8s kubectl delete pod falco-test
```

Falcosidekick runs with no outputs configured. Falco alerts reach Wazuh through the file above.

## Container logs to the Wazuh indexer

| Piece | Where | What it does |
|---|---|---|
| Fluent Bit (Helm release `fluent-bit`, namespace `logging`) | k8s-01 | Tails container logs and kubelet's journal, adds Kubernetes metadata |
| Output | Wazuh indexer, port 9200 | Container logs to `k8s-logs-YYYY.MM.DD`, kubelet to `k8s-logs-node-YYYY.MM.DD` |
| Indexer user `k8s-logs-writer` | Wazuh indexer | Write-only, `k8s-logs-*` indexes only. Password in the Kubernetes Secret `k8s-logs-indexer` |
| Retention | ISM policy `k8s-logs-7d` | Deletes each daily index after 7 days |

The firewall allows k8s-01 to the indexer port and nothing else on the SOC VLAN. Change Fluent Bit through Helm (`helm upgrade --reuse-values`), not by editing the ConfigMap, or the change is lost on the next upgrade.

To search them, add the index pattern `k8s-logs-*` in the Wazuh dashboard (Dashboards Management, Index patterns). Logs sent while Wazuh is off are retried and then dropped.

## Planned Falco rules

| Rule | MITRE |
|---|---|
| Privileged container spawned | T1611 |
| kubectl exec into a running pod | T1609 |
| Unexpected outbound connection | T1071 |
