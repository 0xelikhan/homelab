# Kubernetes

| Item | Value |
|---|---|
| VM | 115 `k8s-01`, VLAN 40, 4 cores, 6 GB RAM |
| Group | k8s (`lab-profile k8s start`) |
| Cluster | MicroK8s, single node (`sudo microk8s kubectl get pods -A`) |

Running in the cluster: Falco, Falcosidekick, Fluent Bit, Trivy operator, Calico, CoreDNS, hostpath provisioner, metrics-server.

Has a Wazuh agent (auditd).

## Planned Falco rules

| Rule | MITRE |
|---|---|
| Privileged container spawned | T1611 |
| kubectl exec into a running pod | T1609 |
| Sensitive file read in a container | T1003 |
| Unexpected outbound connection | T1071 |
