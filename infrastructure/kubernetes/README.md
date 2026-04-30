# Kubernetes Detection Lab

MicroK8s cluster with Falco for runtime container threat detection. FluentBit ships Falco alerts to Wazuh. Kubernetes audit policy logs all API server activity.

- k8s-01: master — 10.10.40.20
- k8s-02: worker — 10.10.40.21

## Custom Falco rules
| Rule | MITRE |
|------|-------|
| Privileged container spawned | T1611 |
| kubectl exec into running pod | T1609 |
| Sensitive file read in container | T1003 |
| Unexpected outbound connection | T1071 |

## Screenshots
<!-- Add after build -->
![MicroK8s nodes ready](screenshots/k8s-nodes.png)
![Falco DaemonSet running](screenshots/falco-daemonset.png)
![Falco alert in Wazuh](screenshots/falco-wazuh-alert.png)
