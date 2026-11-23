#!/usr/bin/env bash
# Waits for run-all.sh to exit, then replaces the broken azure-sentinel clone on Wazuh.
SSH="ssh -o BatchMode=yes -o ConnectTimeout=10 -i /root/.ssh/lab_ed25519 labadmin@10.10.10.10"
echo "[$(date)] waiting for run-all.sh to exit"
while pgrep -f "bash /opt/lab-build/lab-post-install/run-all.sh" >/dev/null; do sleep 60; done
echo "[$(date)] run-all.sh finished; re-cloning azure-sentinel"
$SSH 'sudo rm -rf /opt/detection-rules/azure-sentinel && sudo git clone --depth 1 https://github.com/Azure/Azure-Sentinel /opt/detection-rules/azure-sentinel && sudo git -C /opt/detection-rules/azure-sentinel log -1 --format="HEAD %h %cd"; df -h / | tail -1'
echo "[$(date)] done (exit $?)"
