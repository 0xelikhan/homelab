#!/bin/bash
# Run on the Proxmox host. Tests the Whonix internal network (vmbr9) guard.
# A temporary network namespace on vmbr9 plays a "compromised workstation" that uses the host as its gateway.
K="-i /root/.ssh/lab_ed25519 -o BatchMode=yes -o ConnectTimeout=10"
WS=user@10.152.152.11

echo "== host -> workstation SSH (must work)"
ssh $K $WS 'echo ok' 2>&1 | tail -1

echo "== workstation internet through Tor (must work)"
ssh $K $WS 'curl -s --max-time 60 https://check.torproject.org/api/ip' 2>&1 | tail -1; echo

echo "== workstation -> host SSH and web UI (should be blocked)"
for p in 22 8006; do
  ssh $K $WS "timeout 5 bash -c '</dev/tcp/10.152.152.1/$p' 2>/dev/null && echo port $p OPEN || echo port $p blocked"
done

echo "== fake workstation routing out through the host (should be blocked)"
ip netns add wgtest
ip link add wgt0 type veth peer name wgt1
ip link set wgt1 netns wgtest
ip link set wgt0 master vmbr9 up
ip netns exec wgtest ip addr add 10.152.152.250/24 dev wgt1
ip netns exec wgtest ip link set wgt1 up
ip netns exec wgtest ip link set lo up
ip netns exec wgtest ip route add default via 10.152.152.1
timeout 8 tcpdump -ni vmbr0 -c 5 src 10.152.152.250 > /tmp/wgtest.pcap.txt 2>/dev/null &
sleep 1
ip netns exec wgtest ping -c 3 -W 1 1.1.1.1 >/dev/null 2>&1
wait
n=$(grep -c "10.152.152.250" /tmp/wgtest.pcap.txt)
echo "packets from the fake workstation that left on the home network: $n"
ip netns exec wgtest timeout 4 bash -c '</dev/tcp/10.152.152.1/22' 2>/dev/null && echo "fake workstation -> host SSH: OPEN" || echo "fake workstation -> host SSH: blocked"
ip link del wgt0
ip netns del wgtest
rm -f /tmp/wgtest.pcap.txt
