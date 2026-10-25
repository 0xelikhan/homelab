# OpenCanary and Cowrie

| Item | Value |
|---|---|
| VM | 118 `opencanary`, VLAN 20, 1 core, 1 GB RAM |

Honeypots in the victim VLAN. Anything touching them is suspicious by definition.

| Service | Provided by |
|---|---|
| SSH (fake shell) | Cowrie (pinned to v2.9.20, last release for Python 3.10) |
| FTP, Telnet, HTTP login page, MySQL, RDP, VNC, Redis | OpenCanary |
| Port scan detection | OpenCanary |

Both write JSON logs that the Wazuh agent ships to Wazuh.
