# OpenCanary Honeypot

OpenCanary in the victim VLAN (10.10.20.99) poses as a legitimate server. Any connection to it is inherently suspicious — no legitimate user or process should touch it. Alerts forward to Wazuh via syslog.

Services listening: SSH (22), HTTP (80), SMB (445), FTP (21)

## Screenshots
<!-- Add after build -->
![OpenCanary services listening](screenshots/opencanary-services.png)
![Wazuh alert when Kali hits OpenCanary](screenshots/opencanary-alert.png)
