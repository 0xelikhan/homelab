# Active Directory Lab

Windows Server 2022 DC with a Windows 11 domain victim. BadBlood populates realistic vulnerable AD objects — Kerberoastable service accounts, weak ACLs, misconfigured delegations. Full advanced audit policy feeds all security events to Wazuh.

- Domain: lab.local
- DC: win-dc01 — 10.10.20.10
- Victim: win11-victim — 10.10.20.20
- Attacker: Kali (VLAN 30 — can reach VLAN 20 per firewall rules)

## Key event IDs monitored
4624, 4625, 4648, 4672, 4768, 4769, 4776, 5140

## Attack scenarios run from Kali
See [adversary-simulation/ad-attacks/](../../adversary-simulation/ad-attacks/)

## Screenshots
<!-- Add after build -->
![AD Users and Computers](screenshots/ad-users-computers.png)
![BadBlood completion](screenshots/badblood-complete.png)
![Audit policy settings](screenshots/audit-policy.png)
