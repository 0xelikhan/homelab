# Active Directory

| VM | ID | VLAN | Group | Notes |
|---|---|---|---|---|
| win-dc01 | 105 | 20 | attack | Windows Server domain controller. Wazuh agent enrolled. Snapshot `pre-badblood` exists |

## To do

| Task | How |
|---|---|
| Sysmon | `sysmon-advanced.ps1` |
| Domain build | `dc01-setup.ps1` (OUs, users, GPOs, audit policy) |
| Velociraptor client | MSI from the Velociraptor GUI (`Server.Utils.CreateMSI`) |
| Remote management | OpenSSH Server with key-only login |
