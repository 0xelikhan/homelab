# Active Directory

| VM | ID | VLAN | Group | Notes |
|---|---|---|---|---|
| win-dc01 | 105 | 20 | purple, attack | Windows Server 2022 domain controller, 2 cores, 4 GB RAM. Wazuh agent enrolled. Snapshot `pre-badblood` exists |

## Installed

| What | Where | What it does |
|---|---|---|
| OpenSSH Server | service `sshd` | Remote management, key login only, PowerShell as the shell |
| Sysmon | `C:\Tools\Sysmon`, service `Sysmon64` | Process, network, registry and file events. Config: sysmon-modular (merged release build) |
| PowerShell script block logging | Group Policy registry key | Logs the full text of every PowerShell script that runs |
| Atomic Red Team | `C:\AtomicRedTeam` | Invoke-AtomicRedTeam module plus the atomics folder. Loads in every PowerShell session |
| DNS forwarders | DNS Server role | Lets the domain resolve internet names |
| Wazuh agent channels | agent `ossec.conf` | Security, System, Application, Sysmon and PowerShell operational logs go to Wazuh |

## Atomic Red Team

```powershell
Invoke-AtomicTest T1003.001 -ShowDetailsBrief     # what the test does
Invoke-AtomicTest T1003.001 -GetPrereqs           # install what it needs
Invoke-AtomicTest T1003.001                       # run it
Invoke-AtomicTest T1003.001 -Cleanup              # undo it
```

Check the result in Wazuh, then mark the technique in DeTT&CT and Navigator (see [attack-tools](../../adversary-simulation/attack-tools/README.md)). Roll back to a snapshot after destructive tests.

## Updating Sysmon config

```powershell
Invoke-WebRequest https://github.com/olafhartong/sysmon-modular/releases/latest/download/sysmonconfig.xml -OutFile C:\Tools\Sysmon\sysmonconfig.xml
C:\Tools\Sysmon\Sysmon64.exe -c C:\Tools\Sysmon\sysmonconfig.xml
```

## To do

| Task | How |
|---|---|
| Domain build | `dc01-setup.ps1` (OUs, users, GPOs, audit policy) |
| Velociraptor client | MSI from the Velociraptor GUI (`Server.Utils.CreateMSI`) |
