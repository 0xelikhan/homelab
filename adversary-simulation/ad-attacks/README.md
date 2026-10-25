# AD Attacks

From Kali against DC01. Domain setup in [infrastructure/active-directory](../../infrastructure/active-directory/README.md).

| Attack | Tool | MITRE | Event IDs | Detected |
|---|---|---|---|---|
| Kerberoasting | impacket-GetUserSPNs | T1558.003 | 4769 (RC4) | |
| Pass-the-Hash | impacket-psexec | T1550.002 | 4624 type 3 NTLM | |
| SMB enumeration | netexec smb | T1021.002 | 5140 | |
| Attack path mapping | bloodhound-python | T1069 | 4661, LDAP | |
| DCSync / secretsdump | impacket-secretsdump | T1003.006 | 4662 | |
