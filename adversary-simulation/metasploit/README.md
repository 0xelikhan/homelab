# Metasploit

Run from Kali (`msfconsole`).

| Target | ID | VLAN | Services |
|---|---|---|---|
| metasploitable2 | 108 | 20 | vsftpd 2.3.4 backdoor, Samba 3.0.20, UnrealIRCd, Tomcat, PostgreSQL, DVWA |
| web-01 | 106 | 40 | Apache, pingapp (command injection) |

| Exploit | Module | MITRE |
|---|---|---|
| vsftpd backdoor | `exploit/unix/ftp/vsftpd_234_backdoor` | T1190 |
| Samba usermap | `exploit/multi/samba/usermap_script` | T1190 |
| UnrealIRCd backdoor | `exploit/unix/irc/unreal_ircd_3281_backdoor` | T1190 |
