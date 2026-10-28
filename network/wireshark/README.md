# Wireshark

## Display filters

| Filter | Finds |
|---|---|
| `kerberos.msg_type == 14` | AS-REP roasting (no pre-auth) |
| `kerberos.CNameString` | Kerberoasting SPN requests |
| `tcp.port == 4444` | Common reverse shell port |
| `dns.qry.name.len > 52` | DNS tunneling |
| `smb2.cmd == 5` | SMB create file (lateral movement) |
| `tls.handshake.type == 1` | TLS Client Hello (JA3/JA4 fingerprinting) |
