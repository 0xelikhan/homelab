# Wireshark PCAP Analysis

PCAPs are pulled from Security Onion and analyzed in Wireshark to validate detections, identify missed alerts, and extract IOCs for DFIR-IRIS cases.

## Useful filters
| Scenario | Filter |
|----------|--------|
| Nmap SYN scan | `tcp.flags.syn==1 && tcp.flags.ack==0` |
| DNS tunneling | `dns && frame.len > 200` |
| Pass-the-Hash NTLM | `ntlmssp` |
| SMB lateral movement | `smb2.cmd == 3` |
| Kerberoasting | `kerberos.msg_type == 12` |

## Screenshots
<!-- Add after build -->
![Wireshark — attack traffic with filter](screenshots/wireshark-attack.png)
![NTLM traffic in Pass-the-Hash capture](screenshots/wireshark-ntlm.png)
