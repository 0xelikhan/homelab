# Security Onion + Zeek

Security Onion on a span port sees all victim network traffic passively. Zeek generates structured connection, DNS, HTTP, SSL, and file logs. Full PCAP stored for forensic analysis.

- IP: 10.10.50.10 | VLAN 50 (span port — passive, not in traffic path)
- 8GB RAM, 200GB disk — PCAP retention depends on traffic volume

## Log types
| Log | What it captures |
|-----|-----------------|
| conn.log | All TCP/UDP/ICMP connections |
| dns.log | All DNS queries and responses |
| http.log | HTTP URIs, user agents, response codes |
| ssl.log | TLS handshakes, certificates, JA3 hashes |
| files.log | File transfers with MD5/SHA1 hashes |

## Screenshots
<!-- Add after build -->
![Security Onion dashboard](screenshots/security-onion-dashboard.png)
![Zeek conn.log showing attack traffic](screenshots/zeek-conn-log.png)
