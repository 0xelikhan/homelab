# web-01

| Item | Value |
|---|---|
| VM | 106 `web-01`, VLAN 40, 2 GB RAM |
| Web | port 80 |
| Group | attack |

| Component | What |
|---|---|
| Apache | serves the site |
| ModSecurity | Apache WAF module |
| pingapp | Flask app with a command injection endpoint, behind Apache |

Wazuh agent reads Apache logs, pingapp logs and auditd. Velociraptor client installed.

## Test plan

Attack from Kali with Burp Suite or OWASP ZAP, with and without ModSecurity rules.

| Attack | Without WAF | With WAF | Wazuh |
|---|---|---|---|
| Command injection on /ping | | | auditd execve |
| Directory traversal | | | Apache log |
| SQLi | | | ModSecurity log |
