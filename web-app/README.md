# Web App Testing — Burp Suite + OWASP ZAP + WAF

Deliberately vulnerable Flask app with command injection endpoint. ModSecurity WAF in front. Burp Suite and OWASP ZAP used from Kali to attack it. Full detection comparison: without WAF vs with WAF vs Wazuh alert.

- web-01: Ubuntu 22.04, VLAN 40, 10.10.40.10
- Stack: Flask + nginx + ModSecurity (libnginx-mod-security2)
- Detection: Wazuh agent watching nginx logs, ModSecurity alerts, auditd exec logs

## Detection comparison
| Attack | Without WAF | With WAF | Wazuh alert |
|--------|-------------|----------|-------------|
| Command injection /ping | Shell executes | 403 blocked | auditd execve |
| Directory traversal | File read | 403 blocked | nginx log alert |
| SQLi | App-dependent | 403 blocked | ModSecurity in Wazuh |

## Screenshots
<!-- Add after build -->
![Burp Suite intercepting request](screenshots/burp-intercept.png)
![Command injection working before WAF](screenshots/cmd-injection-success.png)
![ModSecurity blocking same request](screenshots/modsecurity-block.png)
![Wazuh alert from web attack](screenshots/wazuh-web-alert.png)
![OWASP ZAP scan results](screenshots/zap-scan.png)
