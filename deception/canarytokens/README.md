# Canarytokens

Fake credential files and documents placed on victim machines. Opening one triggers a DNS callback or webhook — immediate indication of an attacker accessing files they should not.

## Tokens deployed
| Token type | Location | Triggers on |
|------------|----------|-------------|
| AWS credentials | C:\Users\victim\.aws\credentials | File open |
| Word document | C:\Users\victim\Desktop\passwords.docx | File open |
| DNS token | Embedded in web-01 config | DNS lookup |

## Screenshots
<!-- Add after build -->
![Canarytoken alert triggered](screenshots/canarytoken-alert.png)
