# ATT&CK tools

| Item | Value |
|---|---|
| LXC | 121 `attack-tools`, 2 cores, 768 MB RAM, Ubuntu 24.04 |
| Group | `purple` and `attack` |
| Network | SOC VLAN |

A landing page on port 80 links to all three.

| Tool | Version | Port | What it does |
|---|---|---|---|
| ATT&CK Navigator | 5.3 (MITRE prebuilt site) | 8081 | Color-coded ATT&CK matrices. Load DeTT&CT output or Atomic test lists as layers |
| Attack Flow builder | 4.1.0, built from source | 8082 | Draw an attack as a sequence of techniques, export as STIX for OpenCTI |
| DeTT&CT editor | 2.2.0, Docker `rabobankcdc/dettect` | 8080 | Score data source quality, visibility and detection per technique, export Navigator layers |

## Layers

| Layer | What it shows |
|---|---|
| [layers/wazuh-coverage.json](layers/wazuh-coverage.json) | Techniques with a Wazuh rule. Green: verified with a real event in the lab. Light green: custom rule not yet tested. Yellow: built-in Wazuh rule only |

Open it in Navigator with Open Existing Layer, Upload from local. Test the light green techniques with `Invoke-AtomicTest` on DC01, then update the layer.

## Where things live

| Path | What |
|---|---|
| `/var/www/navigator`, `/var/www/attack-flow`, `/var/www/home` | Static sites served by nginx |
| `/etc/nginx/sites-available/attack-tools` | nginx config |
| `/opt/dettect/input`, `/opt/dettect/output` | DeTT&CT YAML files, mounted into the container |
| `/opt/src` | Source checkouts used for the builds |

Navigator loads ATT&CK data from GitHub, so the browser needs internet access.

## Update

```bash
# Navigator
cd /opt/src/navigator-pages && git pull && rsync -a --delete --exclude .git ./ /var/www/navigator/ \
  && sed -i 's#<base href="[^"]*"#<base href="/"#' /var/www/navigator/index.html
# DeTT&CT
docker pull rabobankcdc/dettect:<new tag>   # then recreate the container with the new tag
```

Attack Flow needs Node 22 to rebuild (`npm ci && npm run build-only` in `src/attack_flow_builder`, copy `dist/`).
