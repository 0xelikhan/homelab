# infra/robin-local

Local addition to the upstream [apurvsinghgautam/robin](https://github.com/apurvsinghgautam/robin)
OSINT tool deployed on LXC 130 at `/opt/robin`. The upstream clone is reproducible;
only this local wrapper is tracked here.

- `run-mcp.sh` — runs robin as an MCP server. Drop into a robin checkout to use.

Secrets (`/opt/robin/.env`) stay on the box; upstream already gitignores them.
