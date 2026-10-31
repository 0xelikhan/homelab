# SIFT / DFIR workstation

| Item | Value |
|---|---|
| VM | 126 `sift`, VLAN 10 (10.10.10.60), 12 GB RAM, 150 GB disk |
| Group | on-demand (needs the `cti` group stopped for RAM) |
| OS | Ubuntu 24.04 |
| CPU | `host` (NumPy wheels need x86-64-v2; the default `kvm64` breaks them) |
| Desktop | XFCE over xrdp, port 3389 |
| SSH | `ubuntu@10.10.10.60` |

One workstation carrying SIFT, REMnux, the Eric Zimmerman tools, an agentic DFIR
MCP stack and a local Valhuntir RAG. Start it with the `cti` group stopped:
`qm start 126`, `qm shutdown 126` when done.

## Tools

| Tool | Where | Notes |
|---|---|---|
| SIFT | `cast install sift` | SANS SIFT workstation |
| REMnux | `remnux install --mode=addon` | Malware analysis add-on, 24.04 only |
| Eric Zimmerman tools | `/opt/zimmermantools`, wrappers in `/usr/local/bin` | 19 CLI tools via .NET 10 (`dotnet X.dll`). The WPF GUI tools are Windows-only |
| agentic-dfir | `~/agentic-dfir` | 73-tool MCP surface (48 native + 25 SIFT adapters), 9/9 adapters |
| Protocol SIFT | `~/.claude` | Claude Code config: forensic skills, case templates, audit hook |
| Valhuntir Lite | `~/.vhir`, `~/sift-mcp` | CPU venv + triage DBs + forensic-rag (ChromaDB, 25,329 records) |

## Gotchas

- `cpu: host` is required. On `kvm64` NumPy raises `X86_V2` at import and every
  NumPy-dependent tool (Valhuntir, Volatility) fails.
- Eric Zimmerman GUI tools (RegistryExplorer, TimelineExplorer, MFTExplorer, …)
  are Windows WPF and do not run here — CLI tools (MFTECmd, PECmd, EvtxECmd, …) do.
- Do not copy `~/.claude/.credentials.json`; it holds the API key.
