# Dark-web CTI sources

Source lists for dark-web / Tor threat-intel collection, used from the Whonix research VM. Access these only from that hardened, Tor-routed VM — never from a lab or host browser.

| File | What it is |
|---|---|
| [curated.md](curated.md) | Working subset: the reachable (VALID/ONLINE) Telegram channels plus hand-picked high-value sources |
| [deepdarkcti/](deepdarkcti/) | Full snapshot of fastfire/deepdarkCTI (2026-11-01, commit 9f068ac): 1215 Telegram channels, 713 ransomware leak-site rows, 356 forums, 168 markets, 63 onion search engines, and more |
| [cti-skills.md](cti-skills.md) | Inventory of Liberty91LTD/cti-skills (78 skills) and the dark-web sources its `darkweb-collection` skill references |

## Live sources

The vendored copy is a point-in-time snapshot; the upstream lists update daily. On the research VM, clone and `pull` for current data:

```
git clone https://github.com/fastfire/deepdarkCTI
git clone https://github.com/Liberty91LTD/cti-skills
git -C deepdarkCTI pull    # refresh
```

## Attribution

`deepdarkcti/` is vendored from <https://github.com/fastfire/deepdarkCTI> under GPL-3.0 (see [deepdarkcti/LICENSE](deepdarkcti/LICENSE)). cti-skills: <https://github.com/Liberty91LTD/cti-skills>.
