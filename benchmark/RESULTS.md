# AgentGuard Benchmark Results

Generated: 2026-09-06T17:18:13.624Z by `npm run benchmark` (do not edit by hand).

## Summary

- Corpus: 50 samples (40 malicious, 10 benign)
- Malicious detection rate: **40/40 (100.0%)** — a sample counts as detected when every rule in `expect.rules` fired
- Benign false-positive rate: **0/10 (0.0%)** — a false positive is a forbidden rule hit, or any unexpected critical/high finding

## Detection rate by category

| Category | Samples | Fully detected | Misses | False positives | Detection rate |
| --- | ---: | ---: | ---: | ---: | ---: |
| benign | 10 | 10 | 0 | 0 | 100.0% |
| config-supply-chain | 6 | 6 | 0 | 0 | 100.0% |
| exfil-channel | 4 | 4 | 0 | 0 | 100.0% |
| invisible-unicode | 2 | 2 | 0 | 0 | 100.0% |
| malicious-source | 10 | 10 | 0 | 0 | 100.0% |
| rug-pull | 2 | 2 | 0 | 0 | 100.0% |
| sensitive-file-access | 4 | 4 | 0 | 0 | 100.0% |
| skill-attack | 6 | 6 | 0 | 0 | 100.0% |
| tool-poisoning | 4 | 4 | 0 | 0 | 100.0% |
| tool-shadowing | 2 | 2 | 0 | 0 | 100.0% |

## Per-sample results

| Sample | Category | Status | Findings | Missing rules | Unexpected findings |
| --- | --- | --- | ---: | --- | --- |
| benign-fetch-server | benign | PASS | 0 | — | — |
| benign-filesystem-server | benign | PASS | 0 | — | — |
| benign-github-server | benign | PASS | 0 | — | — |
| benign-pinned-sqlite | benign | PASS | 0 | — | — |
| benign-remote-https-auth | benign | PASS | 0 | — | — |
| benign-skill-agents-md | benign | PASS | 0 | — | — |
| benign-skill-cursor-rule | benign | PASS | 0 | — | — |
| benign-source-js | benign | PASS | 0 | — | — |
| benign-source-py | benign | PASS | 0 | — | — |
| benign-tool-calculator | benign | PASS | 0 | — | — |
| C001-plain-http | config-supply-chain | PASS | 1 | — | — |
| C003-hardcoded-secrets | config-supply-chain | PASS | 3 | — | — |
| C004-curl-pipe-shell | config-supply-chain | PASS | 1 | — | — |
| C004-sh-c-wrapper | config-supply-chain | PASS | 1 | — | — |
| C005-unpinned-npx | config-supply-chain | PASS | 1 | — | — |
| C006-typosquat | config-supply-chain | PASS | 1 | — | — |
| E001-markdown-beacon | exfil-channel | PASS | 1 | — | — |
| E002-base64-param | exfil-channel | PASS | 1 | — | — |
| E003-webhook-site | exfil-channel | PASS | 1 | — | — |
| E004-pipedream | exfil-channel | PASS | 1 | — | — |
| T002-tags-block | invisible-unicode | PASS | 1 | — | — |
| T002-zero-width | invisible-unicode | PASS | 1 | — | — |
| S001-js-eval | malicious-source | PASS | 1 | — | — |
| S001-js-exec-template | malicious-source | PASS | 1 | — | — |
| S001-py-os-system | malicious-source | PASS | 1 | — | — |
| S001-py-pickle | malicious-source | PASS | 1 | — | — |
| S001-py-subprocess-shell | malicious-source | PASS | 1 | — | — |
| S002-js-read-ssh-key | malicious-source | PASS | 1 | — | — |
| S003-js-env-fetch | malicious-source | PASS | 1 | — | — |
| S003-py-env-requests | malicious-source | PASS | 1 | — | — |
| S004-js-obfuscation | malicious-source | PASS | 4 | — | — |
| S005-py-hardcoded-keys | malicious-source | PASS | 1 | — | — |
| R001-rugpull-description-change | rug-pull | PASS | 1 | — | — |
| R002-rugpull-sensitive-path | rug-pull | PASS | 1 | — | — |
| F001-aws-credentials | sensitive-file-access | PASS | 1 | — | — |
| F002-dotenv | sensitive-file-access | PASS | 1 | — | — |
| F003-kube-config | sensitive-file-access | PASS | 1 | — | — |
| F004-ed25519-key | sensitive-file-access | PASS | 1 | — | — |
| K001-ignore-previous | skill-attack | PASS | 1 | — | — |
| K002-no-confirmation | skill-attack | PASS | 1 | — | — |
| K003-curl-exfil | skill-attack | PASS | 1 | — | — |
| K004-html-comment | skill-attack | PASS | 2 | — | — |
| K005-invisible-unicode | skill-attack | PASS | 1 | — | — |
| K006-credential-ref | skill-attack | PASS | 1 | — | — |
| T001-basic-instruction | tool-poisoning | PASS | 1 | — | — |
| T001-combo-ssh-exfil | tool-poisoning | PASS | 2 | — | — |
| T001-system-tag | tool-poisoning | PASS | 1 | — | — |
| T001-when-calling-tools | tool-poisoning | PASS | 1 | — | — |
| X001-basic-shadowing | tool-shadowing | PASS | 1 | — | — |
| X001-shadowing-poisoned | tool-shadowing | PASS | 2 | — | — |

## Comparison with academic baselines

The corpus categories mirror public attack taxonomies: the Invariant Labs tool-poisoning disclosure (April 2025) and the component-based, 12-category attack taxonomy of *When MCP Servers Attack: Taxonomy, Feasibility, and Mitigation* (Zhao et al., [arXiv:2509.24272](https://arxiv.org/abs/2509.24272)). That paper evaluates state-of-the-art MCP scanners against its generated malicious servers and finds existing detection insufficient: mcp-scan caught only a handful of poisoned tool descriptions, and AI-Infra-Guard, while better, remained insufficient — both score on the order of **0.1/1.0** across the paper's attack classes.

Against this corpus, AgentGuard fully detects **100.0%** of malicious samples with a **0.0%** false-positive rate on benign samples. Caveats: this corpus is small and self-hosted, samples are static artifacts rather than live PoC servers, and categories are weighted towards the rules AgentGuard ships — treat the number as a regression gate for our own rule set, not as an independent evaluation.

## Engine notes

No misses or false positives in this run — no engine issues surfaced by the corpus.
