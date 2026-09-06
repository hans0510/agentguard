# AgentGuard Benchmark

Quantifies how well the AgentGuard rule engine detects known MCP / agent attack
techniques, using a public corpus of attack samples modeled on:

- the [Invariant Labs tool-poisoning disclosure](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) (April 2025), and
- the 12-category attack taxonomy of *When MCP Servers Attack: Taxonomy, Feasibility,
  and Mitigation* ([arXiv:2509.24272](https://arxiv.org/abs/2509.24272)).

## Running

```sh
npm run benchmark
```

This compiles `benchmark/run.ts` (with `benchmark/tsconfig.json`, output in
`benchmark/dist/`) and executes it. The runner prints a per-sample table to the
terminal, regenerates `benchmark/RESULTS.md`, and exits with code 1 if any sample
has a MISS or a false positive — so it can gate CI.

## Corpus layout

```
corpus/
  <sample-id>/sample.json      # malicious samples, one directory each
  benign/<sample-id>/sample.json
```

Each `sample.json`:

```json
{
  "id": "T001-basic-instruction",
  "category": "tool-poisoning",
  "name": "Basic instruction injection in tool description",
  "source": "invariant-labs | arxiv-2509.24272 | community | synthetic",
  "reference": "https://...",
  "artifacts": [ /* engine Artifact objects, see src/types.ts */ ],
  "expect": {
    "rules": ["AG-T001"],
    "forbid": []
  }
}
```

- `artifacts` uses the exact `Artifact` union from `src/types.ts`
  (`server-config`, `tool`, `source-file`, `skill-file`).
- `expect.rules` — rule ids that must fire at least once across the sample's artifacts.
- `expect.forbid` — rule ids that must not fire.

The runner feeds each sample through `runScan()` from `src/engine/scanner.ts`,
with `ctx.servers` extracted from `server-config` artifacts and `knownTools`
built from all `tool` artifacts (so cross-server rules like AG-X001 tool
shadowing work exactly as in a real scan).

## Verdicts

- **PASS** — every expected rule fired, and nothing forbidden or unexpected.
- **MISS** — at least one rule in `expect.rules` did not fire.
- **FP** — a rule in `expect.forbid` fired, or any *critical/high* finding fired
  that is not listed in `expect.rules` (medium/low extras are tolerated, since
  several rules legitimately co-fire on real attacks).

Detection rate = share of malicious samples with no MISS. False-positive rate =
share of benign samples with any FP. Benign samples list every critical/high-capable
rule in `forbid`.

## Contributing a sample

1. `mkdir corpus/<id>` (or `corpus/benign/<id>` for a benign case).
2. Add a `sample.json` in the format above. Keep malicious payloads self-contained:
   use placeholder infrastructure (`example.com`, `webhook.site`, fake keys such as
   `AKIAIOSFODNN7EXAMPLE`), never real endpoints or live credentials.
3. Invisible-Unicode samples: write the characters as JSON `\uXXXX` escapes
   (surrogate pairs for the Tags block, e.g. U+E0069 is written `"\udb40\udc69"`)
   so the hidden payload stays reviewable in the file.
4. Run `npm run benchmark`. It must exit 0 — a new malicious sample that the engine
   misses means either fixing the sample to match documented rule behavior, or
   reporting the rule gap (do not silently relax `expect`).

`benchmark/dist/` is build output and can be deleted at any time.

## Known engine gaps observed while building the corpus

- **AG-T001** (`src/util/patterns.ts` `INSTRUCTION_OVERRIDE_PATTERNS`): the
  cross-tool redirection pattern `(?:before|after|when|whenever)\s+(?:using|calling|invoking|running)\s+(?:any|other|another|the)\s+tool`
  does not match the natural double-qualifier phrasing *"when calling **any other** tool(s)"*
  (only a single qualifier before "tool" is allowed). The corpus sample
  `T001-when-calling-tools` uses the matching phrasing "when calling other tools";
  the "any other tool" variant slips through undetected. Reported as a rule gap,
  not worked around in the engine.
