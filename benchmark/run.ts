import { readdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { runScan } from "../src/engine/scanner.js";
import { allRules } from "../src/rules/index.js";
import type { Artifact, Finding, ScanContext, ServerConfig, ToolDefinition } from "../src/types.js";

interface SampleExpect {
  rules: string[];
  forbid: string[];
}

interface Sample {
  id: string;
  category: string;
  name: string;
  source: string;
  reference: string;
  artifacts: Artifact[];
  expect: SampleExpect;
}

type Status = "PASS" | "MISS" | "FP";

interface SampleResult {
  sample: Sample;
  status: Status;
  missing: string[];
  unexpected: Finding[];
  findings: Finding[];
}

const benchmarkDir = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const corpusDir = join(benchmarkDir, "corpus");
const resultsPath = join(benchmarkDir, "RESULTS.md");

/** Recursively collect directories that contain a sample.json (handles corpus/<id>/ and corpus/benign/<id>/). */
function collectSampleFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue;
    const sub = join(dir, entry.name);
    try {
      const direct = join(sub, "sample.json");
      readFileSync(direct);
      out.push(direct);
    } catch {
      out.push(...collectSampleFiles(sub));
    }
  }
  return out;
}

function loadSample(path: string): Sample {
  const raw = JSON.parse(readFileSync(path, "utf8")) as Sample;
  for (const key of ["id", "category", "name", "artifacts", "expect"] as const) {
    if (raw[key] === undefined) throw new Error(`${path}: missing required field "${key}"`);
  }
  return raw;
}

function evaluate(sample: Sample, sampleDir: string): SampleResult {
  const artifacts = sample.artifacts;
  const servers: ServerConfig[] = artifacts
    .filter((a): a is Extract<Artifact, { kind: "server-config" }> => a.kind === "server-config")
    .map((a) => a.server);
  const knownTools: Array<{ server: string; tool: ToolDefinition }> = artifacts
    .filter((a): a is Extract<Artifact, { kind: "tool" }> => a.kind === "tool")
    .map((a) => ({ server: a.server, tool: a.tool }));
  const ctx: ScanContext = { servers, root: sampleDir };

  const findings = runScan({ rules: allRules(), artifacts, ctx, knownTools });
  const found = new Set(findings.map((f) => f.ruleId));

  const missing = sample.expect.rules.filter((id) => !found.has(id));
  const forbid = new Set(sample.expect.forbid ?? []);
  const expected = new Set(sample.expect.rules);
  const unexpected = findings.filter(
    (f) => forbid.has(f.ruleId) || (!expected.has(f.ruleId) && (f.severity === "critical" || f.severity === "high")),
  );

  const status: Status = missing.length > 0 ? "MISS" : unexpected.length > 0 ? "FP" : "PASS";
  return { sample, status, missing, unexpected, findings };
}

function pad(s: string, n: number): string {
  return s.length >= n ? s : s + " ".repeat(n - s.length);
}

function renderTerminal(results: SampleResult[]): void {
  const idW = Math.max(...results.map((r) => r.sample.id.length), 2);
  const catW = Math.max(...results.map((r) => r.sample.category.length), 8);
  console.log(`\n${pad("STATUS", 6)}  ${pad("ID", idW)}  ${pad("CATEGORY", catW)}  DETAIL`);
  for (const r of results) {
    const detail =
      r.status === "MISS"
        ? `missing: ${r.missing.join(", ")}`
        : r.status === "FP"
          ? `unexpected: ${[...new Set(r.unexpected.map((f) => `${f.ruleId}(${f.severity})`))].join(", ")}`
          : `${r.findings.length} finding(s)`;
    console.log(`${pad(r.status, 6)}  ${pad(r.sample.id, idW)}  ${pad(r.sample.category, catW)}  ${detail}`);
  }
  console.log("");
}

function renderMarkdown(results: SampleResult[]): string {
  const malicious = results.filter((r) => r.sample.category !== "benign");
  const benign = results.filter((r) => r.sample.category === "benign");
  const detected = malicious.filter((r) => r.status === "PASS").length;
  const benignClean = benign.filter((r) => r.status === "PASS").length;
  const detectionRate = malicious.length === 0 ? 0 : detected / malicious.length;
  const fpRate = benign.length === 0 ? 0 : 1 - benignClean / benign.length;

  const categories = [...new Set(results.map((r) => r.sample.category))].sort();
  const lines: string[] = [];
  lines.push("# AgentGuard Benchmark Results");
  lines.push("");
  lines.push(`Generated: ${new Date().toISOString()} by \`npm run benchmark\` (do not edit by hand).`);
  lines.push("");
  lines.push("## Summary");
  lines.push("");
  lines.push(`- Corpus: ${results.length} samples (${malicious.length} malicious, ${benign.length} benign)`);
  lines.push(
    `- Malicious detection rate: **${detected}/${malicious.length} (${(detectionRate * 100).toFixed(1)}%)** — a sample counts as detected when every rule in \`expect.rules\` fired`,
  );
  lines.push(
    `- Benign false-positive rate: **${benign.length - benignClean}/${benign.length} (${(fpRate * 100).toFixed(1)}%)** — a false positive is a forbidden rule hit, or any unexpected critical/high finding`,
  );
  lines.push("");
  lines.push("## Detection rate by category");
  lines.push("");
  lines.push("| Category | Samples | Fully detected | Misses | False positives | Detection rate |");
  lines.push("| --- | ---: | ---: | ---: | ---: | ---: |");
  for (const cat of categories) {
    const rows = results.filter((r) => r.sample.category === cat);
    const pass = rows.filter((r) => r.status === "PASS").length;
    const miss = rows.filter((r) => r.status === "MISS").length;
    const fp = rows.filter((r) => r.status === "FP").length;
    lines.push(`| ${cat} | ${rows.length} | ${pass} | ${miss} | ${fp} | ${((pass / rows.length) * 100).toFixed(1)}% |`);
  }
  lines.push("");
  lines.push("## Per-sample results");
  lines.push("");
  lines.push("| Sample | Category | Status | Findings | Missing rules | Unexpected findings |");
  lines.push("| --- | --- | --- | ---: | --- | --- |");
  for (const r of results) {
    const missing = r.missing.length > 0 ? r.missing.join(", ") : "—";
    const unexpected =
      r.unexpected.length > 0 ? [...new Set(r.unexpected.map((f) => `${f.ruleId} (${f.severity})`))].join(", ") : "—";
    lines.push(`| ${r.sample.id} | ${r.sample.category} | ${r.status} | ${r.findings.length} | ${missing} | ${unexpected} |`);
  }
  lines.push("");
  lines.push("## Comparison with academic baselines");
  lines.push("");
  lines.push(
    "The corpus categories mirror public attack taxonomies: the Invariant Labs tool-poisoning disclosure " +
      "(April 2025) and the component-based, 12-category attack taxonomy of *When MCP Servers Attack: Taxonomy, " +
      "Feasibility, and Mitigation* (Zhao et al., [arXiv:2509.24272](https://arxiv.org/abs/2509.24272)). " +
      "That paper evaluates state-of-the-art MCP scanners against its generated malicious servers and finds existing " +
      "detection insufficient: mcp-scan caught only a handful of poisoned tool descriptions, and AI-Infra-Guard, " +
      "while better, remained insufficient — both score on the order of **0.1/1.0** across the paper's attack classes.",
  );
  lines.push("");
  lines.push(
    `Against this corpus, AgentGuard fully detects **${(detectionRate * 100).toFixed(1)}%** of malicious samples ` +
      `with a **${(fpRate * 100).toFixed(1)}%** false-positive rate on benign samples. Caveats: this corpus is small ` +
      "and self-hosted, samples are static artifacts rather than live PoC servers, and categories are weighted " +
      "towards the rules AgentGuard ships — treat the number as a regression gate for our own rule set, not as an " +
      "independent evaluation.",
  );
  lines.push("");

  const failed = results.filter((r) => r.status !== "PASS");
  lines.push("## Engine notes");
  lines.push("");
  if (failed.length === 0) {
    lines.push("No misses or false positives in this run — no engine issues surfaced by the corpus.");
  } else {
    lines.push("The following samples expose engine gaps or over-triggering (rule bugs are reported, not worked around):");
    lines.push("");
    for (const r of failed) {
      const why =
        r.status === "MISS"
          ? `expected rule(s) ${r.missing.join(", ")} did not fire`
          : `unexpected critical/high finding(s): ${[...new Set(r.unexpected.map((f) => `${f.ruleId} (${f.severity}) — ${f.title}`))].join("; ")}`;
      lines.push(`- **${r.sample.id}** (${r.sample.category}): ${why}.`);
    }
  }
  lines.push("");
  return lines.join("\n");
}

const sampleFiles = collectSampleFiles(corpusDir).sort();
if (sampleFiles.length === 0) {
  console.error(`No samples found under ${corpusDir}`);
  process.exit(1);
}

const results: SampleResult[] = sampleFiles.map((path) => evaluate(loadSample(path), dirname(path)));
results.sort((a, b) =>
  a.sample.category === b.sample.category ? a.sample.id.localeCompare(b.sample.id) : a.sample.category.localeCompare(b.sample.category),
);

renderTerminal(results);
writeFileSync(resultsPath, renderMarkdown(results));
console.log(`Wrote ${relative(process.cwd(), resultsPath)}`);

const failures = results.filter((r) => r.status !== "PASS");
const malicious = results.filter((r) => r.sample.category !== "benign");
const detected = malicious.filter((r) => r.status === "PASS").length;
console.log(
  `Detection: ${detected}/${malicious.length} malicious | False positives: ${failures.filter((r) => r.status === "FP").length} | Misses: ${failures.filter((r) => r.status === "MISS").length}`,
);
if (failures.length > 0) {
  console.error(`\n${failures.length} sample(s) failed (MISS or FP).`);
  process.exit(1);
}
