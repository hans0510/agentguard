import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { scan } from "../src/scan.js";
import { renderSarif } from "../src/report/sarif.js";
import { renderJson } from "../src/report/json.js";
import { renderTerminal } from "../src/report/terminal.js";

const FIXTURE = join(__dirname, "fixtures", "malicious-project");

describe("end-to-end scan of a malicious project", () => {
  it("finds config, skill, and transport issues", async () => {
    const report = await scan({ root: FIXTURE, configPath: join(FIXTURE, ".mcp.json") });

    const all = [
      ...report.servers.flatMap((s) => s.findings),
      ...report.skillFindings,
      ...report.unassignedFindings,
    ];
    const ruleIds = new Set(all.map((f) => f.ruleId));

    expect(ruleIds).toContain("AG-C003"); // hardcoded secret
    expect(ruleIds).toContain("AG-C004"); // curl | bash
    expect(ruleIds).toContain("AG-C005"); // unpinned package
    expect(ruleIds).toContain("AG-C001"); // plain http remote
    expect(ruleIds).toContain("AG-K004"); // hidden HTML comment
    expect(ruleIds).toContain("AG-K001"); // prompt injection (inside comment)
    expect(ruleIds).toContain("AG-K006"); // credential access

    expect(report.summary.bySeverity.critical).toBeGreaterThan(0);
    expect(report.summary.worstGrade).toBe("F");
  });

  it("renders all three formats without throwing", async () => {
    const report = await scan({ root: FIXTURE, configPath: join(FIXTURE, ".mcp.json") });
    expect(renderJson(report)).toContain('"tool": "agentguard"');
    expect(renderTerminal(report)).toContain("agentguard");
    const sarif = JSON.parse(renderSarif(report));
    expect(sarif.version).toBe("2.1.0");
    expect(sarif.runs[0].results.length).toBeGreaterThan(0);
  });

  it("a clean empty directory produces no findings", async () => {
    const report = await scan({ root: join(__dirname, "fixtures", "clean-project") });
    expect(report.summary.totalFindings).toBe(0);
  });
});
