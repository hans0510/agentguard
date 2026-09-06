import type { Artifact, Finding, Rule, ScanContext, ServerConfig, ToolDefinition } from "../types.js";
import { INSTRUCTION_OVERRIDE_PATTERNS } from "../util/patterns.js";

export interface ScanOptions {
  rules: Rule[];
  artifacts: Artifact[];
  ctx: ScanContext;
  /** Lockfile data for cross-artifact checks (tool shadowing) */
  knownTools?: Array<{ server: string; tool: ToolDefinition }>;
}

/** Cross-artifact escalation: a tool description that BOTH gives the agent
 *  instructions AND touches sensitive paths is the canonical tool-poisoning
 *  attack — escalate those findings to critical. */
function escalate(findings: Finding[]): Finding[] {
  const byTool = new Map<string, Finding[]>();
  for (const f of findings) {
    const key = `${f.location.server ?? ""}::${f.location.tool ?? ""}::${f.location.file ?? ""}`;
    const list = byTool.get(key) ?? [];
    list.push(f);
    byTool.set(key, list);
  }
  for (const group of byTool.values()) {
    const hasInstruction = group.some((f) => f.ruleId === "AG-T001");
    const hasSensitive = group.some((f) => f.ruleId === "AG-T004" || f.ruleId === "AG-T005");
    if (hasInstruction && hasSensitive) {
      for (const f of group) {
        if (f.ruleId === "AG-T004" || f.ruleId === "AG-T005") {
          f.severity = "critical";
          f.title += " (tool poisoning)";
          f.description +=
            " Combined with embedded agent instructions, this is the canonical tool-poisoning pattern: the tool tricks the agent into reading sensitive data and passing it back.";
        }
      }
    }
  }
  return findings;
}

/** Tool shadowing: two servers exposing the same tool name. */
function detectToolShadowing(knownTools: Array<{ server: string; tool: ToolDefinition }> | undefined): Finding[] {
  if (!knownTools || knownTools.length === 0) return [];
  const byName = new Map<string, string[]>();
  for (const { server, tool } of knownTools) {
    const list = byName.get(tool.name) ?? [];
    if (!list.includes(server)) list.push(server);
    byName.set(tool.name, list);
  }
  const findings: Finding[] = [];
  for (const [name, servers] of byName) {
    if (servers.length > 1) {
      findings.push({
        ruleId: "AG-X001",
        severity: "medium",
        title: `Tool name shadowing: "${name}" exposed by ${servers.length} servers`,
        description:
          `The tool name "${name}" is exposed by multiple servers (${servers.join(", ")}). ` +
          "A malicious server can shadow a trusted server's tools to intercept calls and their arguments.",
        location: { server: servers[servers.length - 1]!, tool: name },
        remediation: "Rename one of the tools, or remove the server you do not trust.",
        references: ["https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks"],
      });
    }
  }
  return findings;
}

export function runScan(options: ScanOptions): Finding[] {
  const { rules, artifacts, ctx, knownTools } = options;
  const findings: Finding[] = [];

  for (const artifact of artifacts) {
    for (const rule of rules) {
      if (!rule.appliesTo.includes(artifact.kind)) continue;
      try {
        findings.push(...rule.check(artifact, ctx));
      } catch {
        // A buggy rule must never crash a scan.
      }
    }
  }

  findings.push(...detectToolShadowing(knownTools));
  return escalate(findings);
}

/** Split findings into per-server, skill, and unassigned buckets. */
export function bucketFindings(findings: Finding[], servers: ServerConfig[]): {
  perServer: Map<string, Finding[]>;
  skill: Finding[];
  unassigned: Finding[];
} {
  const perServer = new Map<string, Finding[]>(servers.map((s) => [s.name, []]));
  const skill: Finding[] = [];
  const unassigned: Finding[] = [];
  for (const f of findings) {
    if (f.location.server && perServer.has(f.location.server)) {
      perServer.get(f.location.server)!.push(f);
    } else if (f.location.file && /\.(md|mdc|markdown)$/i.test(f.location.file)) {
      skill.push(f);
    } else {
      unassigned.push(f);
    }
  }
  return { perServer, skill, unassigned };
}

/** Used by the escalation logic to know whether a text carries agent-directed instructions. */
export function carriesInstructions(text: string): boolean {
  return INSTRUCTION_OVERRIDE_PATTERNS.some((p) => p.test(text));
}
