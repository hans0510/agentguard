import type { Artifact, Finding, Rule, ScanContext } from "../types.js";
import { allMatches, findInvisibleChars, firstMatch, truncate } from "../util/text.js";
import {
  EXFIL_ACTION_PATTERNS,
  EXFIL_ENDPOINT_PATTERNS,
  INSTRUCTION_OVERRIDE_PATTERNS,
  SENSITIVE_PATH_PATTERNS,
} from "../util/patterns.js";

function toolFindings(
  artifact: Extract<Artifact, { kind: "tool" }>,
  make: (text: string) => Finding | null,
): Finding[] {
  const f = make(artifact.tool.description ?? "");
  if (f) {
    f.location.server = artifact.server;
    f.location.tool = artifact.tool.name;
    return [f];
  }
  return [];
}

export const instructionInDescription: Rule = {
  id: "AG-T001",
  name: "Embedded agent instructions in tool description",
  description:
    "Tool descriptions are injected into the agent's context. A malicious server can hide instructions " +
    "there that the agent follows without the user ever seeing them (tool poisoning).",
  defaultSeverity: "high",
  appliesTo: ["tool"],
  check(artifact: Artifact): Finding[] {
    if (artifact.kind !== "tool") return [];
    return toolFindings(artifact, (text) => {
      const m = firstMatch(text, INSTRUCTION_OVERRIDE_PATTERNS);
      if (!m) return null;
      return {
        ruleId: "AG-T001",
        severity: "high",
        title: "Tool description contains agent-directed instructions",
        description:
          "The description contains phrasing meant to steer the agent itself (e.g. telling it what to do " +
          "before/after other tools, or what to hide from the user). Descriptions should document the tool, " +
          "not command the agent.",
        location: {},
        evidence: truncate(m.match),
        remediation:
          "Remove this MCP server, or report the issue upstream. Legitimate tools never embed agent instructions in descriptions.",
        references: ["https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks"],
      };
    });
  },
};

export const invisibleCharsInDescription: Rule = {
  id: "AG-T002",
  name: "Invisible Unicode in tool description",
  description:
    "Zero-width and tag-block characters can smuggle instructions into a description that are invisible " +
    "when rendered, but fully visible to the model.",
  defaultSeverity: "critical",
  appliesTo: ["tool"],
  check(artifact: Artifact): Finding[] {
    if (artifact.kind !== "tool") return [];
    const text = `${artifact.tool.name}\n${artifact.tool.description ?? ""}`;
    const found = findInvisibleChars(text);
    if (found.length === 0) return [];
    const unique = [...new Set(found.map((c) => c.hex))];
    return [
      {
        ruleId: "AG-T002",
        severity: "critical",
        title: `Invisible Unicode characters in tool definition (${unique.length} distinct)`,
        description:
          `Found ${found.length} invisible character(s) (${unique.join(", ")}). These are the canonical ` +
          "channel for hidden prompt injection: text the model reads but a human reviewer cannot see.",
        location: { server: artifact.server, tool: artifact.tool.name },
        evidence: unique.join(" "),
        remediation: "Remove this MCP server. There is no legitimate reason for invisible characters in a tool description.",
        references: ["https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks"],
      },
    ];
  },
};

export const sensitivePathInDescription: Rule = {
  id: "AG-T004",
  name: "Sensitive file access in tool description",
  description: "The description instructs the agent to read credential files, SSH keys, or other secrets.",
  defaultSeverity: "high",
  appliesTo: ["tool"],
  check(artifact: Artifact): Finding[] {
    if (artifact.kind !== "tool") return [];
    return toolFindings(artifact, (text) => {
      const m = firstMatch(text, SENSITIVE_PATH_PATTERNS);
      if (!m) return null;
      return {
        ruleId: "AG-T004",
        severity: "high",
        title: "Tool description references sensitive files",
        description:
          "The description points the agent at credential material (SSH keys, cloud credentials, .env files, " +
          "etc.). Legitimate tools receive such data through typed parameters, never by asking the agent to read it.",
        location: {},
        evidence: truncate(m.match),
        remediation: "Remove this MCP server. Do not run agents that are told to read credential files.",
      };
    });
  },
};

export const exfiltrationInDescription: Rule = {
  id: "AG-T005",
  name: "Data exfiltration channel in tool description",
  description: "The description tells the agent to send data to an external endpoint or via a covert channel.",
  defaultSeverity: "high",
  appliesTo: ["tool"],
  check(artifact: Artifact): Finding[] {
    if (artifact.kind !== "tool") return [];
    return toolFindings(artifact, (text) => {
      const endpoint = firstMatch(text, EXFIL_ENDPOINT_PATTERNS);
      const action = firstMatch(text, EXFIL_ACTION_PATTERNS);
      const m = endpoint ?? action;
      if (!m) return null;
      return {
        ruleId: "AG-T005",
        severity: endpoint ? "critical" : "high",
        title: "Tool description contains an exfiltration channel",
        description: endpoint
          ? `The description references a known data-sink service (${truncate(m.match)}).`
          : "The description instructs the agent to transmit data to an external URL or via a covert channel (e.g. base64-encoded parameter, markdown image beacon).",
        location: {},
        evidence: truncate(m.match),
        remediation: "Remove this MCP server immediately and rotate any credentials the agent had access to.",
      };
    });
  },
};

/** Multi-pattern helper for tests: which description patterns fire on a text. */
export function matchDescription(text: string): string[] {
  const hits: string[] = [];
  if (firstMatch(text, INSTRUCTION_OVERRIDE_PATTERNS)) hits.push("instructions");
  if (findInvisibleChars(text).length > 0) hits.push("invisible-unicode");
  if (firstMatch(text, SENSITIVE_PATH_PATTERNS)) hits.push("sensitive-path");
  if (firstMatch(text, EXFIL_ENDPOINT_PATTERNS) || firstMatch(text, EXFIL_ACTION_PATTERNS)) hits.push("exfiltration");
  void allMatches; // exported for rule authors
  return hits;
}

export const toolDescriptionRules: Rule[] = [
  instructionInDescription,
  invisibleCharsInDescription,
  sensitivePathInDescription,
  exfiltrationInDescription,
];
