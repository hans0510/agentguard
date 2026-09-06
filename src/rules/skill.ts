import type { Artifact, Finding, Rule } from "../types.js";
import {
  EXFIL_ACTION_PATTERNS,
  EXFIL_ENDPOINT_PATTERNS,
  INSTRUCTION_OVERRIDE_PATTERNS,
  SENSITIVE_PATH_PATTERNS,
} from "../util/patterns.js";
import { allMatches, findInvisibleChars, firstMatch, lineOf, truncate } from "../util/text.js";

function asSkill(artifact: Artifact): Extract<Artifact, { kind: "skill-file" }> | null {
  return artifact.kind === "skill-file" ? artifact : null;
}

const SAFETY_SUPPRESSION_PATTERNS: RegExp[] = [
  /\bdo\s+not\s+ask\s+(?:the\s+user\s+)?for\s+confirm/i,
  /\bnever\s+ask\s+(?:the\s+user\s+)?for\s+confirm/i,
  /\bskip\s+(?:all\s+)?(?:confirmation|approval|verification)\s+steps?\b/i,
  /\bwithout\s+(?:any\s+)?(?:confirmation|approval|user\s+consent)/i,
  /\bnever\s+refuse\b/i,
  /\balways\s+(?:say\s+yes|approve|allow|proceed)\b/i,
  /\bdisable\s+(?:safety|security|guardrails?|filters?)/i,
  /\bact\s+as\s+if\s+you\s+have\s+(?:no|full)\s+(?:restrictions?|limitations?|permissions?)/i,
  /\byou\s+are\s+(?:now\s+)?in\s+(?:developer|admin|debug|unrestricted|jailbreak)\s+mode/i,
  /\brm\s+-rf\s+(?:~|\/|\$HOME)/i,
];

export const skillPromptInjection: Rule = {
  id: "AG-K001",
  name: "Prompt injection in skill/instruction file",
  description: "Agent instruction files are the agent's system prompt. Anything that tells it to ignore prior instructions is an attack.",
  defaultSeverity: "high",
  appliesTo: ["skill-file"],
  check(artifact: Artifact): Finding[] {
    const s = asSkill(artifact);
    if (!s) return [];
    const findings: Finding[] = [];
    for (const m of allMatches(s.file.content, INSTRUCTION_OVERRIDE_PATTERNS).slice(0, 5)) {
      findings.push({
        ruleId: "AG-K001",
        severity: "high",
        title: "Prompt-injection phrasing in agent instruction file",
        description:
          "This file is injected into the agent's context. Phrases that override instructions, order the agent to hide things from the user, or redirect tool use are prompt-injection red flags.",
        location: { file: s.file.path, line: lineOf(s.file.content, m.index) },
        evidence: truncate(m.match),
        remediation: "Remove the instruction. If this file came from a third party, review the whole file before using it.",
        references: ["https://simonwillison.net/series/prompt-injection/"],
      });
    }
    return findings;
  },
};

export const skillSafetySuppression: Rule = {
  id: "AG-K002",
  name: "Safety suppression in skill/instruction file",
  description: "Instructions that disable confirmations, refusals, or guardrails turn the agent into an unmonitored operator.",
  defaultSeverity: "high",
  appliesTo: ["skill-file"],
  check(artifact: Artifact): Finding[] {
    const s = asSkill(artifact);
    if (!s) return [];
    const m = firstMatch(s.file.content, SAFETY_SUPPRESSION_PATTERNS);
    if (!m) return [];
    return [
      {
        ruleId: "AG-K002",
        severity: "high",
        title: "Skill suppresses user confirmations or safety checks",
        description:
          "The file tells the agent to skip confirmations, never refuse, or disable guardrails. This converts one injected instruction into unbounded autonomous action.",
        location: { file: s.file.path, line: lineOf(s.file.content, m.index) },
        evidence: truncate(m.match),
        remediation: "Delete the suppression clause. Skills should narrow what an agent does, not remove the user's veto.",
      },
    ];
  },
};

export const skillExfiltration: Rule = {
  id: "AG-K003",
  name: "Exfiltration instruction in skill/instruction file",
  description: "Instructions to send data to external endpoints.",
  defaultSeverity: "critical",
  appliesTo: ["skill-file"],
  check(artifact: Artifact): Finding[] {
    const s = asSkill(artifact);
    if (!s) return [];
    const endpoint = firstMatch(s.file.content, EXFIL_ENDPOINT_PATTERNS);
    const action = firstMatch(s.file.content, EXFIL_ACTION_PATTERNS);
    const m = endpoint ?? action;
    if (!m) return [];
    return [
      {
        ruleId: "AG-K003",
        severity: "critical",
        title: "Skill instructs the agent to send data externally",
        description: endpoint
          ? `The file references a known data-sink service (${truncate(m.match, 60)}).`
          : "The file tells the agent to transmit data to an external URL or hide it in a covert channel.",
        location: { file: s.file.path, line: lineOf(s.file.content, m.index) },
        evidence: truncate(m.match),
        remediation: "Delete this skill immediately and rotate any credentials the agent had access to.",
      },
    ];
  },
};

export const skillHiddenComment: Rule = {
  id: "AG-K004",
  name: "Hidden instructions in HTML comments",
  description: "HTML comments render invisibly in markdown viewers but are fully readable by the model.",
  defaultSeverity: "medium",
  appliesTo: ["skill-file"],
  check(artifact: Artifact): Finding[] {
    const s = asSkill(artifact);
    if (!s) return [];
    const findings: Finding[] = [];
    const COMMENT_RE = /<!--([\s\S]*?)-->/g;
    let m: RegExpExecArray | null;
    while ((m = COMMENT_RE.exec(s.file.content)) !== null) {
      const body = m[1]!;
      if (body.trim().length < 8) continue;
      const suspicious =
        firstMatch(body, INSTRUCTION_OVERRIDE_PATTERNS) ||
        firstMatch(body, SAFETY_SUPPRESSION_PATTERNS) ||
        firstMatch(body, SENSITIVE_PATH_PATTERNS) ||
        firstMatch(body, EXFIL_ACTION_PATTERNS);
      findings.push({
        ruleId: "AG-K004",
        severity: suspicious ? "high" : "low",
        title: suspicious ? "Malicious instruction hidden in an HTML comment" : "Hidden HTML comment in skill file",
        description: suspicious
          ? "This comment is invisible when the markdown is rendered, but the model reads it — and it contains instruction-override or exfiltration phrasing."
          : "HTML comments are invisible in rendered markdown but visible to the model. Review what it says.",
        location: { file: s.file.path, line: lineOf(s.file.content, m.index) },
        evidence: truncate(body),
        remediation: "Remove the hidden comment. Instructions must be visible to anyone who installs the skill.",
      });
    }
    return findings.slice(0, 10);
  },
};

export const skillInvisibleChars: Rule = {
  id: "AG-K005",
  name: "Invisible Unicode in skill/instruction file",
  description: "Zero-width and tag-block characters smuggle model-readable text past human review.",
  defaultSeverity: "critical",
  appliesTo: ["skill-file"],
  check(artifact: Artifact): Finding[] {
    const s = asSkill(artifact);
    if (!s) return [];
    const found = findInvisibleChars(s.file.content);
    if (found.length === 0) return [];
    const unique = [...new Set(found.map((c) => c.hex))];
    return [
      {
        ruleId: "AG-K005",
        severity: "critical",
        title: `Invisible Unicode characters in skill file (${found.length} found)`,
        description: `Found invisible characters (${unique.join(", ")}). The model reads them; a human reviewer of the markdown does not. This is a hidden prompt-injection channel.`,
        location: { file: s.file.path, line: lineOf(s.file.content, found[0]!.index) },
        evidence: unique.join(" "),
        remediation: "Strip all invisible characters, or delete the skill if they encode instructions.",
      },
    ];
  },
};

export const skillCredentialAccess: Rule = {
  id: "AG-K006",
  name: "Credential access instruction in skill/instruction file",
  description: "Instructions telling the agent to read SSH keys, cloud credentials, or .env files.",
  defaultSeverity: "high",
  appliesTo: ["skill-file"],
  check(artifact: Artifact): Finding[] {
    const s = asSkill(artifact);
    if (!s) return [];
    const m = firstMatch(s.file.content, SENSITIVE_PATH_PATTERNS);
    if (!m) return [];
    return [
      {
        ruleId: "AG-K006",
        severity: "high",
        title: "Skill points the agent at credential files",
        description: "The file references SSH keys, cloud credentials, .env files, or similar secret material.",
        location: { file: s.file.path, line: lineOf(s.file.content, m.index) },
        evidence: truncate(m.match),
        remediation: "Remove the reference. Agents should receive secrets through narrowly scoped environment variables, never by reading credential stores.",
      },
    ];
  },
};

export const skillRules: Rule[] = [
  skillPromptInjection,
  skillSafetySuppression,
  skillExfiltration,
  skillHiddenComment,
  skillInvisibleChars,
  skillCredentialAccess,
];
