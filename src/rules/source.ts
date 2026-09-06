import type { Artifact, Finding, Rule } from "../types.js";
import { EXFIL_ENDPOINT_PATTERNS, SECRET_VALUE_PATTERNS, SENSITIVE_PATH_PATTERNS } from "../util/patterns.js";
import { firstMatch, lineOf, stripLineComments, truncate } from "../util/text.js";

interface LinePattern {
  re: RegExp;
  label: string;
  severity: "critical" | "high" | "medium" | "low";
  languages?: string[];
}

const EXECUTION_PATTERNS: LinePattern[] = [
  { re: /\beval\s*\(\s*[^'"`)\s]/, label: "eval() on a dynamic value", severity: "high", languages: ["javascript", "typescript"] },
  { re: /\bnew\s+Function\s*\(/, label: "new Function() (dynamic code compilation)", severity: "high", languages: ["javascript", "typescript"] },
  { re: /\bvm\.(?:runInThisContext|runInNewContext|runInContext)\s*\(/, label: "vm.runIn*() dynamic code execution", severity: "high", languages: ["javascript", "typescript"] },
  { re: /\b(?:execSync|exec)\s*\(\s*[^'"`\s]/, label: "child_process exec() with a non-literal command", severity: "high", languages: ["javascript", "typescript"] },
  { re: /\b(?:execSync|exec|spawn|spawnSync)\s*\(\s*`[^`]*\$\{/, label: "shell command built from a template literal (command injection surface)", severity: "high", languages: ["javascript", "typescript"] },
  { re: /shell\s*:\s*true/, label: "spawn with shell:true (command injection surface)", severity: "medium", languages: ["javascript", "typescript"] },
  { re: /\bos\.system\s*\(/, label: "os.system()", severity: "high", languages: ["python"] },
  { re: /\bsubprocess\.(?:run|call|Popen|check_output|check_call)\s*\([^)]*shell\s*=\s*True/, label: "subprocess with shell=True", severity: "high", languages: ["python"] },
  { re: /(?<![\w.])\beval\s*\(\s*[^('"0-9\s]/, label: "eval() on a dynamic value", severity: "high", languages: ["python"] },
  { re: /(?<![\w.])\bexec\s*\(\s*[^('"0-9\s]/, label: "exec() on a dynamic value", severity: "high", languages: ["python"] },
  { re: /\b(?:pickle|marshal|dill)\.loads?\s*\(/, label: "pickle/marshal deserialization (arbitrary code execution on crafted data)", severity: "medium", languages: ["python"] },
];

const OBFUSCATION_PATTERNS: LinePattern[] = [
  { re: /["'][A-Za-z0-9+/]{300,}={0,2}["']/, label: "very long base64 blob (likely a hidden payload)", severity: "high" },
  { re: /(?:\\x[0-9a-fA-F]{2}){12,}/, label: "long hex-escaped byte sequence", severity: "high" },
  { re: /Buffer\.from\s*\([^)]*["']base64["']\s*\)/, label: "Buffer.from(..., 'base64') — check what is decoded", severity: "medium", languages: ["javascript", "typescript"] },
  { re: /\batob\s*\(/, label: "atob() base64 decode — check what is decoded", severity: "medium", languages: ["javascript", "typescript"] },
  { re: /base64\.(?:b64decode|urlsafe_b64decode)\s*\(/, label: "base64 decode — check what is decoded", severity: "medium", languages: ["python"] },
  { re: /codecs\.decode\s*\([^)]*["']rot/i, label: "rot13 decode (obfuscation)", severity: "medium", languages: ["python"] },
  { re: /\\u[0-9a-fA-F]{4}(?:\\u[0-9a-fA-F]{4}){7,}/, label: "long unicode-escape sequence", severity: "medium" },
];

function scanLines(
  artifact: Extract<Artifact, { kind: "source-file" }>,
  ruleId: string,
  title: string,
  description: string,
  patterns: LinePattern[],
  remediation: string,
): Finding[] {
  const { language } = artifact.file;
  const code = stripLineComments(artifact.file.content, language);
  const findings: Finding[] = [];
  const seenLines = new Set<number>();
  for (const { re, label, severity, languages } of patterns) {
    if (languages && !languages.includes(language)) continue;
    const global = new RegExp(re.source, re.flags.includes("g") ? re.flags : re.flags + "g");
    let m: RegExpExecArray | null;
    while ((m = global.exec(code)) !== null) {
      const line = lineOf(code, m.index);
      if (seenLines.has(line)) continue;
      seenLines.add(line);
      findings.push({
        ruleId,
        severity,
        title: `${title}: ${label}`,
        description,
        location: { file: artifact.file.path, line, server: artifact.server },
        evidence: truncate(m[0]),
        remediation,
      });
      if (findings.length >= 10) return findings; // per-file cap keeps reports readable
    }
  }
  return findings;
}

export const dangerousExecution: Rule = {
  id: "AG-S001",
  name: "Dangerous code execution",
  description: "eval, shell exec with dynamic input, and deserialization give the server (and anything controlling it) arbitrary code execution.",
  defaultSeverity: "high",
  appliesTo: ["source-file"],
  check(artifact: Artifact): Finding[] {
    if (artifact.kind !== "source-file" || artifact.file.language === "json" || artifact.file.language === "other") return [];
    return scanLines(
      artifact,
      "AG-S001",
      "Dangerous execution primitive",
      "This server can execute dynamically constructed commands. Combined with prompt-influenced arguments, this is the main command-injection surface of MCP servers.",
      EXECUTION_PATTERNS,
      "Pass commands as fixed strings with typed arguments (spawn with an argv array, shell:false), never interpolate agent-controlled values into a shell string.",
    );
  },
};

export const sensitiveFileAccess: Rule = {
  id: "AG-S002",
  name: "Sensitive file access in source",
  description: "The server reads SSH keys, cloud credentials, or other secret files.",
  defaultSeverity: "high",
  appliesTo: ["source-file"],
  check(artifact: Artifact): Finding[] {
    if (artifact.kind !== "source-file") return [];
    const code = stripLineComments(artifact.file.content, artifact.file.language);
    const findings: Finding[] = [];
    const ACCESS_RE = /(?:readFileSync|readFile|open|createReadStream|load_file|Path)\s*\(\s*["'`]([^"'`]+)["'`]/g;
    let m: RegExpExecArray | null;
    while ((m = ACCESS_RE.exec(code)) !== null) {
      const target = m[1]!;
      const hit = firstMatch(target, SENSITIVE_PATH_PATTERNS);
      if (!hit) continue;
      findings.push({
        ruleId: "AG-S002",
        severity: "high",
        title: `Reads sensitive file ${truncate(target, 60)}`,
        description: "The server reads credential material from disk. Anything the agent returns can carry these secrets to a remote endpoint or into a prompt.",
        location: { file: artifact.file.path, line: lineOf(code, m.index), server: artifact.server },
        evidence: truncate(m[0]),
        remediation: "Remove credential-file access. Inject secrets through narrowly scoped environment variables instead.",
      });
    }
    return findings;
  },
};

const NETWORK_CALL_RE = /\b(?:fetch|axios\.(?:get|post)|https?\.(?:get|request)|urllib\.request\.urlopen|requests\.(?:get|post)|httpx\.(?:get|post))\s*\(/;

export const networkExfiltration: Rule = {
  id: "AG-S003",
  name: "Potential data exfiltration in source",
  description: "Network calls that carry environment variables, file contents, or go to known data-sink services.",
  defaultSeverity: "high",
  appliesTo: ["source-file"],
  check(artifact: Artifact): Finding[] {
    if (artifact.kind !== "source-file") return [];
    const code = stripLineComments(artifact.file.content, artifact.file.language);
    const findings: Finding[] = [];

    const sink = firstMatch(code, EXFIL_ENDPOINT_PATTERNS);
    if (sink) {
      findings.push({
        ruleId: "AG-S003",
        severity: "critical",
        title: `Hardcoded data-sink endpoint (${truncate(sink.match, 60)})`,
        description: "The source references a known exfiltration/data-sink service. There is no legitimate reason for an MCP server to post to it.",
        location: { file: artifact.file.path, line: lineOf(code, sink.index), server: artifact.server },
        evidence: truncate(sink.match),
        remediation: "Remove this server and rotate any credentials the agent could access.",
      });
    }

    const lines = code.split("\n");
    lines.forEach((line, i) => {
      if (!NETWORK_CALL_RE.test(line)) return;
      const window = lines.slice(Math.max(0, i - 3), i + 4).join("\n");
      if (/process\.env|os\.environ|readFileSync|readFile|\.env\b/i.test(window)) {
        findings.push({
          ruleId: "AG-S003",
          severity: "high",
          title: "Network call near secret/file access",
          description: "A network request is constructed within a few lines of reading environment variables or files — the classic exfiltration shape.",
          location: { file: artifact.file.path, line: i + 1, server: artifact.server },
          evidence: truncate(line),
          remediation: "Verify exactly what data leaves the process. Network egress should use fixed payloads, never secret-derived values.",
        });
      }
    });
    return findings.slice(0, 10);
  },
};

export const obfuscatedCode: Rule = {
  id: "AG-S004",
  name: "Obfuscated code",
  description: "Base64 blobs, hex escapes, and decoded-then-executed payloads hide behavior from reviewers.",
  defaultSeverity: "medium",
  appliesTo: ["source-file"],
  check(artifact: Artifact): Finding[] {
    if (artifact.kind !== "source-file" || artifact.file.language === "json" || artifact.file.language === "other") return [];
    return scanLines(
      artifact,
      "AG-S004",
      "Obfuscation",
      "Obfuscated content defeats human and tool review. It is rare in legitimate MCP servers and common in malicious ones.",
      OBFUSCATION_PATTERNS,
      "Decode the blob and review what it contains. If it decodes to executable code, treat the server as malicious.",
    );
  },
};

export const hardcodedSecretInSource: Rule = {
  id: "AG-S005",
  name: "Hardcoded secret in source",
  description: "Live credentials committed in source code.",
  defaultSeverity: "medium",
  appliesTo: ["source-file"],
  check(artifact: Artifact): Finding[] {
    if (artifact.kind !== "source-file") return [];
    const findings: Finding[] = [];
    for (const re of SECRET_VALUE_PATTERNS) {
      const m = re.exec(artifact.file.content);
      if (m) {
        findings.push({
          ruleId: "AG-S005",
          severity: "medium",
          title: "Hardcoded credential in source",
          description: "A live-looking credential is committed in the server's source. It will leak with the repo, the npm tarball, and every fork.",
          location: { file: artifact.file.path, line: lineOf(artifact.file.content, m.index), server: artifact.server },
          evidence: truncate(m[0].slice(0, 10) + "…"),
          remediation: "Move the secret to an environment variable and rotate it.",
        });
        break;
      }
    }
    return findings;
  },
};

export const sourceRules: Rule[] = [
  dangerousExecution,
  sensitiveFileAccess,
  networkExfiltration,
  obfuscatedCode,
  hardcodedSecretInSource,
];
