import type { Finding, ScanReport, Severity } from "../types.js";

const useColor = process.stdout.isTTY && !process.env.NO_COLOR;

const C = {
  reset: (s: string) => (useColor ? `[0m${s}[0m` : s),
  bold: (s: string) => (useColor ? `[1m${s}[0m` : s),
  dim: (s: string) => (useColor ? `[2m${s}[0m` : s),
  red: (s: string) => (useColor ? `[31m${s}[0m` : s),
  yellow: (s: string) => (useColor ? `[33m${s}[0m` : s),
  blue: (s: string) => (useColor ? `[34m${s}[0m` : s),
  magenta: (s: string) => (useColor ? `[35m${s}[0m` : s),
  cyan: (s: string) => (useColor ? `[36m${s}[0m` : s),
  green: (s: string) => (useColor ? `[32m${s}[0m` : s),
};

const SEVERITY_STYLE: Record<Severity, { label: string; paint: (s: string) => string }> = {
  critical: { label: "CRIT", paint: (s) => C.bold(C.red(s)) },
  high: { label: "HIGH", paint: C.red },
  medium: { label: "MED ", paint: C.yellow },
  low: { label: "LOW ", paint: C.blue },
  info: { label: "INFO", paint: C.dim },
};

function gradeColor(grade: string, s: string): string {
  if (grade === "A") return C.green(s);
  if (grade === "B" || grade === "C") return C.yellow(s);
  return C.red(s);
}

function formatFinding(f: Finding, indent = "  "): string {
  const sev = SEVERITY_STYLE[f.severity];
  const where: string[] = [];
  if (f.location.file) where.push(f.location.line ? `${f.location.file}:${f.location.line}` : f.location.file);
  if (f.location.tool) where.push(`tool=${f.location.tool}`);
  const lines = [
    `${indent}${sev.paint(sev.label)} ${C.bold(f.title)} ${C.dim(`[${f.ruleId}]`)}`,
    `${indent}     ${C.dim(where.join("  "))}`,
    `${indent}     ${f.description}`,
  ];
  if (f.evidence) lines.push(`${indent}     ${C.magenta("evidence:")} ${f.evidence}`);
  if (f.remediation) lines.push(`${indent}     ${C.cyan("fix:")} ${f.remediation}`);
  return lines.join("\n");
}

export function renderTerminal(report: ScanReport, opts: { quiet?: boolean } = {}): string {
  const out: string[] = [];
  out.push("");
  out.push(C.bold(`agentguard ${report.version}`) + C.dim(` — ${report.servers.length} MCP server(s), scanned ${report.scannedAt}`));
  out.push("");

  for (const server of report.servers) {
    const grade = server.grade;
    const name = server.server.name;
    const via = server.server.transport === "stdio"
      ? `${server.server.command} ${(server.server.args ?? []).join(" ")}`.trim()
      : server.server.url ?? "";
    out.push(`${C.bold(name)} ${gradeColor(grade, `[${grade}]`)} ${C.dim(`(${server.server.client}) ${via}`)}`);
    if (server.findings.length === 0) {
      out.push(`  ${C.green("no findings")}`);
    } else {
      for (const f of server.findings) {
        if (opts.quiet && (f.severity === "info" || f.severity === "low")) continue;
        out.push(formatFinding(f));
      }
    }
    if (server.capabilities && !opts.quiet) {
      const cap = server.capabilities;
      const parts: string[] = [];
      if (cap.networkHosts.length > 0) parts.push(`network → ${cap.networkHosts.join(", ")}`);
      if (cap.envVars.length > 0) parts.push(`env → ${cap.envVars.join(", ")}`);
      if (cap.usesShell) parts.push("shell exec");
      if (cap.writesFiles) parts.push("file writes");
      if (parts.length > 0) out.push(`  ${C.dim("observed capabilities:")} ${C.dim(parts.join(" · "))}`);
    }
    out.push("");
  }

  if (report.skillFindings.length > 0) {
    out.push(C.bold("Skill / instruction files"));
    for (const f of report.skillFindings) {
      if (opts.quiet && (f.severity === "info" || f.severity === "low")) continue;
      out.push(formatFinding(f));
    }
    out.push("");
  }

  if (report.unassignedFindings.length > 0) {
    out.push(C.bold("Other findings"));
    for (const f of report.unassignedFindings) {
      if (opts.quiet && (f.severity === "info" || f.severity === "low")) continue;
      out.push(formatFinding(f));
    }
    out.push("");
  }

  const s = report.summary;
  const counts = (Object.keys(s.bySeverity) as Severity[])
    .filter((k) => s.bySeverity[k] > 0)
    .map((k) => `${SEVERITY_STYLE[k].paint(`${s.bySeverity[k]} ${k}`)}`)
    .join(", ");
  out.push(
    s.totalFindings === 0
      ? C.green("✔ no security findings")
      : `${C.bold(`${s.totalFindings} finding(s)`)}: ${counts}  ${C.dim(`worst grade: `)}${gradeColor(s.worstGrade, s.worstGrade)}`,
  );
  out.push("");
  return out.join("\n");
}
