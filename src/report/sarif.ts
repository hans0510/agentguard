import type { Finding, ScanReport, Severity } from "../types.js";

const SARIF_LEVEL: Record<Severity, "error" | "warning" | "note"> = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "note",
  info: "note",
};

interface SarifResult {
  ruleId: string;
  level: "error" | "warning" | "note";
  message: { text: string };
  locations: Array<{
    physicalLocation: {
      artifactLocation: { uri: string };
      region?: { startLine: number };
    };
  }>;
}

/** SARIF 2.1.0 — upload to GitHub code scanning for PR annotations. */
export function renderSarif(report: ScanReport): string {
  const allFindings: Finding[] = [
    ...report.servers.flatMap((s) => s.findings),
    ...report.skillFindings,
    ...report.unassignedFindings,
  ];

  const ruleIds = [...new Set(allFindings.map((f) => f.ruleId))];
  const results: SarifResult[] = allFindings.map((f) => ({
    ruleId: f.ruleId,
    level: SARIF_LEVEL[f.severity],
    message: { text: `${f.title}\n${f.description}${f.remediation ? `\nFix: ${f.remediation}` : ""}` },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: f.location.file ?? report.root },
          ...(f.location.line ? { region: { startLine: f.location.line } } : {}),
        },
      },
    ],
  }));

  const sarif = {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "agentguard",
            version: report.version,
            informationUri: "https://github.com/agentguard/agentguard",
            rules: ruleIds.map((id) => ({ id })),
          },
        },
        results,
      },
    ],
  };
  return JSON.stringify(sarif, null, 2) + "\n";
}
