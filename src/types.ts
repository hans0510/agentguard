export type Severity = "critical" | "high" | "medium" | "low" | "info";

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

export interface Location {
  file?: string;
  line?: number;
  /** MCP server name the finding belongs to */
  server?: string;
  /** Tool name the finding belongs to */
  tool?: string;
}

export interface Finding {
  ruleId: string;
  severity: Severity;
  title: string;
  description: string;
  location: Location;
  /** The matched content that proves the finding (truncated) */
  evidence?: string;
  remediation?: string;
  references?: string[];
}

export type Transport = "stdio" | "http" | "sse";

export interface ServerConfig {
  name: string;
  /** Which client config this came from, e.g. "claude-desktop", "cursor" */
  client: string;
  /** Absolute path of the config file */
  source: string;
  transport: Transport;
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  url?: string;
  headers?: Record<string, string>;
}

export interface ToolDefinition {
  name: string;
  description?: string;
  inputSchema?: unknown;
}

export interface SkillFile {
  path: string;
  kind: "skill" | "agents-md" | "claude-md" | "cursor-rule" | "copilot" | "other";
  content: string;
}

export interface SourceFile {
  path: string;
  language: "javascript" | "typescript" | "python" | "shell" | "json" | "other";
  content: string;
}

export type Artifact =
  | { kind: "server-config"; server: ServerConfig }
  | { kind: "tool"; server: string; tool: ToolDefinition; source: "probe" | "lockfile" | "static" }
  | { kind: "source-file"; server?: string; file: SourceFile }
  | { kind: "skill-file"; file: SkillFile };

export interface ScanContext {
  /** All server configs discovered in this scan (for cross-server rules) */
  servers: ServerConfig[];
  /** Root directory being scanned */
  root: string;
}

export interface Rule {
  /** Stable id, e.g. "AG-T001" */
  id: string;
  name: string;
  description: string;
  defaultSeverity: Severity;
  appliesTo: Array<Artifact["kind"]>;
  check(artifact: Artifact, ctx: ScanContext): Finding[];
}

/** Capabilities observed from source code / config — the basis of a permission manifest */
export interface ObservedCapabilities {
  server: string;
  networkHosts: string[];
  envVars: string[];
  filePaths: string[];
  usesShell: boolean;
  writesFiles: boolean;
}

export interface ServerReport {
  server: ServerConfig;
  findings: Finding[];
  capabilities?: ObservedCapabilities;
  score: number;
  grade: "A" | "B" | "C" | "D" | "F";
}

export interface ScanReport {
  tool: string;
  version: string;
  scannedAt: string;
  root: string;
  servers: ServerReport[];
  skillFindings: Finding[];
  unassignedFindings: Finding[];
  summary: {
    totalFindings: number;
    bySeverity: Record<Severity, number>;
    worstGrade: "A" | "B" | "C" | "D" | "F";
  };
}
