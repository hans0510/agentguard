import { resolve } from "node:path";
import type { Artifact, ScanReport, ServerConfig, ServerReport, Severity, ToolDefinition } from "./types.js";
import { discoverConfigs, parseExplicitConfig } from "./discover/configs.js";
import { discoverSkillFiles } from "./discover/skills.js";
import { collectDirectorySources, resolveLocalSources } from "./discover/sources.js";
import { extractCapabilities } from "./engine/capabilities.js";
import { bucketFindings, runScan } from "./engine/scanner.js";
import { gradeScore, scoreFindings, worstGrade } from "./engine/score.js";
import { allRules } from "./rules/index.js";
import { probeAll } from "./probe/stdio.js";
import { SEVERITY_ORDER } from "./types.js";

export const VERSION = "0.1.0";

export interface ScanInput {
  root: string;
  /** Explicit config file instead of discovery */
  configPath?: string;
  /** Scan a directory as an MCP server source tree (cloned repo) */
  path?: string;
  /** Extra skill files to include */
  skillPaths?: string[];
  /** Probe stdio servers to inspect live tool definitions (executes server code) */
  probe?: boolean;
  probeTimeoutMs?: number;
}

export async function scan(input: ScanInput): Promise<ScanReport> {
  const root = resolve(input.root);
  const rules = allRules();
  const artifacts: Artifact[] = [];

  // 1. Server configs
  let servers: ServerConfig[];
  if (input.configPath) {
    servers = parseExplicitConfig(input.configPath);
  } else if (input.path) {
    servers = [];
  } else {
    servers = discoverConfigs(root).servers;
  }
  for (const server of servers) artifacts.push({ kind: "server-config", server });

  // 2. Source files: explicit directory scan, or locally-resolvable stdio servers
  const capabilities = new Map<string, ReturnType<typeof extractCapabilities>>();
  if (input.path) {
    const sources = collectDirectorySources(resolve(input.path));
    const pseudoServer = input.path;
    for (const file of sources) artifacts.push({ kind: "source-file", server: pseudoServer, file });
    capabilities.set(pseudoServer, extractCapabilities(pseudoServer, sources));
  } else {
    for (const server of servers) {
      const sources = resolveLocalSources(server, root);
      if (!sources) continue;
      for (const file of sources) artifacts.push({ kind: "source-file", server: server.name, file });
      capabilities.set(server.name, extractCapabilities(server.name, sources));
    }
  }

  // 3. Live tool definitions (opt-in: spawns server processes)
  const knownTools: Array<{ server: string; tool: ToolDefinition }> = [];
  if (input.probe) {
    const results = await probeAll(
      servers.filter((s) => s.transport === "stdio" && s.command),
      input.probeTimeoutMs ?? 15_000,
    );
    for (const r of results) {
      if (!r.ok) continue;
      for (const tool of r.tools) {
        artifacts.push({ kind: "tool", server: r.server, tool, source: "probe" });
        knownTools.push({ server: r.server, tool });
      }
    }
  }

  // 4. Skill / instruction files
  const skillFiles = discoverSkillFiles(root, input.skillPaths ?? []);
  for (const file of skillFiles) artifacts.push({ kind: "skill-file", file });

  // 5. Run rules + bucket
  const findings = runScan({ rules, artifacts, ctx: { servers, root }, knownTools });
  const { perServer, skill, unassigned } = bucketFindings(findings, servers);

  const serverReports: ServerReport[] = servers.map((server) => {
    const serverFindings = perServer.get(server.name) ?? [];
    const score = scoreFindings(serverFindings);
    return {
      server,
      findings: serverFindings.sort(sortBySeverity),
      capabilities: capabilities.get(server.name),
      score,
      grade: gradeScore(serverFindings, score),
    };
  });

  if (input.path) {
    const pathFindings = unassigned.filter((f) => f.location.server === input.path);
    const pseudo: ServerConfig = {
      name: input.path,
      client: "directory",
      source: resolve(input.path),
      transport: "stdio",
    };
    const score = scoreFindings(pathFindings);
    serverReports.push({
      server: pseudo,
      findings: pathFindings.sort(sortBySeverity),
      capabilities: capabilities.get(input.path),
      score,
      grade: gradeScore(pathFindings, score),
    });
    for (const f of pathFindings) unassigned.splice(unassigned.indexOf(f), 1);
  }

  const bySeverity = Object.fromEntries(SEVERITY_ORDER.map((s) => [s, 0])) as Record<Severity, number>;
  for (const f of findings) bySeverity[f.severity]++;

  // Grades for non-server buckets so a critical skill finding sinks the overall grade too.
  const skillGrade = gradeScore(skill, scoreFindings(skill));
  const unassignedGrade = gradeScore(unassigned, scoreFindings(unassigned));

  return {
    tool: "agentguard",
    version: VERSION,
    scannedAt: new Date().toISOString(),
    root,
    servers: serverReports,
    skillFindings: skill.sort(sortBySeverity),
    unassignedFindings: unassigned.sort(sortBySeverity),
    summary: {
      totalFindings: findings.length,
      bySeverity,
      worstGrade: worstGrade([...serverReports.map((s) => s.grade), skillGrade, unassignedGrade]),
    },
  };
}

function sortBySeverity(a: { severity: Severity }, b: { severity: Severity }): number {
  return SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity);
}
