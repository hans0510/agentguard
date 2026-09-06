import { createHash } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { Finding, ServerConfig, ToolDefinition } from "../types.js";
import { probeAll } from "../probe/stdio.js";
import { truncate } from "../util/text.js";

export const LOCKFILE_NAME = "agentguard.lock.json";
const LOCKFILE_VERSION = 1;

export interface LockedTool {
  descriptionHash: string;
  schemaHash: string;
}

export interface LockedServer {
  command?: string;
  args?: string[];
  url?: string;
  packageHash?: string;
  tools: Record<string, LockedTool>;
  lockedAt: string;
}

export interface Lockfile {
  version: number;
  createdAt: string;
  servers: Record<string, LockedServer>;
}

export function hashText(text: string): string {
  return "sha256:" + createHash("sha256").update(text, "utf8").digest("hex").slice(0, 32);
}

function hashTool(tool: ToolDefinition): LockedTool {
  return {
    descriptionHash: hashText(tool.description ?? ""),
    schemaHash: hashText(JSON.stringify(tool.inputSchema ?? null)),
  };
}

/** Probe servers and write a lockfile pinning every tool description + schema hash. */
export async function createLockfile(root: string, servers: ServerConfig[], timeoutMs: number): Promise<{
  lockfile: Lockfile;
  probed: number;
  failed: Array<{ server: string; error: string }>;
}> {
  const stdioServers = servers.filter((s) => s.transport === "stdio" && s.command);
  const remoteServers = servers.filter((s) => s.transport !== "stdio");
  const results = await probeAll(stdioServers, timeoutMs);

  const lockfile: Lockfile = {
    version: LOCKFILE_VERSION,
    createdAt: new Date().toISOString(),
    servers: {},
  };
  const failed: Array<{ server: string; error: string }> = [];

  for (const result of results) {
    if (!result.ok) {
      failed.push({ server: result.server, error: result.error ?? "unknown error" });
      continue;
    }
    const config = stdioServers.find((s) => s.name === result.server)!;
    const tools: Record<string, LockedTool> = {};
    for (const tool of result.tools) tools[tool.name] = hashTool(tool);
    lockfile.servers[result.server] = {
      command: config.command,
      args: config.args,
      tools,
      lockedAt: new Date().toISOString(),
    };
  }

  // Remote servers can't be probed over stdio here; pin their endpoint so at least the URL is fixed.
  for (const s of remoteServers) {
    lockfile.servers[s.name] = { url: s.url, tools: {}, lockedAt: new Date().toISOString() };
  }

  writeFileSync(join(root, LOCKFILE_NAME), JSON.stringify(lockfile, null, 2) + "\n");
  return { lockfile, probed: results.filter((r) => r.ok).length, failed };
}

export function readLockfile(root: string): Lockfile | null {
  const path = join(root, LOCKFILE_NAME);
  if (!existsSync(path)) return null;
  try {
    return JSON.parse(readFileSync(path, "utf8")) as Lockfile;
  } catch {
    return null;
  }
}

/** Re-probe servers and diff against the lockfile. Any drift = rug pull. */
export async function verifyLockfile(
  root: string,
  servers: ServerConfig[],
  timeoutMs: number,
): Promise<{ findings: Finding[]; verified: number; failed: Array<{ server: string; error: string }> }> {
  const lockfile = readLockfile(root);
  if (!lockfile) {
    return {
      findings: [
        {
          ruleId: "AG-L000",
          severity: "info",
          title: `No ${LOCKFILE_NAME} found`,
          description: "Run `agentguard lock` first to pin tool descriptions, then `agentguard verify` in CI to detect rug pulls.",
          location: {},
        },
      ],
      verified: 0,
      failed: [],
    };
  }

  const findings: Finding[] = [];
  const stdioServers = servers.filter((s) => s.transport === "stdio" && s.command && lockfile.servers[s.name]);
  const results = await probeAll(stdioServers, timeoutMs);
  const failed: Array<{ server: string; error: string }> = [];
  let verified = 0;

  for (const result of results) {
    if (!result.ok) {
      failed.push({ server: result.server, error: result.error ?? "unknown error" });
      continue;
    }
    verified++;
    const locked = lockfile.servers[result.server]!;
    const liveTools = new Map(result.tools.map((t) => [t.name, t]));
    const lockedNames = new Set(Object.keys(locked.tools));

    for (const [name, tool] of liveTools) {
      const lockedTool = locked.tools[name];
      if (!lockedTool) {
        findings.push({
          ruleId: "AG-L002",
          severity: "medium",
          title: `New tool "${name}" appeared in server "${result.server}"`,
          description: "A tool that did not exist when you locked this server is now exposed. Review what it does — servers gain capabilities silently on update.",
          location: { server: result.server, tool: name },
          remediation: "If the change is expected, re-run `agentguard lock` after reviewing the new tool.",
        });
        continue;
      }
      const live = hashTool(tool);
      if (live.descriptionHash !== lockedTool.descriptionHash) {
        findings.push({
          ruleId: "AG-L001",
          severity: "critical",
          title: `Tool description changed: "${name}" in "${result.server}" (rug pull)`,
          description:
            `The description of "${name}" changed since you approved it. This is the rug-pull attack: ` +
            "a server you vetted can later inject instructions into your agent's context by editing tool descriptions server-side.",
          location: { server: result.server, tool: name },
          evidence: truncate(tool.description ?? "", 200),
          remediation: "Do not use this server until you have reviewed the new description. Rotate credentials if it ran in between.",
          references: ["https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks"],
        });
      }
      if (live.schemaHash !== lockedTool.schemaHash) {
        findings.push({
          ruleId: "AG-L003",
          severity: "medium",
          title: `Tool input schema changed: "${name}" in "${result.server}"`,
          description: "The parameter schema changed since lock. New parameters can request data the tool never asked for before.",
          location: { server: result.server, tool: name },
          remediation: "Review the new schema; re-lock with `agentguard lock` if it is a legitimate update.",
        });
      }
    }
    for (const name of lockedNames) {
      if (!liveTools.has(name)) {
        findings.push({
          ruleId: "AG-L002",
          severity: "low",
          title: `Tool "${name}" removed from server "${result.server}"`,
          description: "A tool present at lock time no longer exists. Usually harmless, but unexpected downgrades deserve a look.",
          location: { server: result.server, tool: name },
        });
      }
    }
  }
  return { findings, verified, failed };
}
