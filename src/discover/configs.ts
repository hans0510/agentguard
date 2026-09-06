import { existsSync, readFileSync } from "node:fs";
import { homedir, platform } from "node:os";
import { join, resolve } from "node:path";
import type { ServerConfig, Transport } from "../types.js";

interface RawServer {
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  url?: string;
  serverUrl?: string;
  type?: string;
  transport?: string;
  headers?: Record<string, string>;
}

interface ConfigLocation {
  client: string;
  path: string;
  /** Which top-level key holds the server map */
  key: string;
}

function home(): string {
  return homedir();
}

function candidateLocations(root: string): ConfigLocation[] {
  const p = platform();
  const locations: ConfigLocation[] = [
    // Project-local configs (highest priority)
    { client: "claude-code (project)", path: join(root, ".mcp.json"), key: "mcpServers" },
    { client: "cursor (project)", path: join(root, ".cursor", "mcp.json"), key: "mcpServers" },
    { client: "vscode (project)", path: join(root, ".vscode", "mcp.json"), key: "servers" },
    { client: "zed (project)", path: join(root, ".zed", "settings.json"), key: "context_servers" },
    // User-level configs
    { client: "claude-code", path: join(home(), ".claude.json"), key: "mcpServers" },
    { client: "cursor", path: join(home(), ".cursor", "mcp.json"), key: "mcpServers" },
    { client: "windsurf", path: join(home(), ".codeium", "windsurf", "mcp_config.json"), key: "mcpServers" },
    { client: "zed", path: join(home(), ".config", "zed", "settings.json"), key: "context_servers" },
    { client: "vscode", path: join(home(), ".config", "Code", "User", "mcp.json"), key: "servers" },
  ];
  if (p === "darwin") {
    locations.push({
      client: "claude-desktop",
      path: join(home(), "Library", "Application Support", "Claude", "claude_desktop_config.json"),
      key: "mcpServers",
    });
  } else if (p === "win32") {
    const appData = process.env.APPDATA ?? join(home(), "AppData", "Roaming");
    locations.push({ client: "claude-desktop", path: join(appData, "Claude", "claude_desktop_config.json"), key: "mcpServers" });
    locations.push({ client: "vscode", path: join(appData, "Code", "User", "mcp.json"), key: "servers" });
  } else {
    locations.push({ client: "claude-desktop", path: join(home(), ".config", "Claude", "claude_desktop_config.json"), key: "mcpServers" });
  }
  return locations;
}

function normalizeTransport(raw: RawServer): Transport {
  if (raw.url || raw.serverUrl) {
    const t = (raw.type ?? raw.transport ?? "").toLowerCase();
    return t === "sse" ? "sse" : "http";
  }
  return "stdio";
}

function parseConfigFile(client: string, path: string, key: string): ServerConfig[] {
  let json: unknown;
  try {
    json = JSON.parse(readFileSync(path, "utf8"));
  } catch {
    return [];
  }
  if (typeof json !== "object" || json === null) return [];
  const servers = (json as Record<string, unknown>)[key];
  if (typeof servers !== "object" || servers === null) return [];
  const out: ServerConfig[] = [];
  for (const [name, rawValue] of Object.entries(servers as Record<string, unknown>)) {
    if (typeof rawValue !== "object" || rawValue === null) continue;
    const raw = rawValue as RawServer;
    out.push({
      name,
      client,
      source: path,
      transport: normalizeTransport(raw),
      command: raw.command,
      args: raw.args,
      env: raw.env,
      url: raw.url ?? raw.serverUrl,
      headers: raw.headers,
    });
  }
  return out;
}

export interface DiscoveredConfigs {
  servers: ServerConfig[];
  configFiles: string[];
  searched: number;
}

/** Discover MCP server configs from all known clients, plus a project root. */
export function discoverConfigs(root: string): DiscoveredConfigs {
  const servers: ServerConfig[] = [];
  const configFiles: string[] = [];
  let searched = 0;
  for (const loc of candidateLocations(resolve(root))) {
    searched++;
    if (!existsSync(loc.path)) continue;
    const parsed = parseConfigFile(loc.client, loc.path, loc.key);
    if (parsed.length > 0) {
      configFiles.push(loc.path);
      servers.push(...parsed);
    }
  }
  return { servers, configFiles, searched };
}

/** Parse one explicit config file (mcpServers-style), used for --config. */
export function parseExplicitConfig(path: string): ServerConfig[] {
  for (const key of ["mcpServers", "servers", "context_servers"]) {
    const parsed = parseConfigFile("explicit", resolve(path), key);
    if (parsed.length > 0) return parsed;
  }
  return [];
}
