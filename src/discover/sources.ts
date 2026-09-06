import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { extname, isAbsolute, join, resolve } from "node:path";
import type { ServerConfig, SourceFile } from "../types.js";

const MAX_FILE_BYTES = 1024 * 1024;
const MAX_FILES_PER_SERVER = 200;

const EXT_LANGUAGE: Record<string, SourceFile["language"]> = {
  ".js": "javascript",
  ".mjs": "javascript",
  ".cjs": "javascript",
  ".jsx": "javascript",
  ".ts": "typescript",
  ".tsx": "typescript",
  ".mts": "typescript",
  ".cts": "typescript",
  ".py": "python",
  ".sh": "shell",
  ".bash": "shell",
  ".json": "json",
};

function collectFiles(dir: string, out: string[], depth: number): void {
  if (depth > 5 || out.length >= MAX_FILES_PER_SERVER) return;
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const e of entries) {
    if (out.length >= MAX_FILES_PER_SERVER) return;
    if (e.name === "node_modules" || e.name === ".git" || e.name === "__pycache__") continue;
    const p = join(dir, e.name);
    if (e.isDirectory()) collectFiles(p, out, depth + 1);
    else if (e.isFile() && EXT_LANGUAGE[extname(e.name).toLowerCase()]) out.push(p);
  }
}

function readSource(path: string): SourceFile | null {
  try {
    if (statSync(path).size > MAX_FILE_BYTES) return null;
    const content = readFileSync(path, "utf8");
    return { path, language: EXT_LANGUAGE[extname(path).toLowerCase()] ?? "other", content };
  } catch {
    return null;
  }
}

/** Resolve the local source a stdio server runs, when possible:
 *  - direct script paths (node /abs/path/server.js, python ./server.py)
 *  - relative script paths resolved against the scan root
 *  Returns null for registry packages (npx pkg) unless --deep fetched them. */
export function resolveLocalSources(server: ServerConfig, root: string): SourceFile[] | null {
  if (server.transport !== "stdio" || !server.command) return null;
  const candidates: string[] = [];
  for (const arg of server.args ?? []) {
    if (arg.startsWith("-")) continue;
    if (!/\.(?:js|mjs|cjs|ts|py|sh)$/i.test(arg)) continue;
    candidates.push(isAbsolute(arg) ? arg : resolve(root, arg));
  }
  // Windows-style: command itself may be a script
  if (/\.(?:js|mjs|cjs|ts|py|sh)$/i.test(server.command)) {
    candidates.push(isAbsolute(server.command) ? server.command : resolve(root, server.command));
  }
  for (const path of candidates) {
    if (!existsSync(path)) continue;
    if (statSync(path).isDirectory()) {
      const files: string[] = [];
      collectFiles(path, files, 0);
      const sources = files.map(readSource).filter((f): f is SourceFile => f !== null);
      return sources.length > 0 ? sources : null;
    }
    const single = readSource(path);
    if (single) {
      // Also scan the package directory around the entry file (max 2 levels up to a package root)
      return [single];
    }
  }
  return null;
}

/** Collect all scannable source files under a directory (for `scan --path` of a cloned server). */
export function collectDirectorySources(dir: string): SourceFile[] {
  const files: string[] = [];
  collectFiles(dir, files, 0);
  return files.map(readSource).filter((f): f is SourceFile => f !== null);
}
