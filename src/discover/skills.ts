import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { basename, join } from "node:path";
import type { SkillFile } from "../types.js";

const MAX_FILE_BYTES = 512 * 1024;

function classify(path: string): SkillFile["kind"] {
  const base = basename(path).toLowerCase();
  if (base === "skill.md") return "skill";
  if (base === "agents.md") return "agents-md";
  if (base === "claude.md") return "claude-md";
  if (base === "copilot-instructions.md") return "copilot";
  if (base.endsWith(".mdc")) return "cursor-rule";
  return "other";
}

function readSafe(path: string): string | null {
  try {
    if (statSync(path).size > MAX_FILE_BYTES) return null;
    return readFileSync(path, "utf8");
  } catch {
    return null;
  }
}

function walk(dir: string, depth: number, out: string[]): void {
  if (depth > 6) return;
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const e of entries) {
    if (e.name === "node_modules" || e.name === ".git" || e.name.startsWith(".") && e.name !== ".claude" && e.name !== ".cursor" && e.name !== ".github") continue;
    const p = join(dir, e.name);
    if (e.isDirectory()) walk(p, depth + 1, out);
    else if (e.isFile()) out.push(p);
  }
}

/** Files that act as agent instructions: skills, AGENTS.md, cursor rules, copilot instructions… */
export function discoverSkillFiles(root: string, explicitPaths: string[] = []): SkillFile[] {
  const candidates = new Set<string>();

  const direct = [
    join(root, "AGENTS.md"),
    join(root, "CLAUDE.md"),
    join(root, "GEMINI.md"),
    join(root, ".github", "copilot-instructions.md"),
  ];
  for (const f of direct) if (existsSync(f)) candidates.add(f);

  for (const dir of [
    join(root, ".claude", "skills"),
    join(root, ".cursor", "rules"),
    join(root, ".agents", "skills"),
    join(homedir(), ".claude", "skills"),
  ]) {
    if (!existsSync(dir)) continue;
    const files: string[] = [];
    walk(dir, 0, files);
    for (const f of files) {
      if (/\.(md|mdc|markdown)$/i.test(f)) candidates.add(f);
    }
  }

  for (const p of explicitPaths) {
    if (existsSync(p)) candidates.add(p);
  }

  const out: SkillFile[] = [];
  for (const path of candidates) {
    const content = readSafe(path);
    if (content !== null) out.push({ path, kind: classify(path), content });
  }
  return out.sort((a, b) => a.path.localeCompare(b.path));
}
