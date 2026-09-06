import type { ObservedCapabilities, SourceFile } from "../types.js";

const URL_RE = /https?:\/\/([a-zA-Z0-9.-]+)(?::\d+)?/g;
const ENV_JS_RE = /process\.env\.([A-Z][A-Z0-9_]+)|process\.env\[["']([A-Z][A-Z0-9_]+)["']\]/g;
const ENV_PY_RE = /os\.environ(?:\.get)?\(?\[?["']([A-Z][A-Z0-9_]+)["']|os\.getenv\(["']([A-Z][A-Z0-9_]+)["']/g;
const PATH_RE = /(?:readFileSync|readFile|writeFileSync|writeFile|open|createReadStream|createWriteStream)\s*\(\s*["'`]([^"'`]+)["'`]/g;
const SHELL_RE = /\b(?:execSync|exec|spawn|spawnSync)\s*\(|shell\s*:\s*true|os\.system\s*\(|subprocess\.(?:run|call|Popen|check_output)\s*\(/;
const WRITE_RE = /\b(?:writeFileSync|writeFile|createWriteStream|appendFile)\s*\(|open\s*\([^)]*["'][wa]["']/;

/** Extract an observed capability manifest from source files. This is the
 *  answer to "100% of MCP servers ship without permission declarations":
 *  we derive one from what the code actually does. */
export function extractCapabilities(server: string, files: SourceFile[]): ObservedCapabilities {
  const hosts = new Set<string>();
  const envVars = new Set<string>();
  const paths = new Set<string>();
  let usesShell = false;
  let writesFiles = false;

  for (const file of files) {
    const { content } = file;
    for (const m of content.matchAll(URL_RE)) {
      const host = m[1]!;
      if (!/^(localhost|127\.0\.0\.1|0\.0\.0\.0|example\.(com|org)|schemas?\.)/.test(host)) hosts.add(host);
    }
    for (const re of [ENV_JS_RE, ENV_PY_RE]) {
      for (const m of content.matchAll(re)) {
        const v = m[1] ?? m[2];
        if (v && !/^(PATH|HOME|USER|SHELL|TERM|PWD|LANG|NODE_ENV|TMPDIR|TEMP)$/.test(v)) envVars.add(v);
      }
    }
    for (const m of content.matchAll(PATH_RE)) {
      const p = m[1]!;
      if (p.length > 1 && p.length < 120) paths.add(p);
    }
    if (SHELL_RE.test(content)) usesShell = true;
    if (WRITE_RE.test(content)) writesFiles = true;
  }

  return {
    server,
    networkHosts: [...hosts].sort(),
    envVars: [...envVars].sort(),
    filePaths: [...paths].sort(),
    usesShell,
    writesFiles,
  };
}
