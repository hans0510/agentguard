#!/usr/bin/env node
import { resolve } from "node:path";
import { scan, VERSION } from "./scan.js";
import { discoverConfigs } from "./discover/configs.js";
import { createLockfile, LOCKFILE_NAME, verifyLockfile } from "./lockfile/lock.js";
import { allRules } from "./rules/index.js";
import { renderTerminal } from "./report/terminal.js";
import { renderJson } from "./report/json.js";
import { renderSarif } from "./report/sarif.js";
import type { Severity } from "./types.js";
import { SEVERITY_ORDER } from "./types.js";

const HELP = `agentguard ${VERSION} — security scanner for AI agents

Usage:
  agentguard scan [dir] [options]   Scan MCP configs, skills, and server source
  agentguard lock [dir]             Pin tool descriptions (rug-pull protection)
  agentguard verify [dir]           Diff live tools against ${LOCKFILE_NAME}
  agentguard rules                  List detection rules
  agentguard init                   Print a GitHub Actions workflow for CI

scan options:
  --config <file>       Scan one MCP config file instead of discovery
  --path <dir>          Scan a directory as MCP server source (cloned repo)
  --skills <files...>   Extra skill/instruction files to include
  --probe               Spawn stdio servers to inspect live tool definitions
                        (executes server code — use with care)
  --format <fmt>        terminal (default) | json | sarif
  --fail-on <sev>       Exit 1 if findings >= severity (critical|high|medium|low)
  --quiet               Only show medium and above
  --timeout <ms>        Probe timeout per server (default 15000)

Examples:
  agentguard scan                        # scan this machine's agent configs
  agentguard scan --probe                # + inspect live tool descriptions
  agentguard scan --path ./some-mcp      # audit a cloned MCP server
  agentguard lock && agentguard verify   # pin, then detect rug pulls
  agentguard scan --format sarif > results.sarif
`;

interface ParsedArgs {
  command: string;
  positional: string[];
  flags: Map<string, string | boolean>;
}

function parseArgs(argv: string[]): ParsedArgs {
  const [command = "help", ...rest] = argv;
  const positional: string[] = [];
  const flags = new Map<string, string | boolean>();
  for (let i = 0; i < rest.length; i++) {
    const arg = rest[i]!;
    if (arg.startsWith("--")) {
      const key = arg.slice(2);
      const next = rest[i + 1];
      if (next !== undefined && !next.startsWith("--")) {
        flags.set(key, next);
        i++;
      } else {
        flags.set(key, true);
      }
    } else {
      positional.push(arg);
    }
  }
  return { command, positional, flags };
}

function flagString(flags: Map<string, string | boolean>, key: string): string | undefined {
  const v = flags.get(key);
  return typeof v === "string" ? v : undefined;
}

function exitCodeFor(report: { summary: { bySeverity: Record<Severity, number> } }, failOn?: string): number {
  if (!failOn) return report.summary.bySeverity.critical > 0 || report.summary.bySeverity.high > 0 ? 1 : 0;
  const threshold = SEVERITY_ORDER.indexOf(failOn as Severity);
  if (threshold === -1) return 0;
  for (const sev of SEVERITY_ORDER.slice(0, threshold + 1)) {
    if (report.summary.bySeverity[sev] > 0) return 1;
  }
  return 0;
}

async function main(): Promise<void> {
  const { command, positional, flags } = parseArgs(process.argv.slice(2));
  const root = resolve(positional[0] ?? ".");

  switch (command) {
    case "scan": {
      const format = flagString(flags, "format") ?? "terminal";
      const report = await scan({
        root,
        configPath: flagString(flags, "config"),
        path: flagString(flags, "path"),
        skillPaths: typeof flags.get("skills") === "string" ? [flags.get("skills") as string] : [],
        probe: flags.has("probe"),
        probeTimeoutMs: Number(flagString(flags, "timeout") ?? 15_000),
      });
      if (format === "json") process.stdout.write(renderJson(report));
      else if (format === "sarif") process.stdout.write(renderSarif(report));
      else process.stdout.write(renderTerminal(report, { quiet: flags.has("quiet") }));
      process.exit(exitCodeFor(report, flagString(flags, "fail-on")));
      break;
    }

    case "lock": {
      const { servers } = discoverConfigs(root);
      if (servers.length === 0) {
        console.error("No MCP server configs found on this machine.");
        process.exit(2);
      }
      console.error(`Probing ${servers.length} server(s) — this executes their code, like your agent client does…`);
      const { lockfile, probed, failed } = await createLockfile(root, servers, Number(flagString(flags, "timeout") ?? 15_000));
      console.error(`Wrote ${LOCKFILE_NAME}: ${Object.keys(lockfile.servers).length} server(s), ${probed} probed OK.`);
      for (const f of failed) console.error(`  ✗ ${f.server}: ${f.error}`);
      process.exit(0);
      break;
    }

    case "verify": {
      const { servers } = discoverConfigs(root);
      const { findings, verified, failed } = await verifyLockfile(root, servers, Number(flagString(flags, "timeout") ?? 15_000));
      const report = {
        tool: "agentguard",
        version: VERSION,
        scannedAt: new Date().toISOString(),
        root,
        servers: [],
        skillFindings: [],
        unassignedFindings: findings,
        summary: {
          totalFindings: findings.length,
          bySeverity: Object.fromEntries(SEVERITY_ORDER.map((s) => [s, findings.filter((f) => f.severity === s).length])) as Record<Severity, number>,
          worstGrade: findings.some((f) => f.severity === "critical") ? ("F" as const) : findings.length > 0 ? ("C" as const) : ("A" as const),
        },
      };
      if (flagString(flags, "format") === "json") process.stdout.write(renderJson(report));
      else process.stdout.write(renderTerminal(report));
      console.error(`Verified ${verified} server(s) against ${LOCKFILE_NAME}.`);
      for (const f of failed) console.error(`  ✗ ${f.server}: ${f.error}`);
      process.exit(exitCodeFor(report, flagString(flags, "fail-on") ?? "medium"));
      break;
    }

    case "rules": {
      for (const rule of allRules()) {
        console.log(`${rule.id}  [${rule.defaultSeverity}] ${rule.name}`);
        console.log(`        ${rule.description}`);
      }
      process.exit(0);
      break;
    }

    case "init": {
      console.log(GITHUB_ACTION);
      process.exit(0);
      break;
    }

    case "help":
    case "--help":
    case "-h": {
      process.stdout.write(HELP);
      process.exit(0);
      break;
    }

    case "--version":
    case "-v":
    case "version": {
      console.log(VERSION);
      process.exit(0);
      break;
    }

    default: {
      console.error(`Unknown command: ${command}\n`);
      process.stdout.write(HELP);
      process.exit(2);
    }
  }
}

const GITHUB_ACTION = `name: agentguard
on: [push, pull_request]
permissions:
  security-events: write
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npx agentguard scan --path . --format sarif --fail-on high > agentguard.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: agentguard.sarif
`;

main().catch((err) => {
  console.error(`agentguard: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(2);
});
