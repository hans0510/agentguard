import type { Artifact, Finding, Rule, ServerConfig } from "../types.js";
import { POPULAR_MCP_PACKAGES, SECRET_VALUE_PATTERNS } from "../util/patterns.js";
import { firstMatch, levenshtein, truncate } from "../util/text.js";

function asServer(artifact: Artifact): ServerConfig | null {
  return artifact.kind === "server-config" ? artifact.server : null;
}

function isLocalHost(url: string): boolean {
  try {
    const h = new URL(url).hostname;
    return h === "localhost" || h === "127.0.0.1" || h === "::1" || h === "0.0.0.0";
  } catch {
    return false;
  }
}

export const insecureTransport: Rule = {
  id: "AG-C001",
  name: "Insecure transport for remote server",
  description: "Remote MCP servers over plain HTTP expose tool traffic and credentials to interception.",
  defaultSeverity: "high",
  appliesTo: ["server-config"],
  check(artifact: Artifact): Finding[] {
    const s = asServer(artifact);
    if (!s?.url) return [];
    if (!s.url.startsWith("http://") || isLocalHost(s.url)) return [];
    return [
      {
        ruleId: "AG-C001",
        severity: "high",
        title: "Remote MCP server over plain HTTP",
        description: `"${s.name}" connects to ${s.url} without TLS. Tool calls and any credentials in headers cross the network in cleartext.`,
        location: { server: s.name, file: s.source },
        evidence: s.url,
        remediation: "Use an https:// endpoint, or a local stdio server instead.",
      },
    ];
  },
};

export const remoteWithoutAuth: Rule = {
  id: "AG-C002",
  name: "Remote server without authentication",
  description: "A remote MCP endpoint with no auth header means anyone who finds the URL can use your tools.",
  defaultSeverity: "low",
  appliesTo: ["server-config"],
  check(artifact: Artifact): Finding[] {
    const s = asServer(artifact);
    if (!s?.url || isLocalHost(s.url)) return [];
    const hasAuth =
      s.headers &&
      Object.keys(s.headers).some((k) => /^(authorization|x-api-key|api[-_]?key)$/i.test(k));
    if (hasAuth) return [];
    return [
      {
        ruleId: "AG-C002",
        severity: "low",
        title: "Remote MCP server configured without credentials",
        description: `"${s.name}" talks to ${s.url} without an Authorization or API-key header. If the endpoint is public, anyone can invoke your tools.`,
        location: { server: s.name, file: s.source },
        remediation: "Add authentication, or confirm the endpoint enforces auth some other way (mTLS, network policy).",
      },
    ];
  },
};

export const hardcodedSecretInConfig: Rule = {
  id: "AG-C003",
  name: "Hardcoded secret in MCP config",
  description: "API keys and tokens stored in plaintext config files leak via dotfile repos and backups.",
  defaultSeverity: "medium",
  appliesTo: ["server-config"],
  check(artifact: Artifact): Finding[] {
    const s = asServer(artifact);
    if (!s?.env) return [];
    const findings: Finding[] = [];
    for (const [key, value] of Object.entries(s.env)) {
      if (value.startsWith("${") || value === "") continue; // env reference, not a literal
      const m = firstMatch(value, SECRET_VALUE_PATTERNS);
      if (m) {
        findings.push({
          ruleId: "AG-C003",
          severity: "medium",
          title: `Hardcoded credential "${key}" in config`,
          description: `Server "${s.name}" stores what looks like a live credential in plaintext. Config files are routinely committed to git or synced to backups.`,
          location: { server: s.name, file: s.source },
          evidence: `${key}=${value.slice(0, 6)}…`,
          remediation: "Move the secret to an environment variable or a secret manager; rotate it if the file was ever shared.",
        });
      }
    }
    return findings;
  },
};

export const shellWrappedCommand: Rule = {
  id: "AG-C004",
  name: "Shell-wrapped or remote-script command",
  description: "Configs that run sh -c '...' or pipe curl into a shell execute arbitrary code at every client start.",
  defaultSeverity: "high",
  appliesTo: ["server-config"],
  check(artifact: Artifact): Finding[] {
    const s = asServer(artifact);
    if (!s?.command) return [];
    const joined = [s.command, ...(s.args ?? [])].join(" ");
    const findings: Finding[] = [];
    if (/\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z|fi)?sh\b/i.test(joined)) {
      findings.push({
        ruleId: "AG-C004",
        severity: "high",
        title: "Config pipes a remote script into a shell",
        description: `Server "${s.name}" downloads and executes a script on every client start. The remote side can change the payload at any time — this is a rug pull by design.`,
        location: { server: s.name, file: s.source },
        evidence: truncate(joined),
        remediation: "Install a pinned version of the server locally instead of piping curl into a shell.",
      });
    } else if (/^(?:sudo\s+)?(?:ba|z|fi)?sh$|^cmd(?:\.exe)?$|^powershell(?:\.exe)?$/i.test(s.command) &&
      (s.args ?? []).some((a) => a === "-c" || a === "-Command" || a === "/c")) {
      findings.push({
        ruleId: "AG-C004",
        severity: "medium",
        title: "Server command is a shell wrapper",
        description: `Server "${s.name}" runs an inline shell script. This hides the real command from reviewers and from tools like this one.`,
        location: { server: s.name, file: s.source },
        evidence: truncate(joined),
        remediation: "Point the config directly at the executable, or keep the script in an auditable file.",
      });
    }
    return findings;
  },
};

const PACKAGE_RUNNERS = /^(npx|uvx|pipx|bunx|pnpm dlx|yarn dlx)$/;

export const unpinnedPackage: Rule = {
  id: "AG-C005",
  name: "Unpinned server package version",
  description:
    "Running a server via npx without a version pin means today's approved code can be silently replaced " +
    "tomorrow — the rug-pull channel.",
  defaultSeverity: "medium",
  appliesTo: ["server-config"],
  check(artifact: Artifact): Finding[] {
    const s = asServer(artifact);
    if (!s?.command || !PACKAGE_RUNNERS.test(s.command)) return [];
    const args = (s.args ?? []).filter((a) => !a.startsWith("-"));
    const pkg = args[0];
    if (!pkg || pkg.includes("/") && pkg.startsWith(".")) return []; // local path, fine
    const hasPin = /@[\w.+-]*\d[\w.+-]*$/.test(pkg) && !/@(latest|next|canary)$/i.test(pkg);
    if (hasPin) return [];
    return [
      {
        ruleId: "AG-C005",
        severity: "medium",
        title: `Server "${s.name}" runs an unpinned package`,
        description: `"${pkg}" has no version pin. Every client start resolves the latest published code — a compromised or malicious release is executed immediately, with your agent's permissions.`,
        location: { server: s.name, file: s.source },
        evidence: `${s.command} ${(s.args ?? []).join(" ")}`,
        remediation: `Pin an exact version, e.g. ${pkg}@x.y.z, and review changelogs before bumping.`,
      },
    ];
  },
};

export const typosquatRisk: Rule = {
  id: "AG-C006",
  name: "Package name resembles a popular MCP server",
  description: "Names within edit distance 2 of a popular package are a classic typosquat signal.",
  defaultSeverity: "high",
  appliesTo: ["server-config"],
  check(artifact: Artifact): Finding[] {
    const s = asServer(artifact);
    if (!s?.command || !PACKAGE_RUNNERS.test(s.command)) return [];
    const pkg = (s.args ?? []).filter((a) => !a.startsWith("-"))[0]?.replace(/@[\w.+-]+$/, "");
    if (!pkg) return [];
    for (const popular of POPULAR_MCP_PACKAGES) {
      if (pkg === popular) return [];
      const d = levenshtein(pkg, popular);
      if (d > 0 && d <= 2) {
        return [
          {
            ruleId: "AG-C006",
            severity: "high",
            title: `Package "${pkg}" is ${d} edit(s) away from "${popular}"`,
            description:
              "Typosquatting is the cheapest supply-chain attack on MCP servers: publish a near-identical name, wait for a typo, inherit the agent's full permissions.",
            location: { server: s.name, file: s.source },
            evidence: pkg,
            remediation: `Verify you meant the official package ${popular}. Check the publisher, weekly downloads, and repository link.`,
          },
        ];
      }
    }
    return [];
  },
};

export const configRules: Rule[] = [
  insecureTransport,
  remoteWithoutAuth,
  hardcodedSecretInConfig,
  shellWrappedCommand,
  unpinnedPackage,
  typosquatRisk,
];
