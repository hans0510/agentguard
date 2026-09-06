/** Shared pattern sets used by multiple rules. */

/** Paths that should never appear in tool descriptions or agent instructions. */
export const SENSITIVE_PATH_PATTERNS: RegExp[] = [
  /(?:~|\/home\/[\w.-]+|\$HOME|%USERPROFILE%)?\/?\.ssh\/[\w.-]+/i,
  /\bid_(?:rsa|ed25519|dsa|ecdsa)\b/i,
  /\.aws\/(?:credentials|config)\b/i,
  /\.azure\/[\w.-]+/i,
  /\.gcloud\//i,
  /\.kube\/config\b/i,
  /\.docker\/config\.json/i,
  /\.gnupg\//i,
  /\.env(?:\.[\w.-]+)?(?:\s|$|"|'|`)/
  ,
  /\.npmrc\b/i,
  /\.pypirc\b/i,
  /\.netrc\b/i,
  /\.git-credentials\b/i,
  /keychain/i,
  /\/etc\/(?:passwd|shadow)\b/i,
  /\b(?:wallet\.dat|keystore)\b/i,
];

/** Destinations / channels associated with exfiltration. */
export const EXFIL_ENDPOINT_PATTERNS: RegExp[] = [
  /webhook\.site/i,
  /requestbin(?:\.com|net)?/i,
  /\bpipedream\.(?:com|net)/i,
  /\bngrok(?:-free)?\.(?:io|app|dev)\b/i,
  /pastebin\.com/i,
  /transfer\.sh/i,
  /0x0\.st/i,
  /discord(?:app)?\.com\/api\/webhooks/i,
  /hooks\.slack\.com/i,
  /oastify\.com/i,
  /burpcollaborator\.net/i,
  /interact\.sh/i,
];

/** Instructions to send data somewhere. */
export const EXFIL_ACTION_PATTERNS: RegExp[] = [
  /\b(?:send|post|upload|transmit|forward|exfiltrate|leak)\b[^\n.]{0,80}\bhttps?:\/\//i,
  /\b(?:encode|encrypt|obfuscate)\b[^\n.]{0,50}\b(?:base64|hex)\b[^\n.]{0,60}\b(?:send|url|parameter|param|request)\b/i,
  /!\[[^\]]*\]\(\s*https?:\/\//i, // markdown image beacon
  /<img[^>]+src\s*=\s*["']https?:\/\//i,
];

/** API-key shaped string literals (gitleaks-style basics). */
export const SECRET_VALUE_PATTERNS: RegExp[] = [
  /\bsk-[A-Za-z0-9_-]{20,}\b/, // OpenAI
  /\bghp_[A-Za-z0-9]{30,}\b/, // GitHub PAT
  /\bgithub_pat_[A-Za-z0-9_]{30,}\b/,
  /\bglpat-[A-Za-z0-9_-]{20,}\b/, // GitLab
  /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/, // Slack
  /\bAKIA[0-9A-Z]{16}\b/, // AWS access key id
  /\bAIza[0-9A-Za-z_-]{35}\b/, // Google API key
  /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/, // JWT
  /-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/,
];

/** Phrases that attempt to override, hide, or inject instructions. */
export const INSTRUCTION_OVERRIDE_PATTERNS: RegExp[] = [
  /<\s*(?:IMPORTANT|SYSTEM|INSTRUCTIONS?|RULES?|HIDDEN|OVERRIDE|ADMIN|PRIORITY)\s*>/i,
  /\bignore\s+(?:all\s+)?(?:previous|prior|earlier|above)\s+(?:instructions?|rules?|prompts?)/i,
  /\bdisregard\s+(?:all\s+)?(?:previous|prior|your)\s+(?:instructions?|rules?|guidelines)/i,
  /\bforget\s+(?:your|all)\s+(?:instructions?|rules?|guidelines)/i,
  /\bdo\s+not\s+(?:tell|inform|mention|disclose|reveal)\s+(?:the\s+)?(?:user|human|anyone)/i,
  /\bnever\s+(?:tell|inform|mention|disclose|reveal)\s+(?:the\s+)?(?:user|human|anyone)/i,
  /\bwithout\s+(?:asking|confirming|notifying)\s+(?:the\s+)?user/i,
  /\byou\s+(?:must|shall|are\s+required\s+to|are\s+instructed\s+to)\b/i,
  /\b(?:before|after|when|whenever)\s+(?:using|calling|invoking|running)\s+(?:(?:any|other|another|the|all|every)\s+){1,3}tools?\b/i,
  /\buse\s+this\s+tool\s+instead\s+of\b/i,
  /\binstead\s+of\s+(?:using|calling)\s+(?:the\s+)?[\w-]+\s+tool/i,
  /\boverride\s+(?:the\s+)?(?:default|safety|security)\b/i,
  /\bbypass\s+(?:the\s+)?(?:safety|security|confirmation|approval)/i,
  /\bdo\s+not\s+(?:ask\s+for\s+)?confirmation\b/i,
];

/** Popular MCP package names for typosquat distance checks. */
export const POPULAR_MCP_PACKAGES: string[] = [
  "@modelcontextprotocol/server-github",
  "@modelcontextprotocol/server-filesystem",
  "@modelcontextprotocol/server-slack",
  "@modelcontextprotocol/server-postgres",
  "@modelcontextprotocol/server-sqlite",
  "@modelcontextprotocol/server-puppeteer",
  "@modelcontextprotocol/server-brave-search",
  "@modelcontextprotocol/server-google-drive",
  "@modelcontextprotocol/server-memory",
  "@modelcontextprotocol/server-fetch",
  "@playwright/mcp",
  "@upstash/context7-mcp",
];
