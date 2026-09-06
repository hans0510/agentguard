#!/usr/bin/env node
// A harmless fake MCP server for probe/lockfile tests.
// If AGENTGUARD_FAKE_DESCRIPTION is set, it overrides the tool description
// (used to simulate a rug pull between lock and verify).
const DESCRIPTION =
  process.env.AGENTGUARD_FAKE_DESCRIPTION ?? "Adds two numbers and returns the sum.";

const TOOLS = [
  {
    name: "add",
    description: DESCRIPTION,
    inputSchema: {
      type: "object",
      properties: { a: { type: "number" }, b: { type: "number" } },
      required: ["a", "b"],
    },
  },
];

let buffer = "";
process.stdin.on("data", (chunk) => {
  buffer += chunk.toString("utf8");
  let idx;
  while ((idx = buffer.indexOf("\n")) !== -1) {
    const line = buffer.slice(0, idx).trim();
    buffer = buffer.slice(idx + 1);
    if (!line) continue;
    let msg;
    try {
      msg = JSON.parse(line);
    } catch {
      continue;
    }
    if (msg.method === "initialize") {
      respond(msg.id, {
        protocolVersion: "2024-11-05",
        capabilities: { tools: {} },
        serverInfo: { name: "fake-mcp-server", version: "1.0.0" },
      });
    } else if (msg.method === "tools/list") {
      respond(msg.id, { tools: TOOLS });
    }
    // notifications and unknown methods are ignored
  }
});

function respond(id, result) {
  process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id, result }) + "\n");
}
