import { spawn } from "node:child_process";
import type { ServerConfig, ToolDefinition } from "../types.js";

export interface ProbeResult {
  server: string;
  ok: boolean;
  tools: ToolDefinition[];
  serverInfo?: { name?: string; version?: string };
  error?: string;
  durationMs: number;
}

const PROTOCOL_VERSION = "2024-11-05";

interface JsonRpcMessage {
  id?: number | string;
  method?: string;
  result?: unknown;
  error?: { code: number; message: string };
  params?: unknown;
}

/** Minimal MCP stdio client: initialize → notifications/initialized → tools/list.
 *  Spawning a server executes its code — only call this for `lock`/`verify`/`--probe`,
 *  never during a default static scan. */
export function probeServer(server: ServerConfig, timeoutMs = 15_000): Promise<ProbeResult> {
  const started = Date.now();
  return new Promise((resolvePromise) => {
    if (server.transport !== "stdio" || !server.command) {
      resolvePromise({ server: server.name, ok: false, tools: [], error: "not a stdio server", durationMs: 0 });
      return;
    }

    let done = false;
    const finish = (result: Omit<ProbeResult, "server" | "durationMs">) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      try {
        child.kill("SIGTERM");
      } catch {
        // already exited
      }
      resolvePromise({ ...result, server: server.name, durationMs: Date.now() - started });
    };

    let child: ReturnType<typeof spawn>;
    try {
      child = spawn(server.command, server.args ?? [], {
        env: { ...process.env, ...(server.env ?? {}) },
        stdio: ["pipe", "pipe", "pipe"],
      });
    } catch (err) {
      resolvePromise({ server: server.name, ok: false, tools: [], error: String(err), durationMs: Date.now() - started });
      return;
    }

    const timer = setTimeout(() => finish({ ok: false, tools: [], error: `timed out after ${timeoutMs}ms` }), timeoutMs);

    let buffer = "";
    let nextId = 1;
    let serverInfo: ProbeResult["serverInfo"];
    const tools: ToolDefinition[] = [];
    let phase: "init" | "tools" = "init";

    const send = (msg: JsonRpcMessage) => {
      try {
        child.stdin!.write(JSON.stringify(msg) + "\n");
      } catch {
        // stdin closed
      }
    };

    child.on("error", (err) => finish({ ok: false, tools: [], error: `spawn failed: ${err.message}` }));
    child.on("exit", (code) => {
      if (!done) finish({ ok: false, tools: [], error: `exited with code ${code} before responding` });
    });
    child.stderr!.resume(); // drain; server logs are not protocol data

    child.stdout!.on("data", (chunk: Buffer) => {
      buffer += chunk.toString("utf8");
      let newline: number;
      while ((newline = buffer.indexOf("\n")) !== -1) {
        const line = buffer.slice(0, newline).trim();
        buffer = buffer.slice(newline + 1);
        if (line === "") continue;
        let msg: JsonRpcMessage;
        try {
          msg = JSON.parse(line) as JsonRpcMessage;
        } catch {
          continue; // not JSON — some servers print logs to stdout
        }
        if (msg.id === undefined || msg.error) continue;

        if (phase === "init") {
          const result = msg.result as { serverInfo?: { name?: string; version?: string } } | undefined;
          serverInfo = result?.serverInfo;
          send({ method: "notifications/initialized", params: {} });
          phase = "tools";
          send({ id: nextId++, method: "tools/list", params: {} });
        } else if (phase === "tools") {
          const result = msg.result as { tools?: ToolDefinition[] } | undefined;
          if (Array.isArray(result?.tools)) {
            tools.push(...result.tools);
            finish({ ok: true, tools, serverInfo });
          }
        }
      }
    });

    send({
      id: nextId++,
      method: "initialize",
      params: {
        protocolVersion: PROTOCOL_VERSION,
        capabilities: {},
        clientInfo: { name: "agentguard", version: "0.1.0" },
      },
    });
  });
}

export async function probeAll(
  servers: ServerConfig[],
  timeoutMs: number,
  concurrency = 3,
): Promise<ProbeResult[]> {
  const results: ProbeResult[] = [];
  const queue = [...servers];
  const workers = Array.from({ length: Math.min(concurrency, queue.length) }, async () => {
    while (queue.length > 0) {
      const server = queue.shift()!;
      results.push(await probeServer(server, timeoutMs));
    }
  });
  await Promise.all(workers);
  return results;
}
