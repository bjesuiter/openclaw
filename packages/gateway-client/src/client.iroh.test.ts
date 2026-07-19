import { EventEmitter } from "node:events";
import { beforeEach, describe, expect, it, vi } from "vitest";

const transports = vi.hoisted(() => [] as FakeIrohTransport[]);

class FakeIrohTransport extends EventEmitter {
  readyState = 0;
  sent: string[] = [];
  closed: { code?: number; reason?: string } | null = null;

  constructor(readonly options: unknown) {
    super();
    transports.push(this);
  }

  open(): void {
    this.readyState = 1;
    this.emit("open");
  }

  send(data: string): void {
    this.sent.push(data);
  }

  close(code?: number, reason?: string): void {
    if (this.readyState === 3) {
      return;
    }
    this.readyState = 3;
    this.closed = { code, reason };
    this.emit("close", code ?? 1000, Buffer.from(reason ?? ""));
  }

  terminate(): void {
    this.close(1006, "terminated");
  }
}

vi.mock("./iroh-transport.js", () => ({
  GatewayIrohClientTransport: FakeIrohTransport,
}));

const { GatewayClient } = await import("./client.js");

function frameAt(index: number): { id: string; method: string; params?: unknown } {
  return JSON.parse(transports[0]?.sent[index] ?? "{}");
}

describe("GatewayClient Iroh transport", () => {
  beforeEach(() => {
    transports.length = 0;
  });

  it("uses Iroh for the existing auth handshake and RPC dispatch", async () => {
    let helloOkResolve!: () => void;
    const helloOk = new Promise<void>((resolve) => {
      helloOkResolve = resolve;
    });
    const client = new GatewayClient({
      url: "ws://public.example.test:18789",
      iroh: { ticket: "iroh-ticket" },
      token: "token-123",
      requestTimeoutMs: 1000,
      onHelloOk: () => helloOkResolve(),
    });

    client.start();
    expect(transports).toHaveLength(1);
    transports[0]?.open();
    transports[0]?.emit(
      "message",
      JSON.stringify({
        type: "event",
        event: "connect.challenge",
        payload: { nonce: "nonce-1", ts: Date.now() },
      }),
    );

    const connectFrame = frameAt(0);
    expect(connectFrame).toMatchObject({
      type: "req",
      method: "connect",
      params: {
        auth: { token: "token-123" },
      },
    });
    transports[0]?.emit(
      "message",
      JSON.stringify({
        type: "res",
        id: connectFrame.id,
        ok: true,
        payload: {
          type: "hello-ok",
          protocol: 4,
          server: { version: "test", connId: "conn-1" },
          methods: ["ping"],
          events: [],
          capabilities: [],
          snapshot: {
            channels: [],
            tasks: [],
            agents: [],
            sessions: [],
            presence: [],
            nodes: [],
          },
          auth: { scopes: [] },
          policy: { tickIntervalMs: 30_000 },
        },
      }),
    );
    await helloOk;

    const pending = client.request("ping", { n: 1 });
    const rpcFrame = frameAt(1);
    expect(rpcFrame).toMatchObject({
      type: "req",
      method: "ping",
      params: { n: 1 },
    });
    transports[0]?.emit(
      "message",
      JSON.stringify({ type: "res", id: rpcFrame.id, ok: true, payload: { pong: true } }),
    );

    await expect(pending).resolves.toEqual({ pong: true });
    await client.stopAndWait();
    expect(transports[0]?.readyState).toBe(3);
  });
});
