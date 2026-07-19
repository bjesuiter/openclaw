import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { GatewayTransportFrameDecoder } from "../../packages/gateway-protocol/src/transport-frame.js";
import type { ResolvedGatewayAuth } from "./auth.js";
import { getGatewayIrohDiscoverySnapshot } from "./iroh-discovery.js";
import { startGatewayIrohRuntime } from "./iroh-runtime.js";
import { MAX_PAYLOAD_BYTES, MAX_PREAUTH_PAYLOAD_BYTES } from "./server-constants.js";
import {
  createGatewayWsTestLogger,
  createGatewayWsTestRequestContext,
  createResolvedGatewayTokenAuth,
} from "./server/ws-connection.test-helpers.js";

const mocks = vi.hoisted(() => ({
  attachGatewayWsMessageHandler: vi.fn(),
  endpoint: null as MockEndpoint | null,
}));

vi.mock("./server/ws-connection/message-handler.js", () => ({
  attachGatewayWsMessageHandler: mocks.attachGatewayWsMessageHandler,
}));

class MockEndpoint {
  readonly idValue = "endpoint-1";
  closed = false;
  private pendingAccept: {
    resolve: (incoming: unknown) => void;
    reject: (error: Error) => void;
  } | null = null;

  id() {
    return { toString: () => this.idValue };
  }

  addr() {
    return { id: () => ({ toString: () => this.idValue }) };
  }

  acceptNext(): Promise<unknown> {
    return new Promise((resolve, reject) => {
      this.pendingAccept = { resolve, reject };
    });
  }

  accept(connection: MockConnection, stream: MockBiStream): void {
    this.pendingAccept?.resolve({
      accept: async () => ({
        connect: async () => connection,
      }),
    });
    connection.stream = stream;
    this.pendingAccept = null;
  }

  close(): void {
    this.closed = true;
    this.pendingAccept?.reject(new Error("endpoint closed"));
    this.pendingAccept = null;
  }
}

class MockConnection {
  stream: MockBiStream | null = null;
  close = vi.fn();

  remoteId() {
    return { toString: () => "remote-1" };
  }

  async acceptBi(): Promise<MockBiStream> {
    if (!this.stream) {
      throw new Error("missing stream");
    }
    return this.stream;
  }
}

function oversizedFrameHeader(size: number): Uint8Array {
  const header = new Uint8Array(4);
  new DataView(header.buffer, header.byteOffset, header.byteLength).setUint32(0, size, false);
  return header;
}

class MockBiStream {
  readonly sent: number[][] = [];
  private pendingRead: ((chunk: Uint8Array | null) => void) | null = null;

  recv = {
    read: vi.fn(
      async () =>
        await new Promise<Uint8Array | null>((resolve) => {
          this.pendingRead = resolve;
        }),
    ),
  };

  send = {
    writeAll: vi.fn(async (bytes: number[]) => {
      this.sent.push(bytes);
    }),
    finish: vi.fn(async () => {}),
  };

  push(chunk: Uint8Array | null): void {
    this.pendingRead?.(chunk);
    this.pendingRead = null;
  }
}

vi.mock(
  "@number0/iroh",
  () => ({
    default: {
      Endpoint: {
        builder: () => ({
          applyN0: vi.fn(),
          alpns: vi.fn(),
          secretKey: vi.fn(),
          relayMode: vi.fn(),
          bind: vi.fn(async () => {
            mocks.endpoint = new MockEndpoint();
            return mocks.endpoint;
          }),
        }),
      },
      EndpointTicket: {
        fromAddr: () => ({ toString: () => "iroh-ticket" }),
      },
      RelayMode: {
        defaultMode: () => "default",
        disabled: () => "disabled",
        staging: () => "staging",
        customFromUrls: (urls: string[]) => ({ custom: urls }),
      },
      SecretKey: {
        generate: () => ({ toBytes: () => Array.from(new Uint8Array(32).fill(4)) }),
      },
    },
  }),
  { virtual: true },
);

function createRuntimeParams(auth: ResolvedGatewayAuth = createResolvedGatewayTokenAuth("token")) {
  return {
    config: { enabled: true, relayMode: "disabled" as const },
    clients: new Set(),
    preauthConnectionBudget: { acquire: vi.fn(() => true), release: vi.fn() },
    resolvedAuth: auth,
    getResolvedAuth: () => auth,
    preauthHandshakeTimeoutMs: 60_000,
    gatewayMethods: ["ping"],
    events: ["tick"],
    logGateway: createGatewayWsTestLogger() as never,
    logHealth: createGatewayWsTestLogger() as never,
    logWsControl: createGatewayWsTestLogger() as never,
    extraHandlers: {},
    broadcast: vi.fn(),
    context: {
      ...createGatewayWsTestRequestContext(),
      refreshHealthSnapshot: vi.fn(async () => ({}) as never),
    } as never,
  };
}

describe("Iroh gateway runtime", () => {
  beforeEach(() => {
    mocks.attachGatewayWsMessageHandler.mockReset();
    mocks.endpoint = null;
  });

  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("refuses to start when Iroh is enabled with auth mode none", async () => {
    await expect(
      startGatewayIrohRuntime(
        createRuntimeParams({ mode: "none", allowTailscale: false } satisfies ResolvedGatewayAuth),
      ),
    ).rejects.toThrow("gateway.iroh.enabled requires gateway auth");
  });

  it("publishes discovery metadata and attaches accepted streams to the gateway handler", async () => {
    const runtimeParams = createRuntimeParams();
    const handle = await startGatewayIrohRuntime(runtimeParams);
    expect(handle?.endpointId).toBe("endpoint-1");
    expect(handle?.ticket).toBe("iroh-ticket");
    expect(getGatewayIrohDiscoverySnapshot()).toEqual({
      enabled: true,
      alpn: "openclaw-gateway-v1",
      endpointId: "endpoint-1",
      ticket: "iroh-ticket",
      relayMode: "disabled",
    });

    const connection = new MockConnection();
    const stream = new MockBiStream();
    mocks.endpoint?.accept(connection, stream);
    await vi.waitFor(() => expect(mocks.attachGatewayWsMessageHandler).toHaveBeenCalledTimes(1));

    const decoder = new GatewayTransportFrameDecoder(MAX_PAYLOAD_BYTES);
    expect(decoder.push(Uint8Array.from(stream.sent[0] ?? [])).map((frame) => frame.value)).toEqual(
      [
        {
          type: "event",
          event: "connect.challenge",
          payload: expect.objectContaining({ nonce: expect.any(String), ts: expect.any(Number) }),
        },
      ],
    );
    const handlerParams = mocks.attachGatewayWsMessageHandler.mock.calls[0]?.[0] as {
      endpoint?: string;
      send: (frame: unknown) => void;
    };
    expect(handlerParams.endpoint).toBe("iroh:remote-1");

    handlerParams.send({ type: "res", id: "r1", ok: true });
    await vi.waitFor(() => expect(stream.sent.length).toBe(2));
    expect(decoder.push(Uint8Array.from(stream.sent[1] ?? [])).map((frame) => frame.value)).toEqual(
      [{ type: "res", id: "r1", ok: true }],
    );
    expect(runtimeParams.preauthConnectionBudget.acquire).toHaveBeenCalledWith(
      "__openclaw_iroh_preauth__",
    );

    await handle?.stop();
    expect(getGatewayIrohDiscoverySnapshot()).toBeNull();
  });

  it("rejects preauth Iroh frames above the handshake payload limit before buffering body", async () => {
    const handle = await startGatewayIrohRuntime(createRuntimeParams());
    const connection = new MockConnection();
    const stream = new MockBiStream();
    mocks.endpoint?.accept(connection, stream);
    await vi.waitFor(() => expect(mocks.attachGatewayWsMessageHandler).toHaveBeenCalledTimes(1));

    stream.push(oversizedFrameHeader(MAX_PREAUTH_PAYLOAD_BYTES + 1));

    await vi.waitFor(() => expect(connection.close).toHaveBeenCalled());
    expect(connection.close).toHaveBeenCalledWith(
      1009n,
      Array.from(Buffer.from("invalid iroh frame")),
    );
    await handle?.stop();
  });
});
