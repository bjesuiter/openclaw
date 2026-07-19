// Native Iroh/QUIC gateway transport runtime.
import { randomUUID } from "node:crypto";
import { EventEmitter } from "node:events";
import type { IncomingMessage } from "node:http";
import {
  encodeGatewayTransportFrame,
  GatewayTransportFrameDecoder,
  GatewayTransportFrameError,
} from "../../packages/gateway-protocol/src/transport-frame.js";
import type { GatewayIrohConfig } from "../config/types.gateway.js";
import { upsertPresence } from "../infra/system-presence.js";
import { logRejectedLargePayload } from "../logging/diagnostic-payload.js";
import type { createSubsystemLogger } from "../logging/subsystem.js";
import { removeRemoteNodeInfo } from "../skills/runtime/remote.js";
import type { AuthRateLimiter } from "./auth-rate-limit.js";
import type { ResolvedGatewayAuth } from "./auth.js";
import { resolvePreauthHandshakeTimeoutMs } from "./handshake-timeouts.js";
import { setGatewayIrohDiscoverySnapshot } from "./iroh-discovery.js";
import { loadOrCreateGatewayIrohSecretKey } from "./iroh-key.js";
import type { GatewayMethodRegistry } from "./methods/registry.js";
import type { NodeReapprovalCoordinator } from "./node-reapproval-coordinator.js";
import type { PluginNodeCapabilitySurface } from "./plugin-node-capability.js";
import {
  MAX_BUFFERED_BYTES,
  MAX_PAYLOAD_BYTES,
  MAX_PREAUTH_PAYLOAD_BYTES,
} from "./server-constants.js";
import { clearNodeWakeState } from "./server-methods/nodes-wake-state.js";
import type { GatewayRequestContext, GatewayRequestHandlers } from "./server-methods/types.js";
import { formatError } from "./server-utils.js";
import { getHealthVersion, incrementPresenceVersion } from "./server/health-state.js";
import type { PreauthConnectionBudget } from "./server/preauth-connection-budget.js";
import { broadcastPresenceSnapshot } from "./server/presence-events.js";
import type {
  GatewayWsMessageHandlerParams,
  WsOriginCheckMetrics,
} from "./server/ws-connection/message-handler.js";
import type { GatewayWsClient, WsHandshakePhase } from "./server/ws-types.js";
import { logWs } from "./ws-log.js";

export const GATEWAY_IROH_ALPN = "openclaw-gateway-v1";

const ALPN_BYTES = Array.from(Buffer.from(GATEWAY_IROH_ALPN, "utf8"));
const IROH_PREAUTH_BUDGET_KEY = "__openclaw_iroh_preauth__";
type SubsystemLogger = ReturnType<typeof createSubsystemLogger>;

type IrohEndpointAddr = {
  id(): { toString(): string };
};

type IrohEndpoint = {
  id(): { toString(): string };
  addr(): IrohEndpointAddr;
  acceptNext(): Promise<IrohIncoming>;
  close(): void;
};

type IrohIncoming = {
  accept(): Promise<{ connect(): Promise<IrohConnection> }>;
};

type IrohConnection = {
  acceptBi(): Promise<IrohBiStream>;
  close(errorCode: bigint, reason: number[]): void;
  remoteId(): { toString(): string };
};

type IrohBiStream = {
  recv: {
    read(sizeLimit: number): Promise<number[] | Uint8Array | null | undefined>;
  };
  send: {
    writeAll(bytes: number[]): Promise<void>;
    finish(): Promise<void>;
  };
};

type IrohModule = {
  Endpoint: {
    builder(): {
      applyN0(): void;
      alpns(alpns: number[][]): void;
      secretKey(bytes: number[]): void;
      relayMode(mode: unknown): void;
      bind(): Promise<IrohEndpoint>;
    };
  };
  EndpointTicket: {
    fromAddr(addr: IrohEndpointAddr): { toString(): string };
  };
  RelayMode: {
    defaultMode(): unknown;
    disabled(): unknown;
    staging(): unknown;
    customFromUrls(urls: string[]): unknown;
  };
  SecretKey: {
    generate(): { toBytes(): number[] };
  };
};

type GatewayIrohSocketLike = EventEmitter & {
  bufferedAmount: number;
  readyState: number;
  send(data: string, cb?: (err?: Error) => void): void;
  close(code?: number, reason?: string): void;
  ping(): void;
};

type GatewayIrohRuntimeParams = {
  config: GatewayIrohConfig | undefined;
  clients: Set<GatewayWsClient>;
  preauthConnectionBudget: PreauthConnectionBudget;
  resolvedAuth: ResolvedGatewayAuth;
  getResolvedAuth: () => ResolvedGatewayAuth;
  getRequiredSharedGatewaySessionGeneration?: () => string | undefined;
  rateLimiter?: AuthRateLimiter;
  browserRateLimiter?: AuthRateLimiter;
  nodeReapprovalCoordinator?: NodeReapprovalCoordinator;
  preauthHandshakeTimeoutMs?: number;
  isStartupPending?: () => boolean;
  gatewayMethods: string[];
  events: string[];
  logGateway: SubsystemLogger;
  logHealth: SubsystemLogger;
  logWsControl: SubsystemLogger;
  extraHandlers: GatewayRequestHandlers;
  getMethodRegistry?: () => GatewayMethodRegistry;
  broadcast: (
    event: string,
    payload: unknown,
    opts?: {
      dropIfSlow?: boolean;
      stateVersion?: { presence?: number; health?: number };
    },
  ) => void;
  context: GatewayRequestContext;
  pluginNodeCapabilities?: PluginNodeCapabilitySurface[];
};

export type GatewayIrohRuntimeHandle = {
  endpointId: string;
  ticket: string;
  stop: () => Promise<void>;
};

class GatewayIrohSocketAdapter extends EventEmitter implements GatewayIrohSocketLike {
  bufferedAmount = 0;
  readyState = 1;
  private closed = false;

  constructor(
    private readonly writeFrame: (frame: unknown) => Promise<void>,
    private readonly closeStream: (code?: number, reason?: string) => void,
  ) {
    super();
  }

  send(data: string, cb?: (err?: Error) => void): void {
    let parsed: unknown;
    try {
      parsed = JSON.parse(data);
    } catch (error) {
      cb?.(error instanceof Error ? error : new Error(String(error)));
      return;
    }
    this.writeFrame(parsed).then(
      () => cb?.(),
      (error: unknown) => cb?.(error instanceof Error ? error : new Error(String(error))),
    );
  }

  close(code?: number, reason?: string): void {
    if (this.closed) {
      return;
    }
    this.closed = true;
    this.readyState = 3;
    this.closeStream(code, reason);
    this.emit("close", code ?? 1000, Buffer.from(reason ?? ""));
  }

  ping(): void {
    // Iroh/QUIC owns transport liveness; application tick events stay unchanged.
  }
}

function resolveRelayMode(iroh: IrohModule, config: GatewayIrohConfig | undefined): unknown {
  const mode = config?.relayMode ?? "default";
  if (mode === "disabled") {
    return iroh.RelayMode.disabled();
  }
  if (mode === "staging") {
    return iroh.RelayMode.staging();
  }
  if (mode === "custom") {
    return iroh.RelayMode.customFromUrls(config?.relayUrls ?? []);
  }
  return iroh.RelayMode.defaultMode();
}

async function loadIrohModule(): Promise<IrohModule> {
  const mod = await import("@number0/iroh");
  return (mod.default ?? mod) as IrohModule;
}

function buildIrohIncomingRequest(remoteId: string): IncomingMessage {
  return {
    headers: {},
    socket: {
      remoteAddress: `iroh:${remoteId}`,
    },
  } as IncomingMessage;
}

function toBytes(chunk: number[] | Uint8Array): Uint8Array {
  return chunk instanceof Uint8Array ? chunk : Uint8Array.from(chunk);
}

async function closeSendStream(send: IrohBiStream["send"]): Promise<void> {
  try {
    await send.finish();
  } catch {
    // The peer may already have closed; connection close below owns teardown.
  }
}

async function attachAcceptedIrohConnection(params: {
  connection: IrohConnection;
  stream: IrohBiStream;
  runtime: GatewayIrohRuntimeParams;
  originCheckMetrics: WsOriginCheckMetrics;
}): Promise<void> {
  const { connection, stream, runtime } = params;
  const remoteId = connection.remoteId().toString();
  if (runtime.getResolvedAuth().mode === "none") {
    connection.close(1008n, Array.from(Buffer.from("gateway auth required")));
    return;
  }
  const preauthBudgetKey = IROH_PREAUTH_BUDGET_KEY;
  if (!runtime.preauthConnectionBudget.acquire(preauthBudgetKey)) {
    connection.close(1008n, Array.from(Buffer.from("preauth connection limit")));
    return;
  }

  let client: GatewayWsClient | null = null;
  let closed = false;
  let sendChain = Promise.resolve();
  let pendingSendBytes = 0;
  const openedAt = Date.now();
  const connId = randomUUID();
  const endpoint = `iroh:${remoteId}`;
  let handshakeState: "pending" | "connected" | "failed" = "pending";
  let lastHandshakePhase: WsHandshakePhase = "tcp_accepted";
  let closeCause: string | undefined;
  let closeMeta: Record<string, unknown> = {};
  let lastFrameType: string | undefined;
  let lastFrameMethod: string | undefined;
  let lastFrameId: string | undefined;
  let holdsPreauthBudget = true;

  const advanceHandshakePhase = (next: WsHandshakePhase) => {
    const phases = [
      "tcp_accepted",
      "ws_upgrade_started",
      "auth_credentials_received",
      "auth_validated",
      "session_attached",
      "hello_payload_prepared",
      "ready",
    ] as const;
    if (phases.indexOf(next) > phases.indexOf(lastHandshakePhase)) {
      lastHandshakePhase = next;
    }
  };
  const setCloseCause = (cause: string, meta?: Record<string, unknown>) => {
    if (!closeCause) {
      closeCause = cause;
    }
    if (meta && Object.keys(meta).length > 0) {
      closeMeta = { ...closeMeta, ...meta };
    }
  };
  const releasePreauthBudget = () => {
    if (!holdsPreauthBudget) {
      return;
    }
    holdsPreauthBudget = false;
    runtime.preauthConnectionBudget.release(preauthBudgetKey);
  };
  const setLastFrameMeta = (meta: { type?: string; method?: string; id?: string }) => {
    if (meta.type || meta.method || meta.id) {
      lastFrameType = meta.type ?? lastFrameType;
      lastFrameMethod = meta.method ?? lastFrameMethod;
      lastFrameId = meta.id ?? lastFrameId;
    }
  };

  const close = (code = 1000, reason?: string) => {
    if (closed) {
      return;
    }
    closed = true;
    clearTimeout(handshakeTimer);
    releasePreauthBudget();
    if (client) {
      runtime.clients.delete(client);
    }
    const context = runtime.context;
    context.unsubscribeAllSessionEvents(connId);
    context.terminalSessions?.handleDisconnect(connId);
    let currentDisconnectedNodeId: string | null = null;
    if (client?.connect?.role === "node") {
      currentDisconnectedNodeId = context.nodeRegistry.unregister(connId);
    }
    if (
      client?.presenceKey &&
      (client.connect.role !== "node" || currentDisconnectedNodeId !== null)
    ) {
      upsertPresence(client.presenceKey, { reason: "disconnect" });
      broadcastPresenceSnapshot({
        broadcast: runtime.broadcast,
        incrementPresenceVersion,
        getHealthVersion,
      });
    }
    if (currentDisconnectedNodeId) {
      removeRemoteNodeInfo(currentDisconnectedNodeId);
      context.nodeUnsubscribeAll(currentDisconnectedNodeId);
      clearNodeWakeState(currentDisconnectedNodeId);
    }
    void closeSendStream(stream.send);
    try {
      connection.close(BigInt(code), Array.from(Buffer.from(reason ?? "")));
    } catch {
      // Ignore close races with peer shutdown.
    }
    logWs("out", "close", {
      connId,
      code,
      reason,
      durationMs: Date.now() - openedAt,
      cause: closeCause,
      handshake: handshakeState,
      ...(lastHandshakePhase !== "ready" ? { phase: lastHandshakePhase } : {}),
      lastFrameType,
      lastFrameMethod,
      lastFrameId,
      endpoint,
      ...closeMeta,
    });
  };

  const handshakeTimeoutMs = resolvePreauthHandshakeTimeoutMs({
    configuredTimeoutMs: runtime.preauthHandshakeTimeoutMs,
  });
  const handshakeTimer = setTimeout(() => {
    if (!client) {
      handshakeState = "failed";
      setCloseCause("handshake-timeout", {
        handshakeMs: Date.now() - openedAt,
        endpoint,
        phase: lastHandshakePhase,
      });
      runtime.logWsControl.warn(
        `iroh handshake timeout conn=${connId} peer=${remoteId} phase=${lastHandshakePhase}`,
      );
      close();
    }
  }, handshakeTimeoutMs);

  const writeFrame = async (frame: unknown) => {
    if (closed) {
      return;
    }
    const encoded = encodeGatewayTransportFrame(frame);
    pendingSendBytes += encoded.byteLength;
    socket.bufferedAmount = pendingSendBytes;
    if (pendingSendBytes > MAX_BUFFERED_BYTES) {
      logRejectedLargePayload({
        surface: "gateway.iroh.outbound_buffer",
        bytes: pendingSendBytes,
        limitBytes: MAX_BUFFERED_BYTES,
        reason: "iroh_send_buffer_close",
      });
      setCloseCause("outbound-buffer-exceeded", {
        bytes: pendingSendBytes,
        limitBytes: MAX_BUFFERED_BYTES,
      });
      close(1008, "slow consumer");
      return;
    }
    sendChain = sendChain
      .then(() => stream.send.writeAll(Array.from(encoded)))
      .catch((error: unknown) => {
        setCloseCause("send-failed", { error: formatError(error) });
        close(1011, "iroh send failed");
      })
      .finally(() => {
        pendingSendBytes -= encoded.byteLength;
        socket.bufferedAmount = Math.max(0, pendingSendBytes);
      });
    await sendChain;
  };

  const socket = new GatewayIrohSocketAdapter(writeFrame, close);
  const connectNonce = randomUUID();
  await writeFrame({
    type: "event",
    event: "connect.challenge",
    payload: { nonce: connectNonce, ts: Date.now() },
  });
  advanceHandshakePhase("ws_upgrade_started");
  logWs("in", "open", { connId, endpoint });

  const { attachGatewayWsMessageHandler } =
    await import("./server/ws-connection/message-handler.js");
  attachGatewayWsMessageHandler({
    socket: socket as unknown as GatewayWsClient["socket"],
    upgradeReq: buildIrohIncomingRequest(remoteId),
    connId,
    endpoint,
    connectNonce,
    getResolvedAuth: runtime.getResolvedAuth,
    getRequiredSharedGatewaySessionGeneration: runtime.getRequiredSharedGatewaySessionGeneration,
    rateLimiter: runtime.rateLimiter,
    browserRateLimiter: runtime.browserRateLimiter,
    nodeReapprovalCoordinator: runtime.nodeReapprovalCoordinator,
    isStartupPending: runtime.isStartupPending,
    gatewayMethods: runtime.gatewayMethods,
    events: runtime.events,
    extraHandlers: runtime.extraHandlers,
    getMethodRegistry: runtime.getMethodRegistry,
    buildRequestContext: () => runtime.context,
    refreshHealthSnapshot: runtime.context.refreshHealthSnapshot,
    send: (frame) => {
      void writeFrame(frame);
    },
    close,
    isClosed: () => closed,
    clearHandshakeTimer: () => clearTimeout(handshakeTimer),
    getClient: () => client,
    setClient: (next) => {
      if (closed) {
        return false;
      }
      releasePreauthBudget();
      client = next;
      runtime.clients.add(next);
      return true;
    },
    setHandshakeState: (next) => {
      handshakeState = next;
    },
    advanceHandshakePhase,
    setCloseCause,
    setLastFrameMeta,
    originCheckMetrics: params.originCheckMetrics,
    logGateway: runtime.logGateway,
    logHealth: runtime.logHealth,
    logWsControl: runtime.logWsControl,
    pluginNodeCapabilities: runtime.pluginNodeCapabilities,
  } satisfies GatewayWsMessageHandlerParams);

  const decoder = new GatewayTransportFrameDecoder(MAX_PREAUTH_PAYLOAD_BYTES);
  try {
    for (;;) {
      const chunk = await stream.recv.read(client ? MAX_PAYLOAD_BYTES : MAX_PREAUTH_PAYLOAD_BYTES);
      if (!chunk || chunk.length === 0 || closed) {
        break;
      }
      decoder.setMaxFrameBytes(client ? MAX_PAYLOAD_BYTES : MAX_PREAUTH_PAYLOAD_BYTES);
      for (const frame of decoder.push(toBytes(chunk))) {
        socket.emit("message", frame.text);
      }
    }
    decoder.close();
  } catch (error) {
    const code =
      error instanceof GatewayTransportFrameError && error.code === "frame_oversized" ? 1009 : 1008;
    setCloseCause("iroh-frame-error", { error: formatError(error) });
    close(code, "invalid iroh frame");
    return;
  }
  close();
}

export async function startGatewayIrohRuntime(
  params: GatewayIrohRuntimeParams,
): Promise<GatewayIrohRuntimeHandle | null> {
  if (params.config?.enabled !== true) {
    setGatewayIrohDiscoverySnapshot(null);
    return null;
  }
  if (params.resolvedAuth.mode === "none" || params.getResolvedAuth().mode === "none") {
    throw new Error("gateway.iroh.enabled requires gateway auth; auth.mode=none is not allowed");
  }

  const iroh = await loadIrohModule();
  const key = await loadOrCreateGatewayIrohSecretKey({
    path: params.config.secretKeyPath,
    generateSecretKeyBytes: () => Uint8Array.from(iroh.SecretKey.generate().toBytes()),
  });
  const builder = iroh.Endpoint.builder();
  builder.applyN0();
  builder.alpns([ALPN_BYTES]);
  builder.secretKey(Array.from(key.bytes));
  builder.relayMode(resolveRelayMode(iroh, params.config));
  const endpoint = await builder.bind();
  const endpointId = endpoint.id().toString();
  const ticket = iroh.EndpointTicket.fromAddr(endpoint.addr()).toString();
  const relayMode = params.config.relayMode ?? "default";
  setGatewayIrohDiscoverySnapshot({
    enabled: true,
    alpn: GATEWAY_IROH_ALPN,
    endpointId,
    ticket,
    relayMode,
    ...(relayMode === "custom" && params.config.relayUrls
      ? { relayUrls: params.config.relayUrls }
      : {}),
  });
  params.logGateway.info(`gateway iroh transport enabled endpoint=${endpointId}`);

  let stopped = false;
  const originCheckMetrics: WsOriginCheckMetrics = { hostHeaderFallbackAccepted: 0 };
  const acceptLoop = (async () => {
    for (;;) {
      if (stopped) {
        break;
      }
      try {
        const incoming = await endpoint.acceptNext();
        const accepting = await incoming.accept();
        const connection = await accepting.connect();
        void connection
          .acceptBi()
          .then((stream) =>
            attachAcceptedIrohConnection({
              connection,
              stream,
              runtime: params,
              originCheckMetrics,
            }),
          )
          .catch((error: unknown) => {
            params.logWsControl.warn(`failed to accept iroh stream: ${formatError(error)}`);
            try {
              connection.close(1011n, Array.from(Buffer.from("stream unavailable")));
            } catch {
              // Ignore close races.
            }
          });
      } catch (error) {
        if (!stopped) {
          params.logWsControl.warn(`iroh accept loop failed: ${formatError(error)}`);
        }
      }
    }
  })();

  return {
    endpointId,
    ticket,
    stop: async () => {
      stopped = true;
      setGatewayIrohDiscoverySnapshot(null);
      endpoint.close();
      await acceptLoop.catch(() => undefined);
    },
  };
}
