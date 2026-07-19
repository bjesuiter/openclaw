import { EventEmitter } from "node:events";
import {
  encodeGatewayTransportFrame,
  GatewayTransportFrameDecoder,
} from "@openclaw/gateway-protocol";

export const GATEWAY_IROH_ALPN = "openclaw-gateway-v1";

const ALPN_BYTES = Array.from(Buffer.from(GATEWAY_IROH_ALPN, "utf8"));
const MAX_PAYLOAD_BYTES = 25 * 1024 * 1024;
const GATEWAY_TRANSPORT_CONNECTING = 0;
const GATEWAY_TRANSPORT_OPEN = 1;
const GATEWAY_TRANSPORT_CLOSING = 2;
const GATEWAY_TRANSPORT_CLOSED = 3;

type IrohEndpointAddr = unknown;

type IrohEndpoint = {
  connect(addr: IrohEndpointAddr, alpn: number[]): Promise<IrohConnection>;
  close(): void;
};

type IrohConnection = {
  openBi(): Promise<IrohBiStream>;
  close(errorCode: bigint, reason: number[]): void;
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
      relayMode(mode: unknown): void;
      bind(): Promise<IrohEndpoint>;
    };
  };
  EndpointTicket: {
    fromString(ticket: string): { endpointAddr(): IrohEndpointAddr };
  };
  RelayMode: {
    defaultMode(): unknown;
    disabled(): unknown;
    staging(): unknown;
    customFromUrls(urls: string[]): unknown;
  };
};

export type GatewayClientIrohOptions = {
  ticket: string;
  relayMode?: "default" | "disabled" | "staging" | "custom";
  relayUrls?: string[];
};

export type GatewayClientTransportSocket = EventEmitter & {
  readyState: number;
  send(data: string): void;
  close(code?: number, reason?: string): void;
  terminate?: () => void;
};

async function loadIrohModule(): Promise<IrohModule> {
  const mod = await import("@number0/iroh");
  return (mod.default ?? mod) as IrohModule;
}

function resolveRelayMode(iroh: IrohModule, options: GatewayClientIrohOptions): unknown {
  const mode = options.relayMode ?? "default";
  if (mode === "disabled") {
    return iroh.RelayMode.disabled();
  }
  if (mode === "staging") {
    return iroh.RelayMode.staging();
  }
  if (mode === "custom") {
    return iroh.RelayMode.customFromUrls(options.relayUrls ?? []);
  }
  return iroh.RelayMode.defaultMode();
}

function toBytes(chunk: number[] | Uint8Array): Uint8Array {
  return chunk instanceof Uint8Array ? chunk : Uint8Array.from(chunk);
}

export class GatewayIrohClientTransport
  extends EventEmitter
  implements GatewayClientTransportSocket
{
  readyState = GATEWAY_TRANSPORT_CONNECTING;
  private endpoint: IrohEndpoint | null = null;
  private connection: IrohConnection | null = null;
  private stream: IrohBiStream | null = null;
  private writeChain = Promise.resolve();

  constructor(private readonly options: GatewayClientIrohOptions) {
    super();
    queueMicrotask(() => {
      void this.connect();
    });
  }

  private isClosingOrClosed(): boolean {
    return (
      this.readyState === GATEWAY_TRANSPORT_CLOSING || this.readyState === GATEWAY_TRANSPORT_CLOSED
    );
  }

  private async connect(): Promise<void> {
    try {
      const iroh = await loadIrohModule();
      if (this.isClosingOrClosed()) {
        return;
      }
      const endpointTicket = iroh.EndpointTicket.fromString(this.options.ticket);
      const builder = iroh.Endpoint.builder();
      builder.applyN0();
      builder.relayMode(resolveRelayMode(iroh, this.options));
      this.endpoint = await builder.bind();
      if (this.isClosingOrClosed()) {
        this.endpoint.close();
        return;
      }
      this.connection = await this.endpoint.connect(endpointTicket.endpointAddr(), ALPN_BYTES);
      if (this.isClosingOrClosed()) {
        this.connection.close(1000n, Array.from(Buffer.from("closed")));
        this.endpoint.close();
        return;
      }
      this.stream = await this.connection.openBi();
      if (this.isClosingOrClosed()) {
        this.connection.close(1000n, Array.from(Buffer.from("closed")));
        this.endpoint.close();
        return;
      }
      this.readyState = GATEWAY_TRANSPORT_OPEN;
      this.emit("open");
      void this.readLoop();
    } catch (error) {
      if (this.isClosingOrClosed()) {
        return;
      }
      this.emit("error", error);
      this.close(1006, "iroh connect failed");
    }
  }

  send(data: string): void {
    if (this.readyState !== GATEWAY_TRANSPORT_OPEN || !this.stream) {
      throw new Error("gateway iroh transport is not open");
    }
    let frame: unknown;
    try {
      frame = JSON.parse(data);
    } catch (error) {
      throw error instanceof Error ? error : new Error(String(error));
    }
    const encoded = encodeGatewayTransportFrame(frame);
    this.writeChain = this.writeChain
      .then(() => this.stream?.send.writeAll(Array.from(encoded)))
      .then(() => undefined);
    void this.writeChain.catch((error: unknown) => {
      this.emit("error", error);
      this.close(1011, "iroh send failed");
    });
  }

  close(code = 1000, reason = ""): void {
    if (this.readyState === GATEWAY_TRANSPORT_CLOSED) {
      return;
    }
    this.readyState = GATEWAY_TRANSPORT_CLOSING;
    const reasonBytes = Array.from(Buffer.from(reason));
    try {
      this.connection?.close(BigInt(code), reasonBytes);
    } catch {
      // Ignore close races.
    }
    try {
      this.endpoint?.close();
    } catch {
      // Ignore close races.
    }
    this.readyState = GATEWAY_TRANSPORT_CLOSED;
    this.emit("close", code, Buffer.from(reason));
  }

  terminate(): void {
    this.close(1006, "terminated");
  }

  private async readLoop(): Promise<void> {
    const decoder = new GatewayTransportFrameDecoder(MAX_PAYLOAD_BYTES);
    try {
      for (;;) {
        const chunk = await this.stream?.recv.read(MAX_PAYLOAD_BYTES);
        if (!chunk || chunk.length === 0 || this.readyState !== GATEWAY_TRANSPORT_OPEN) {
          break;
        }
        for (const frame of decoder.push(toBytes(chunk))) {
          this.emit("message", frame.text);
        }
      }
      decoder.close();
      this.close();
    } catch (error) {
      this.emit("error", error);
      this.close(1008, "invalid iroh frame");
    }
  }
}
