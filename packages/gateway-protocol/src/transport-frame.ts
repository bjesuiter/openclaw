const HEADER_BYTES = 4;

export type GatewayTransportFrameErrorCode =
  | "frame_oversized"
  | "frame_malformed"
  | "frame_truncated";

export class GatewayTransportFrameError extends Error {
  constructor(
    readonly code: GatewayTransportFrameErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "GatewayTransportFrameError";
  }
}

export type GatewayTransportDecodedFrame = {
  text: string;
  value: unknown;
};

function assertMaxFrameBytes(maxFrameBytes: number): void {
  if (!Number.isInteger(maxFrameBytes) || maxFrameBytes <= 0 || maxFrameBytes > 0xffffffff) {
    throw new RangeError("maxFrameBytes must be an integer between 1 and 4294967295");
  }
}

function concatBytes(left: Uint8Array, right: Uint8Array): Uint8Array {
  if (left.byteLength === 0) {
    return right;
  }
  if (right.byteLength === 0) {
    return left;
  }
  const joined = new Uint8Array(left.byteLength + right.byteLength);
  joined.set(left, 0);
  joined.set(right, left.byteLength);
  return joined;
}

export function encodeGatewayTransportFrame(frame: unknown): Uint8Array {
  const payload = Buffer.from(JSON.stringify(frame), "utf8");
  const out = new Uint8Array(HEADER_BYTES + payload.byteLength);
  const view = new DataView(out.buffer, out.byteOffset, out.byteLength);
  view.setUint32(0, payload.byteLength, false);
  out.set(payload, HEADER_BYTES);
  return out;
}

export class GatewayTransportFrameDecoder {
  private buffer = new Uint8Array();
  private maxFrameBytes: number;

  constructor(maxFrameBytes: number) {
    assertMaxFrameBytes(maxFrameBytes);
    this.maxFrameBytes = maxFrameBytes;
  }

  setMaxFrameBytes(maxFrameBytes: number): void {
    assertMaxFrameBytes(maxFrameBytes);
    this.maxFrameBytes = maxFrameBytes;
  }

  push(chunk: Uint8Array): GatewayTransportDecodedFrame[] {
    this.buffer = concatBytes(this.buffer, chunk);
    const frames: GatewayTransportDecodedFrame[] = [];
    let offset = 0;

    for (;;) {
      if (this.buffer.byteLength - offset < HEADER_BYTES) {
        break;
      }

      const view = new DataView(this.buffer.buffer, this.buffer.byteOffset + offset, HEADER_BYTES);
      const payloadBytes = view.getUint32(0, false);
      if (payloadBytes > this.maxFrameBytes) {
        throw new GatewayTransportFrameError(
          "frame_oversized",
          `gateway transport frame exceeds ${this.maxFrameBytes} bytes`,
        );
      }

      const frameEnd = offset + HEADER_BYTES + payloadBytes;
      if (this.buffer.byteLength < frameEnd) {
        break;
      }

      const text = Buffer.from(this.buffer.subarray(offset + HEADER_BYTES, frameEnd)).toString(
        "utf8",
      );
      let value: unknown;
      try {
        value = JSON.parse(text);
      } catch (error) {
        throw new GatewayTransportFrameError(
          "frame_malformed",
          error instanceof Error ? error.message : "malformed gateway transport frame JSON",
        );
      }
      frames.push({ text, value });
      offset = frameEnd;
    }

    if (offset > 0) {
      this.buffer = this.buffer.subarray(offset);
    }
    return frames;
  }

  close(): void {
    if (this.buffer.byteLength > 0) {
      throw new GatewayTransportFrameError(
        "frame_truncated",
        "gateway transport stream ended with a partial frame",
      );
    }
  }
}
