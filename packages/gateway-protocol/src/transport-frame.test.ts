import { describe, expect, it } from "vitest";
import {
  encodeGatewayTransportFrame,
  GatewayTransportFrameDecoder,
  GatewayTransportFrameError,
} from "./transport-frame.js";

function lengthPrefixedPayload(payload: string): Uint8Array {
  const encoded = Buffer.from(payload, "utf8");
  const frame = new Uint8Array(4 + encoded.byteLength);
  new DataView(frame.buffer, frame.byteOffset, frame.byteLength).setUint32(
    0,
    encoded.byteLength,
    false,
  );
  frame.set(encoded, 4);
  return frame;
}

describe("gateway transport frame codec", () => {
  it("decodes frames split across multiple chunks", () => {
    const encoded = encodeGatewayTransportFrame({ type: "req", id: "a", method: "ping" });
    const decoder = new GatewayTransportFrameDecoder(1024);

    expect(decoder.push(encoded.subarray(0, 2))).toEqual([]);
    expect(decoder.push(encoded.subarray(2, 8))).toEqual([]);
    expect(decoder.push(encoded.subarray(8))).toEqual([
      {
        text: JSON.stringify({ type: "req", id: "a", method: "ping" }),
        value: { type: "req", id: "a", method: "ping" },
      },
    ]);
    expect(() => decoder.close()).not.toThrow();
  });

  it("decodes multiple frames delivered in one chunk", () => {
    const first = encodeGatewayTransportFrame({ type: "event", event: "a" });
    const second = encodeGatewayTransportFrame({ type: "res", id: "b", ok: true });
    const joined = new Uint8Array(first.byteLength + second.byteLength);
    joined.set(first, 0);
    joined.set(second, first.byteLength);

    expect(new GatewayTransportFrameDecoder(1024).push(joined).map((frame) => frame.value)).toEqual(
      [
        { type: "event", event: "a" },
        { type: "res", id: "b", ok: true },
      ],
    );
  });

  it("rejects oversized frames before buffering the body", () => {
    const frame = lengthPrefixedPayload("{}");
    new DataView(frame.buffer, frame.byteOffset, frame.byteLength).setUint32(0, 5, false);
    const decoder = new GatewayTransportFrameDecoder(4);

    expect(() => decoder.push(frame.subarray(0, 4))).toThrow(
      new GatewayTransportFrameError("frame_oversized", "gateway transport frame exceeds 4 bytes"),
    );
  });

  it("rejects malformed JSON frames", () => {
    const decoder = new GatewayTransportFrameDecoder(1024);

    expect(() => decoder.push(lengthPrefixedPayload("{"))).toThrow(GatewayTransportFrameError);
    try {
      decoder.push(lengthPrefixedPayload("{"));
    } catch (error) {
      expect(error).toMatchObject({ code: "frame_malformed" });
    }
  });

  it("rejects EOF with a partial header or body", () => {
    const partialHeader = new GatewayTransportFrameDecoder(1024);
    partialHeader.push(Uint8Array.of(0, 0));
    expect(() => partialHeader.close()).toThrow(
      new GatewayTransportFrameError(
        "frame_truncated",
        "gateway transport stream ended with a partial frame",
      ),
    );

    const partialBody = new GatewayTransportFrameDecoder(1024);
    partialBody.push(lengthPrefixedPayload("{}").subarray(0, 5));
    expect(() => partialBody.close()).toThrow(
      new GatewayTransportFrameError(
        "frame_truncated",
        "gateway transport stream ended with a partial frame",
      ),
    );
  });
});
