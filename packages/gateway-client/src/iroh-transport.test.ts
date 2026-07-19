import { beforeEach, describe, expect, it, vi } from "vitest";

const controls = vi.hoisted(() => ({
  resolveBind: null as null | ((endpoint: unknown) => void),
  endpoint: {
    close: vi.fn(),
    connect: vi.fn(),
  },
  connection: {
    close: vi.fn(),
    openBi: vi.fn(),
  },
  stream: {
    recv: { read: vi.fn() },
    send: { writeAll: vi.fn(), finish: vi.fn() },
  },
}));

vi.mock(
  "@number0/iroh",
  () => ({
    default: {
      Endpoint: {
        builder: () => ({
          applyN0: vi.fn(),
          relayMode: vi.fn(),
          bind: vi.fn(
            async () =>
              await new Promise((resolve) => {
                controls.resolveBind = resolve;
              }),
          ),
        }),
      },
      EndpointTicket: {
        fromString: () => ({ endpointAddr: () => ({}) }),
      },
      RelayMode: {
        defaultMode: () => "default",
        disabled: () => "disabled",
        staging: () => "staging",
        customFromUrls: (urls: string[]) => ({ custom: urls }),
      },
    },
  }),
  { virtual: true },
);

const { GatewayIrohClientTransport } = await import("./iroh-transport.js");

describe("GatewayIrohClientTransport", () => {
  beforeEach(() => {
    controls.resolveBind = null;
    controls.endpoint.close.mockReset();
    controls.endpoint.connect.mockReset();
    controls.connection.close.mockReset();
    controls.connection.openBi.mockReset();
    controls.stream.recv.read.mockReset();
    controls.stream.send.writeAll.mockReset();
    controls.stream.send.finish.mockReset();
    controls.endpoint.connect.mockResolvedValue(controls.connection);
    controls.connection.openBi.mockResolvedValue(controls.stream);
    controls.stream.recv.read.mockResolvedValue(null);
  });

  it("does not reopen after close wins the async connect race", async () => {
    const transport = new GatewayIrohClientTransport({ ticket: "iroh-ticket" });
    const open = vi.fn();
    transport.on("open", open);
    await vi.waitFor(() => expect(controls.resolveBind).toBeTypeOf("function"));

    transport.close();
    controls.resolveBind?.(controls.endpoint);

    await vi.waitFor(() => expect(controls.endpoint.close).toHaveBeenCalledTimes(1));
    expect(open).not.toHaveBeenCalled();
    expect(transport.readyState).toBe(3);
    expect(controls.endpoint.connect).not.toHaveBeenCalled();
  });
});
