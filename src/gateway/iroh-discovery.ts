export type GatewayIrohDiscoverySnapshot = {
  enabled: true;
  alpn: string;
  endpointId: string;
  ticket: string;
  relayMode: "default" | "disabled" | "staging" | "custom";
  relayUrls?: string[];
};

let snapshot: GatewayIrohDiscoverySnapshot | null = null;

export function setGatewayIrohDiscoverySnapshot(next: GatewayIrohDiscoverySnapshot | null): void {
  snapshot = next;
}

export function getGatewayIrohDiscoverySnapshot(): GatewayIrohDiscoverySnapshot | null {
  return snapshot;
}
