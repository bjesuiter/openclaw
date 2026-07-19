import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { loadOrCreateGatewayIrohSecretKey } from "./iroh-key.js";

const tempDirs: string[] = [];

async function makeTempDir(): Promise<string> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "openclaw-iroh-key-"));
  tempDirs.push(dir);
  return dir;
}

afterEach(async () => {
  for (const dir of tempDirs.splice(0)) {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

function keyBytes(fill: number): Uint8Array {
  return new Uint8Array(32).fill(fill);
}

describe("Iroh gateway secret key storage", () => {
  it("creates a persistent owner-only key file", async () => {
    const dir = await makeTempDir();
    const keyPath = path.join(dir, "nested", "iroh.key");

    const result = await loadOrCreateGatewayIrohSecretKey({
      path: keyPath,
      generateSecretKeyBytes: () => keyBytes(7),
    });

    expect(result).toMatchObject({ path: keyPath, created: true });
    expect(result.bytes).toEqual(keyBytes(7));
    expect(await fs.readFile(keyPath, "utf8")).toBe(
      `${Buffer.from(keyBytes(7)).toString("base64url")}\n`,
    );
    if (process.platform !== "win32") {
      expect((await fs.stat(keyPath)).mode & 0o777).toBe(0o600);
      expect((await fs.stat(path.dirname(keyPath))).mode & 0o777).toBe(0o700);
    }
  });

  it("reuses an existing key and fixes broad file permissions", async () => {
    const dir = await makeTempDir();
    const keyPath = path.join(dir, "iroh.key");
    await fs.writeFile(keyPath, Buffer.from(keyBytes(9)).toString("base64url"), {
      mode: 0o644,
    });

    const result = await loadOrCreateGatewayIrohSecretKey({
      path: keyPath,
      generateSecretKeyBytes: () => keyBytes(1),
    });

    expect(result.created).toBe(false);
    expect(result.bytes).toEqual(keyBytes(9));
    if (process.platform !== "win32") {
      expect((await fs.stat(keyPath)).mode & 0o777).toBe(0o600);
    }
  });

  it("rejects symlinked key paths", async () => {
    const dir = await makeTempDir();
    const target = path.join(dir, "target.key");
    const link = path.join(dir, "iroh.key");
    await fs.writeFile(target, Buffer.from(keyBytes(2)).toString("base64url"));
    await fs.symlink(target, link);

    await expect(
      loadOrCreateGatewayIrohSecretKey({
        path: link,
        generateSecretKeyBytes: () => keyBytes(3),
      }),
    ).rejects.toThrow("refusing Iroh gateway secret key symlink");
  });

  it("rejects invalid stored key length", async () => {
    const dir = await makeTempDir();
    const keyPath = path.join(dir, "iroh.key");
    await fs.writeFile(keyPath, Buffer.from("short").toString("base64url"));

    await expect(
      loadOrCreateGatewayIrohSecretKey({
        path: keyPath,
        generateSecretKeyBytes: () => keyBytes(3),
      }),
    ).rejects.toThrow("invalid Iroh gateway secret key");
  });
});
