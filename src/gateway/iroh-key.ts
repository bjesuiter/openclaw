// Persistent Iroh transport identity storage.
import fs from "node:fs/promises";
import path from "node:path";
import { resolveStateDir } from "../config/paths.js";
import { resolveUserPath } from "../utils.js";

const DEFAULT_IROH_SECRET_KEY_FILENAME = "gateway-iroh.secret";
const OWNER_ONLY_FILE_MODE = 0o600;
const OWNER_ONLY_DIR_MODE = 0o700;
const IROH_SECRET_KEY_BYTES = 32;

export type GatewayIrohSecretKeyResult = {
  path: string;
  bytes: Uint8Array;
  created: boolean;
};

export function resolveGatewayIrohSecretKeyPath(configuredPath?: string): string {
  const trimmed = configuredPath?.trim();
  if (trimmed) {
    return path.resolve(resolveUserPath(trimmed));
  }
  return path.join(resolveStateDir(), DEFAULT_IROH_SECRET_KEY_FILENAME);
}

function decodeStoredSecretKey(raw: string, keyPath: string): Uint8Array {
  const trimmed = raw.trim();
  const decoded = Buffer.from(trimmed, "base64url");
  if (decoded.byteLength !== IROH_SECRET_KEY_BYTES) {
    throw new Error(`invalid Iroh gateway secret key at ${keyPath}`);
  }
  return new Uint8Array(decoded);
}

async function readExistingSecretKey(keyPath: string): Promise<Uint8Array> {
  const stat = await fs.lstat(keyPath);
  if (stat.isSymbolicLink()) {
    throw new Error(`refusing Iroh gateway secret key symlink at ${keyPath}`);
  }
  if (!stat.isFile()) {
    throw new Error(`Iroh gateway secret key path is not a file: ${keyPath}`);
  }
  if (process.platform !== "win32") {
    await fs.chmod(keyPath, OWNER_ONLY_FILE_MODE);
  }
  return decodeStoredSecretKey(await fs.readFile(keyPath, "utf8"), keyPath);
}

export async function loadOrCreateGatewayIrohSecretKey(params: {
  path?: string;
  generateSecretKeyBytes: () => Uint8Array;
}): Promise<GatewayIrohSecretKeyResult> {
  const keyPath = resolveGatewayIrohSecretKeyPath(params.path);
  try {
    return { path: keyPath, bytes: await readExistingSecretKey(keyPath), created: false };
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code !== "ENOENT") {
      throw error;
    }
  }

  await fs.mkdir(path.dirname(keyPath), { recursive: true, mode: OWNER_ONLY_DIR_MODE });
  if (process.platform !== "win32") {
    await fs.chmod(path.dirname(keyPath), OWNER_ONLY_DIR_MODE);
  }

  const bytes = params.generateSecretKeyBytes();
  if (bytes.byteLength !== IROH_SECRET_KEY_BYTES) {
    throw new Error("Iroh gateway secret key generator returned an invalid key length");
  }
  const encoded = `${Buffer.from(bytes).toString("base64url")}\n`;
  let handle: fs.FileHandle | undefined;
  try {
    handle = await fs.open(keyPath, "wx", OWNER_ONLY_FILE_MODE);
    await handle.writeFile(encoded, "utf8");
    return { path: keyPath, bytes, created: true };
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === "EEXIST") {
      return { path: keyPath, bytes: await readExistingSecretKey(keyPath), created: false };
    }
    throw error;
  } finally {
    await handle?.close();
  }
}
