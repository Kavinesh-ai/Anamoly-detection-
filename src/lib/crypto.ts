import crypto from "node:crypto";

/**
 * Envelope encryption for integration secrets (AWS access keys, kubeconfigs,
 * connector keys) before they are written to Postgres.
 *
 * Uses Node's built-in AES-256-GCM (no custom cryptography, per spec §6/§36).
 * ENCRYPTION_KEY must be a 32-byte key, base64-encoded, supplied via the
 * environment / a real secrets manager in production — never checked into
 * source control.
 */

function getKey(): Buffer {
  const b64 = process.env.ENCRYPTION_KEY;
  if (!b64) {
    throw new Error(
      "ENCRYPTION_KEY is not configured. Set a base64-encoded 32-byte key " +
        "in the environment before storing integration credentials."
    );
  }
  const key = Buffer.from(b64, "base64");
  if (key.length !== 32) {
    throw new Error("ENCRYPTION_KEY must decode to exactly 32 bytes.");
  }
  return key;
}

export function encryptSecret(plaintext: string): {
  ciphertext: string;
  iv: string;
  authTag: string;
} {
  const key = getKey();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([
    cipher.update(plaintext, "utf8"),
    cipher.final(),
  ]);
  return {
    ciphertext: ciphertext.toString("base64"),
    iv: iv.toString("base64"),
    authTag: cipher.getAuthTag().toString("base64"),
  };
}

export function decryptSecret(record: {
  secretCiphertext: string;
  secretIv: string;
  secretAuthTag: string;
}): string {
  const key = getKey();
  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    key,
    Buffer.from(record.secretIv, "base64")
  );
  decipher.setAuthTag(Buffer.from(record.secretAuthTag, "base64"));
  const plaintext = Buffer.concat([
    decipher.update(Buffer.from(record.secretCiphertext, "base64")),
    decipher.final(),
  ]);
  return plaintext.toString("utf8");
}
