// HMAC-SHA256 verification + signing for the x-agent-games-signature header.
// The platform signs the RAW request body; the agent signs the RAW response
// body. The secret comes from the dashboard (Rotate Secret), never from git.

import { createHmac, timingSafeEqual } from "node:crypto";

/** Accept a header value in any of the encodings the platform might use.
 *  The platform never published its exact signature encoding (the spec
 *  flagged hex vs base64 vs prefixed as OPEN), so all plausible forms are
 *  normalized here: "sha256=<hex>" (GitHub-style), "0x"-prefixed hex, bare
 *  hex, and base64. Returns the raw 32 signature bytes, or null. */
export function normalizeSignatureHeader(value: string | undefined): Buffer | null {
  if (!value) return null;
  const trimmed = value.trim();
  if (!trimmed) return null;
  let hex = trimmed;
  if (hex.toLowerCase().startsWith("sha256=")) hex = hex.slice(7).trim();
  if (hex.toLowerCase().startsWith("0x")) hex = hex.slice(2);
  if (/^[0-9a-fA-F]{64}$/.test(hex)) return Buffer.from(hex, "hex");
  try {
    const b64 = Buffer.from(trimmed, "base64");
    if (b64.length === 32) return b64;
  } catch {
    // not base64 — fall through
  }
  return null;
}

/** HMAC-SHA256 of `body` under `secret`, as a lowercase hex string. */
export function hmacHex(secret: string, body: Buffer | string): string {
  return createHmac("sha256", secret).update(body).digest("hex");
}

/**
 * Verify the platform's signature over the raw body. Returns true only when
 * the header is present, decodes to 32 bytes in a recognized encoding
 * (0x-hex, bare hex, "sha256=" hex, or base64), and matches in constant
 * time. Never throws on malformed input (returns false).
 */
export function verifyHmac(secret: string, rawBody: Buffer, signatureHeader: string | undefined): boolean {
  const sig = normalizeSignatureHeader(signatureHeader);
  if (!sig) return false;
  const expected = hmacHex(secret, rawBody);
  try {
    return sig.length === 32 && timingSafeEqual(sig, Buffer.from(expected, "hex"));
  } catch {
    return false;
  }
}

/** Sign a raw response body (the value for the x-agent-games-signature header). */
export function signResponse(secret: string, rawBody: Buffer | string): string {
  return hmacHex(secret, rawBody);
}
