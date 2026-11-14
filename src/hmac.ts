// HMAC-SHA256 verification + signing for the x-agent-games-signature header.
// The platform signs the RAW request body; the agent signs the RAW response
// body. The secret comes from the dashboard (Rotate Secret), never from git.

import { createHmac, timingSafeEqual } from "node:crypto";

/** Accept a header value that is either raw hex or "sha256=<hex>". */
export function normalizeSignatureHeader(value: string | undefined): string | null {
  if (!value) return null;
  const v = value.trim();
  if (!v) return null;
  if (v.toLowerCase().startsWith("sha256=")) return v.slice(7).trim().toLowerCase();
  return v.toLowerCase();
}

/** HMAC-SHA256 of `body` under `secret`, as a lowercase hex string. */
export function hmacHex(secret: string, body: Buffer | string): string {
  return createHmac("sha256", secret).update(body).digest("hex");
}

/**
 * Verify the platform's signature over the raw body. Returns true only when
 * the header is present, well-formed hex, and matches in constant time.
 * Never throws on malformed input (returns false).
 */
export function verifyHmac(secret: string, rawBody: Buffer, signatureHeader: string | undefined): boolean {
  const sig = normalizeSignatureHeader(signatureHeader);
  if (!sig || !/^[0-9a-f]{64}$/.test(sig)) return false;
  const expected = hmacHex(secret, rawBody);
  try {
    return timingSafeEqual(Buffer.from(sig, "hex"), Buffer.from(expected, "hex"));
  } catch {
    return false;
  }
}

/** Sign a raw response body (the value for the x-agent-games-signature header). */
export function signResponse(secret: string, rawBody: Buffer | string): string {
  return hmacHex(secret, rawBody);
}
