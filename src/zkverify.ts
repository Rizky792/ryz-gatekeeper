// Proof verification against the zkVerify network (Kurier) and locally
// (snarkjs). Local verification is the primary gate: it re-checks the Groth16
// proof against the gatekeeper verification key. Kurier adds on-chain
// finalization + a proof_tx when a KURIER_API_KEY is configured.
//
// Kurier API (verbatim from agentgames.zkverify.io/build §03):
//   POST https://api.kurier.xyz/api/v1/submitProof
//   headers: Content-Type: application/json, x-api-key: KURIER_API_KEY
//   body: { proofType: "groth16", proof, publicSignals, vkHash }
//   Status: Submitted -> IncludedInBlock -> Finalized ("Safe to return as
//   confirmed").
// ASSUMPTIONS (the /build page does not publish response shapes): submitProof
// returns a job id under one of `jobId` / `job_id` / `id`; the status endpoint
// is GET /job-status/{API_KEY}/{jobId} and returns a status under `status` /
// `state`, plus a transaction reference under `txHash` / `proofTx` /
// `transactionHash` when finalized. The code accepts all of these spellings
// and treats an unrecognised response as "not finalized".

import fs from "node:fs";
import path from "node:path";
import type { Groth16Proof } from "./types.js";
import { GATEKEEPER_VK_HASH } from "./circuit.js";

// snarkjs sets `__esModule: true` but has no `default` export, so a default
// import compiles to `snarkjs_1.default` (undefined at runtime). Use the
// require-style import (same fix as the Steal-the-VFY agent).
import snarkjs = require("snarkjs");

export const KURIER_API_URL = "https://api.kurier.xyz/api/v1";

export interface LocalVerification {
  valid: boolean;
  /** Why verification failed, when known (human-readable, not a reason code). */
  error?: string;
}

let cachedVkey: any = null;

/** Load (and cache) the gatekeeper verification key from circuits/. */
export function loadVkey(circuitsDir: string): any {
  if (cachedVkey) return cachedVkey;
  const p = path.join(circuitsDir, "gatekeeper.vkey.json");
  cachedVkey = JSON.parse(fs.readFileSync(p, "utf8"));
  return cachedVkey;
}

/** Verify a Groth16 proof locally against the gatekeeper vkey. */
export async function verifyProofLocally(
  proof: Groth16Proof,
  publicSignals: string[],
  circuitsDir: string,
): Promise<LocalVerification> {
  try {
    const vkey = loadVkey(circuitsDir);
    const ok = await snarkjs.groth16.verify(vkey, publicSignals, proof);
    return { valid: ok === true };
  } catch (e: any) {
    return { valid: false, error: e?.message ?? String(e) };
  }
}

export interface KurierSubmitResult {
  submitted: boolean;
  jobId?: string;
  /** Present when the key is missing or the request failed outright. */
  reason?: string;
}

/** Submit a proof to Kurier for on-chain verification. Returns
 *  { submitted: false } when no API key is configured — never throws for a
 *  missing key (local verification is the fallback). */
export async function submitProofToKurier(
  proof: Groth16Proof,
  publicSignals: string[],
  apiKey: string,
): Promise<KurierSubmitResult> {
  if (!apiKey) return { submitted: false, reason: "no_kurier_api_key" };
  try {
    const res = await fetch(`${KURIER_API_URL}/submitProof`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-api-key": apiKey },
      body: JSON.stringify({
        proofType: "groth16",
        proof,
        publicSignals,
        vkHash: GATEKEEPER_VK_HASH,
      }),
    });
    if (!res.ok) return { submitted: false, reason: `kurier_http_${res.status}` };
    const data: any = await res.json().catch(() => ({}));
    const jobId = data?.jobId ?? data?.job_id ?? data?.id ?? data?.jobID;
    if (!jobId || typeof jobId !== "string") {
      return { submitted: false, reason: "kurier_no_job_id" };
    }
    return { submitted: true, jobId };
  } catch (e: any) {
    return { submitted: false, reason: e?.message ?? String(e) };
  }
}

export interface KurierStatus {
  status: string; // e.g. "Submitted" | "IncludedInBlock" | "Finalized" | "Failed"
  proofTx?: string;
}

/** Poll one Kurier job until it reaches Finalized/Failed or the timeout. */
export async function waitForKurierFinalized(
  jobId: string,
  apiKey: string,
  timeoutMs: number,
  pollIntervalMs = 5000,
): Promise<KurierStatus> {
  const deadline = Date.now() + timeoutMs;
  let last: KurierStatus = { status: "Submitted" };
  while (Date.now() < deadline) {
    try {
      const res = await fetch(
        `${KURIER_API_URL}/job-status/${encodeURIComponent(apiKey)}/${encodeURIComponent(jobId)}`,
        { headers: { "x-api-key": apiKey } },
      );
      if (res.ok) {
        const data: any = await res.json().catch(() => ({}));
        const status = String(data?.status ?? data?.state ?? "Submitted");
        const proofTx = data?.txHash ?? data?.proofTx ?? data?.transactionHash ?? data?.tx_hash;
        last = { status, proofTx: typeof proofTx === "string" ? proofTx : undefined };
        if (status === "Finalized" || status === "Failed") return last;
      }
    } catch {
      // Transient network error: keep polling until the deadline.
    }
    await new Promise((r) => setTimeout(r, Math.min(pollIntervalMs, Math.max(0, deadline - Date.now()))));
  }
  return last;
}
