// Gatekeeper circuit facts — all verified empirically against the published
// wasm+zkey (see ~/workspace/agent-games/build-report-gatekeeper.md for the
// probe method and the full evidence). Anything marked ASSUMPTION is a
// documented guess, not a verified fact.

import { keccak256, toBytes } from "viem";
import { buildPoseidon } from "circomlibjs";

/** BN128 (alt_bn128) scalar field prime. */
export const FIELD_PRIME =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

/** Circuit name as the platform calls it. */
export const CIRCUIT_NAME = "gatekeeper";
export const CIRCUIT_PROTOCOL = "groth16";
export const CIRCUIT_CURVE = "bn128";

/** Verification-key hash of the gatekeeper circuit itself, from
 *  https://agentgames.zkverify.io/api/circuit-info. This is the vk used by
 *  snarkjs to verify gatekeeper proofs — NOT the same as the task's
 *  registered_vk / task_vk (those are the vks of the payment proof being
 *  gated). Do not confuse the two. */
export const GATEKEEPER_VK_HASH =
  "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";

/** Circuit artifact URLs (also mirrored in circuits/ + scripts/download-circuits.sh). */
export const CIRCUIT_WASM_URL = "https://agentgames.zkverify.io/circuits/gatekeeper.wasm";
export const CIRCUIT_ZKEY_URL =
  "https://agentgames.zkverify.io/circuits/gatekeeper_final.zkey";

/** The gatekeeper circuit has 13 public signals (nPublic=13, verified from
 *  the exported verification key). */
export const PUBLIC_SIGNAL_COUNT = 13;

/** Index of each public signal, verified by reading the witness of locally
 *  generated proofs (witness[1..13] == publicSignals[0..12]). */
export const PS = {
  STATEMENT_HASH: 0,
  REGISTERED_VK_HASH: 1,
  PROOF_VK_HASH: 2,
  MINIMUM: 3,
  PUBLIC_BALANCE: 4,
  EXPIRY_BLOCK: 5,
  CURRENT_BLOCK: 6,
  RECIPIENT: 7,
  CONDITION_RECIPIENT: 8,
  AMOUNT: 9,
  MAX_TRANSFER: 10,
  DECISION: 11,
  TASK_ID: 12,
} as const;

/** All 13 circuit inputs, in witness order (offsets 2..14; offset 1 is the
 *  constant 1). The last one, `salt`, is private; the rest are public.
 *  Names were recovered by FNV-1a brute force against the wasm's input-signal
 *  table (see build-report-gatekeeper.md). */
export const CIRCUIT_INPUTS = [
  "registeredVkHash",
  "proofVkHash",
  "minimum",
  "publicBalance",
  "expiryBlock",
  "currentBlock",
  "recipient",
  "conditionRecipient",
  "amount",
  "maxTransfer",
  "decision",
  "taskId",
  "salt",
] as const;

/** Reduce an arbitrary bigint into the BN128 scalar field. */
export function toField(v: bigint): bigint {
  let r = v % FIELD_PRIME;
  if (r < 0n) r += FIELD_PRIME;
  return r;
}

/** Parse a 0x-hex string (hash or address) or a decimal string into a field
 *  element. Returns null when the value is not parseable. */
export function fieldFromString(v: string | number | bigint): bigint | null {
  try {
    if (typeof v === "bigint") return toField(v);
    if (typeof v === "number") {
      if (!Number.isInteger(v) || v < 0) return null;
      return toField(BigInt(v));
    }
    const s = v.trim();
    if (/^0x[0-9a-fA-F]+$/.test(s)) return toField(BigInt(s));
    if (/^\d+$/.test(s)) return toField(BigInt(s));
    return null;
  } catch {
    return null;
  }
}

/**
 * Convert a task_id string to the circuit's `taskId` field element.
 *
 * ASSUMPTION — the platform never published how the `gk_...` task_id string
 * maps to a field element. The agent's rule:
 *   - all-digit string  -> the integer itself (mod p)
 *   - 0x-hex string     -> the integer itself (mod p)
 *   - anything else     -> keccak256(UTF-8 bytes of the string) mod p
 * This mirrors the Steal-the-VFY agent's UUID handling. It MUST be validated
 * against a real practice envelope: if the platform's task_id values are
 * opaque strings, the keccak branch is the best guess; if the platform sends
 * numeric task ids, the first branch applies. If a practice task's
 * publicSignals[12] does not match any of these, the agent REJECTs with
 * reason_code "invalid_task_id" and the mapping must be fixed from the
 * observed envelope.
 */
export function taskIdToField(taskId: string): bigint {
  const s = taskId.trim();
  if (/^\d+$/.test(s)) return toField(BigInt(s));
  if (/^0x[0-9a-fA-F]+$/.test(s)) return toField(BigInt(s));
  return toField(BigInt(keccak256(toBytes(s))));
}

/** Cached Poseidon instance (circomlibjs). */
let poseidonInstance: any = null;
async function getPoseidon(): Promise<any> {
  if (!poseidonInstance) poseidonInstance = await buildPoseidon();
  return poseidonInstance;
}

/**
 * publicSignals[0] = Poseidon(salt, taskId) — VERIFIED against 3 witness
 * vectors (see build-report-gatekeeper.md). The salt is the prover's private
 * input, so the agent normally CANNOT recompute this value; it is exposed
 * here for tests and for verification when a salt is supplied out-of-band.
 * The value doubles as the proof's unique statement reference for dedup.
 */
export async function statementHash(salt: bigint, taskId: bigint): Promise<bigint> {
  const poseidon = await getPoseidon();
  return poseidon.F.toObject(poseidon([salt, taskId]));
}

/**
 * The circuit's APPROVE conditions, as observed by sweeping the witness
 * (each condition toggled independently; the witness asserts at
 * GatekeeperEvaluation line 102 when `decision` disagrees with the
 * evaluation). ALL must hold for decision == 1:
 *   1. proofVkHash == registeredVkHash
 *   2. recipient == conditionRecipient
 *   3. publicBalance >= minimum
 *   4. amount <= maxTransfer
 *   5. currentBlock < expiryBlock (strict)
 *   6. taskId, salt, recipient, vkHash all nonzero (single IsZero over a
 *      product — inferred from component counts; see build report)
 *   7. decision == (1..6 all true)
 *
 * NOT checked by the circuit (verified by counterexample): publicBalance >=
 * amount. A witness with balance=200, amount=250, minimum=100, decision=1
 * computes fine, and the same inputs with decision=0 assert-fail — so the
 * evaluation is APPROVE even though the balance is below the amount. The
 * `minimum` is a minimum-BALANCE threshold, not a minimum amount, and the
 * amount is bounded only by maxTransfer. The agent follows the circuit by
 * default; an operator who wants the stricter gate can enable
 * POLICY_REQUIRE_BALANCE_COVERS_AMOUNT (see config.ts).
 * The agent re-checks 1..5 explicitly (clear reason codes) and relies on
 * snarkjs proof verification for 6..7 (a valid proof guarantees the circuit's
 * constraints held, including the decision binding).
 */
export const APPROVE_CONDITIONS = [
  "proofVkHash == registeredVkHash",
  "recipient == conditionRecipient",
  "publicBalance >= minimum",
  "amount <= maxTransfer",
  "currentBlock < expiryBlock",
  "taskId, salt, recipient, vkHash nonzero",
  "decision == evaluation",
] as const;
