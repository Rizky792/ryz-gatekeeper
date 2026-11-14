// Pure, testable decision logic for the Proof Gatekeeper.
// decide(task, ctx) returns APPROVE only when EVERY check passes; any
// missing, uncertain, or failing check returns REJECT (fail closed).
// The function performs no I/O: proof verification (snarkjs / Kurier) and
// dedup are done by the caller and passed in via the context, so the logic
// is unit-testable in isolation.
//
// Check order (first failure wins — the reason code names the first problem
// found, which is the most actionable one for the platform):
//   malformed_task -> stale_task -> missing_proof -> invalid_public_signals
//   -> invalid_proof -> proof_not_finalized -> vk_substitution
//   -> vk_mismatch -> unregistered_vk -> task_vk_mismatch
//   -> recipient_mismatch -> condition_recipient_mismatch -> amount_mismatch
//   -> invalid_task_id -> balance_below_minimum
//   -> amount_above_max_transfer -> expired -> decision_not_approve
//   -> policy_max_transfer_exceeded -> policy_min_balance_not_met
//   -> policy_balance_below_amount -> ok
//
// NOTE: the circuit does NOT check publicBalance >= amount (verified by
// counterexample — see circuit.ts). The agent follows the circuit by
// default; the balance-vs-amount gate is an opt-in policy
// (POLICY_REQUIRE_BALANCE_COVERS_AMOUNT).
//
// NOTE on ordering: the specific threshold/expiry/task-id checks run BEFORE
// decision_not_approve. A valid proof with decision=0 always has at least
// one failing condition (the circuit asserts decision == evaluation), so
// reporting the failing condition — not just "decision_not_approve" — is
// both possible and far more useful. decision_not_approve is the fallback
// for a decision=0 proof whose conditions all pass the agent's re-checks
// (e.g. a failure only the circuit's internal checks can see).

import type { Decision, GatekeeperTask } from "./types.js";
import { FIELD_PRIME, PS, PUBLIC_SIGNAL_COUNT, fieldFromString, taskIdToField } from "./circuit.js";

export interface DecideContext {
  /** The vk hash this agent registered for its statements (0x...). Empty
   *  means "do not check the task's registered_vk against a local value". */
  registeredVk: string;
  policyMaxTransferCap: bigint | null;
  policyMinBalance: bigint | null;
  /** Opt-in stricter gate (NOT a circuit check): refuse when the statement's
   *  publicBalance is below the amount. Default false (follow the circuit). */
  policyRequireBalanceCoversAmount: boolean;
  /** Result of snarkjs groth16.verify on (proof, publicSignals). */
  proofValid: boolean;
  /** Kurier Finalized (or true when Kurier is not used / no key). */
  proofFinalized: boolean;
  /** Kurier transaction reference, when known. */
  proofTx?: string;
  /** Whether Kurier was consulted for this task. */
  kurierUsed: boolean;
  /** Current unix time (seconds), for the timestamp freshness check. */
  nowSeconds: number;
  /** Max age (seconds) of a task timestamp before it is stale. */
  taskMaxAgeSeconds: number;
}

function reject(reasonCode: string, task: GatekeeperTask): Decision {
  const d: Decision = { decision: "REJECT", reason_code: reasonCode };
  // Include the proof + public_signals whenever the task has a proof at all;
  // omit them only when the task has no proof (starter prompt).
  if (task.input?.proof) {
    d.proof = task.input.proof;
    if (Array.isArray(task.input.public_signals)) d.public_signals = task.input.public_signals;
  }
  return d;
}

/** Parse a task amount (number or decimal/hex string) to a bigint. */
function parseAmount(v: unknown): bigint | null {
  if (typeof v === "number") {
    if (!Number.isInteger(v) || v < 0) return null;
    return BigInt(v);
  }
  if (typeof v === "string") {
    const s = v.trim();
    if (/^\d+$/.test(s)) return BigInt(s);
    if (/^0x[0-9a-fA-F]+$/.test(s)) return BigInt(s);
    return null;
  }
  if (typeof v === "bigint") return v >= 0n ? v : null;
  return null;
}

export function decide(task: GatekeeperTask, ctx: DecideContext): Decision {
  // --- envelope shape ---
  if (!task || typeof task !== "object" || !task.input || typeof task.input !== "object") {
    return { decision: "REJECT", reason_code: "malformed_task" };
  }
  if (!task.task_id || typeof task.task_id !== "string" || task.task_id.trim() === "") {
    return { decision: "REJECT", reason_code: "malformed_task" };
  }

  // --- timestamp freshness (when the task carries one) ---
  if (typeof task.timestamp === "number" && Number.isFinite(task.timestamp)) {
    const age = ctx.nowSeconds - task.timestamp;
    if (age > ctx.taskMaxAgeSeconds || age < -60) {
      return reject("stale_task", task);
    }
  }

  // --- proof presence ---
  const proof = task.input.proof ?? null;
  if (!proof || typeof proof !== "object") {
    return { decision: "REJECT", reason_code: "missing_proof" };
  }

  // --- public signals: exactly 13 parseable field elements ---
  const psRaw = task.input.public_signals;
  if (!Array.isArray(psRaw) || psRaw.length !== PUBLIC_SIGNAL_COUNT) {
    return reject("invalid_public_signals", task);
  }
  const ps: (bigint | null)[] = psRaw.map((s) => (typeof s === "string" ? fieldFromString(s) : null));
  if (ps.some((x) => x === null)) {
    return reject("invalid_public_signals", task);
  }
  const signals = ps as bigint[];

  // --- the proof must verify (local snarkjs check done by the caller) ---
  if (!ctx.proofValid) {
    return reject("invalid_proof", task);
  }

  // --- when Kurier was used, finalization is required for APPROVE ---
  if (ctx.kurierUsed && !ctx.proofFinalized) {
    return reject("proof_not_finalized", task);
  }

  // --- vk bindings ---
  const regVkField = fieldFromString(task.input.registered_vk ?? "");
  const taskVkField = fieldFromString(task.input.task_vk ?? "");
  if (regVkField === null || taskVkField === null || regVkField === 0n || taskVkField === 0n) {
    return reject("malformed_task", task);
  }
  // The task itself asks to gate a proof under a vk different from the
  // registered one — the textbook vk-substitution case (example reason code).
  if (regVkField !== taskVkField) {
    return reject("vk_substitution", task);
  }
  if (signals[PS.REGISTERED_VK_HASH] !== regVkField) {
    return reject("vk_mismatch", task);
  }
  if (ctx.registeredVk) {
    const localReg = fieldFromString(ctx.registeredVk);
    if (localReg !== null && localReg !== 0n && regVkField !== localReg) {
      return reject("unregistered_vk", task);
    }
  }
  if (signals[PS.PROOF_VK_HASH] !== taskVkField) {
    return reject("task_vk_mismatch", task);
  }

  // --- recipient / amount bindings ---
  const recipientField = fieldFromString(task.input.recipient ?? "");
  if (recipientField === null || recipientField === 0n) {
    return reject("malformed_task", task);
  }
  if (signals[PS.RECIPIENT] !== recipientField) {
    return reject("recipient_mismatch", task);
  }
  if (signals[PS.CONDITION_RECIPIENT] !== recipientField) {
    return reject("condition_recipient_mismatch", task);
  }
  const amount = parseAmount(task.input.amount);
  if (amount === null) {
    return reject("malformed_task", task);
  }
  if (signals[PS.AMOUNT] !== amount) {
    return reject("amount_mismatch", task);
  }

  // --- task id binding (see circuit.taskIdToField for the mapping rule) ---
  if (signals[PS.TASK_ID] !== taskIdToField(task.task_id)) {
    return reject("invalid_task_id", task);
  }

  // --- the circuit's threshold / balance / expiry conditions, re-checked
  //     explicitly so the reason code names the failing condition ---
  const minimum = signals[PS.MINIMUM];
  const publicBalance = signals[PS.PUBLIC_BALANCE];
  const expiryBlock = signals[PS.EXPIRY_BLOCK];
  const currentBlock = signals[PS.CURRENT_BLOCK];
  const maxTransfer = signals[PS.MAX_TRANSFER];
  // NOTE: no `publicBalance >= amount` check here — the circuit does not
  // enforce it (verified by counterexample; see circuit.ts). It is available
  // as an opt-in policy below.
  if (publicBalance < minimum) {
    return reject("balance_below_minimum", task);
  }
  if (amount > maxTransfer) {
    return reject("amount_above_max_transfer", task);
  }
  if (currentBlock >= expiryBlock) {
    return reject("expired", task);
  }

  // --- the proof's own decision must be APPROVE (1). This is checked
  //     AFTER the specific conditions above, so a REJECT proof reports the
  //     failing condition (not just "decision_not_approve"). A valid proof
  //     with decision=0 always has a failing condition; this branch is the
  //     fallback when the agent's re-checks cannot see which one it is. ---
  if (signals[PS.DECISION] !== 1n) {
    return reject("decision_not_approve", task);
  }

  // --- agent policy caps (optional env config, on top of the circuit) ---
  if (ctx.policyMaxTransferCap !== null && amount > ctx.policyMaxTransferCap) {
    return reject("policy_max_transfer_exceeded", task);
  }
  if (ctx.policyMinBalance !== null && publicBalance < ctx.policyMinBalance) {
    return reject("policy_min_balance_not_met", task);
  }
  if (ctx.policyRequireBalanceCoversAmount && publicBalance < amount) {
    return reject("policy_balance_below_amount", task);
  }

  // --- all checks passed ---
  const d: Decision = {
    decision: "APPROVE",
    reason_code: "ok",
    proof,
    public_signals: psRaw as string[],
  };
  if (ctx.proofTx) d.proof_tx = ctx.proofTx;
  return d;
}

/** Re-exported for tests / docs. */
export { FIELD_PRIME };
