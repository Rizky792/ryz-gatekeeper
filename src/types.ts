// Typed interfaces for the Proof Gatekeeper agent (Agent Games, zkVerify).
// Shapes follow the starter prompt on agentgames.zkverify.io/build.

/** A Groth16 proof as produced/consumed by snarkjs (BN128). */
export interface Groth16Proof {
  pi_a: [string, string, string];
  pi_b: [[string, string], [string, string], [string, string]];
  pi_c: [string, string, string];
  protocol: "groth16";
  curve: "bn128";
}

/** The `input` object of a proof-gatekeeper task envelope. */
export interface GatekeeperTaskInput {
  /** Registered verification-key hash for the statement (0x... 32-byte hash). */
  registered_vk: string;
  /** Verification-key hash of the proof being gated (0x... 32-byte hash). */
  task_vk: string;
  /** Amount the payment requests (smallest unit; number or decimal string). */
  amount: number | string;
  /** Payment recipient (0x... address). */
  recipient: string;
  /** The ZK proof backing the payment (absent => REJECT missing_proof). */
  proof?: Groth16Proof | null;
  /** Public signals of the proof: exactly 13 field elements (decimal strings).
   *  Layout (verified empirically against the gatekeeper circuit, see
   *  circuit.ts): [0] statementHash = Poseidon(salt, taskId),
   *  [1] registeredVkHash, [2] proofVkHash, [3] minimum,
   *  [4] publicBalance, [5] expiryBlock, [6] currentBlock,
   *  [7] recipient, [8] conditionRecipient, [9] amount,
   *  [10] maxTransfer, [11] decision (0|1), [12] taskId. */
  public_signals?: string[] | null;
}

/** A task envelope POSTed by the platform to POST /agent. */
export interface GatekeeperTask {
  type: string; // "agent-games.proof-gatekeeper.v1"
  task_id: string; // e.g. "gk_8d31_..."
  mode?: string; // "competition" | "practice"
  input: GatekeeperTaskInput;
  /** Unix seconds, when present. Stale timestamps are REJECTed. */
  timestamp?: number;
  /** Optional proof reference supplied by the platform (dedup key aid). */
  proofReference?: string;
  proof_reference?: string;
  /** Optional transaction reference for the proof (Kurier / on-chain). */
  proof_tx?: string;
}

/** Preflight envelope POSTed by the platform before marking the agent active. */
export interface PreflightTask {
  type: "agent-games.preflight.v1";
  agent_id: string;
  timestamp: number;
  challenge: string;
}

export type DecisionKind = "APPROVE" | "REJECT";

/** The agent's response to a task. */
export interface Decision {
  decision: DecisionKind;
  /** snake_case reason code, short (e.g. "vk_substitution"). */
  reason_code: string;
  /** Included on APPROVE always; on REJECT when the proof exists and is
   *  verifiable; omitted only when the task has no proof at all. */
  proof?: Groth16Proof;
  public_signals?: string[];
  /** Transaction reference for the finalized proof verification, when known
   *  (Kurier). Absent when verification is local-only (no Kurier key). */
  proof_tx?: string;
}

/** A persisted record of a processed proof reference (dedup / idempotency). */
export interface SeenProofRecord {
  taskId: string;
  /** publicSignals[0] = Poseidon(salt, taskId). */
  statementHash: string;
  /** keccak256 of the canonical proof+publicSignals JSON (hex). */
  proofHash: string;
  decision: DecisionKind;
  reasonCode: string;
  /** Kurier transaction reference, when the decision was APPROVE via Kurier. */
  proofTx?: string;
  decidedAt: string; // ISO timestamp
  /** Task bindings the decision was made for (replay requires an exact
   *  match — a retry with different bindings is not a retry). */
  recipient: string;
  amount: string;
  registeredVk: string;
  taskVk: string;
}
