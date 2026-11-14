// Unit tests for the pure decide() function (src/gatekeeper.ts).
// Uses locally generated proof fixtures (test/fixtures/*.json) — the proofs
// are real Groth16 proofs of the gatekeeper circuit, so the public signals
// are exactly what a platform task would carry.
// Run: npm test (after npm run build; fixtures via npm run test:fixtures)
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { decide } from "../dist/gatekeeper.js";
import { statementHash, taskIdToField } from "../dist/circuit.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FIXTURES = path.join(__dirname, "fixtures");

function load(name) {
  return JSON.parse(fs.readFileSync(path.join(FIXTURES, `${name}.json`), "utf8"));
}

const VK = "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";
const OTHER_VK = "0x1111111111111111111111111111111111111111111111111111111111111111";
const OTHER_RECIPIENT = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

function taskFromFixture(fixture, overrides = {}) {
  const inp = fixture.inputs;
  const task = {
    type: "agent-games.proof-gatekeeper.v1",
    task_id: String(inp.taskId),
    mode: "practice",
    input: {
      registered_vk: inp.registeredVkHash,
      task_vk: inp.proofVkHash,
      amount: Number(inp.amount),
      recipient: inp.recipient,
      proof: fixture.proof,
      public_signals: fixture.publicSignals,
    },
    timestamp: Math.floor(Date.now() / 1000),
  };
  // Deep-merge the input overrides.
  if (overrides.input) {
    task.input = { ...task.input, ...overrides.input };
    delete overrides.input;
  }
  return { ...task, ...overrides };
}

function baseCtx(overrides = {}) {
  return {
    registeredVk: VK,
    policyMaxTransferCap: null,
    policyMinBalance: null,
    policyRequireBalanceCoversAmount: false,
    proofValid: true,
    proofFinalized: true,
    kurierUsed: false,
    nowSeconds: Math.floor(Date.now() / 1000),
    taskMaxAgeSeconds: 300,
    ...overrides,
  };
}

describe("decide() — APPROVE paths", () => {
  it("approves a valid proof with matching task bindings", () => {
    const f = load("approve");
    const d = decide(taskFromFixture(f), baseCtx());
    assert.equal(d.decision, "APPROVE");
    assert.equal(d.reason_code, "ok");
    assert.ok(d.proof, "APPROVE must include the proof");
    assert.ok(d.public_signals, "APPROVE must include public_signals");
    assert.equal(d.public_signals.length, 13);
  });

  it("approves when balance < amount (circuit does not check balance >= amount)", () => {
    const f = load("approve-balance-below-amount");
    const d = decide(taskFromFixture(f), baseCtx());
    assert.equal(d.decision, "APPROVE");
    assert.equal(d.reason_code, "ok");
  });

  it("rejects balance < amount only when the opt-in policy is enabled", () => {
    const f = load("approve-balance-below-amount");
    const d = decide(taskFromFixture(f), baseCtx({ policyRequireBalanceCoversAmount: true }));
    assert.equal(d.decision, "REJECT");
    assert.equal(d.reason_code, "policy_balance_below_amount");
  });

  it("publicSignals[0] equals Poseidon(salt, taskId)", async () => {
    const f = load("approve");
    const h = await statementHash(999999n, 12345n);
    assert.equal(f.publicSignals[0], h.toString());
    assert.equal(taskIdToField("12345"), 12345n);
  });
});

describe("decide() — REJECT paths (circuit conditions)", () => {
  it("amount above maxTransfer", () => {
    const f = load("reject-amount-above-max");
    const d = decide(taskFromFixture(f), baseCtx());
    assert.equal(d.decision, "REJECT");
    assert.equal(d.reason_code, "amount_above_max_transfer");
  });

  it("balance below minimum", () => {
    const f = load("reject-balance-below-minimum");
    const d = decide(taskFromFixture(f), baseCtx());
    assert.equal(d.decision, "REJECT");
    assert.equal(d.reason_code, "balance_below_minimum");
  });

  it("expired (currentBlock >= expiryBlock)", () => {
    const f = load("reject-expired");
    const d = decide(taskFromFixture(f), baseCtx());
    assert.equal(d.decision, "REJECT");
    assert.equal(d.reason_code, "expired");
  });

  it("proof vk differs from registered vk (task-level substitution)", () => {
    const f = load("reject-task-vk-mismatch");
    // task as the platform would send it: registered_vk != task_vk
    const d = decide(taskFromFixture(f), baseCtx());
    assert.equal(d.decision, "REJECT");
    assert.equal(d.reason_code, "vk_substitution");
  });

  it("proof vk hash does not match the task's task_vk", () => {
    const f = load("reject-task-vk-mismatch");
    // Same proof, but the task claims registered_vk == task_vk == VK, so the
    // proof's own proofVkHash (OTHER_VK) is the mismatch.
    const d = decide(taskFromFixture(f, { input: { task_vk: VK } }), baseCtx());
    assert.equal(d.decision, "REJECT");
    assert.equal(d.reason_code, "task_vk_mismatch");
  });

  it("condition recipient differs from the task recipient", () => {
    const f = load("reject-recipient-mismatch");
    const d = decide(taskFromFixture(f), baseCtx());
    assert.equal(d.decision, "REJECT");
    assert.equal(d.reason_code, "condition_recipient_mismatch");
  });

  it("decision=0 with no other visible failure -> decision_not_approve", () => {
    const f = load("approve");
    // Synthetic: take a valid APPROVE proof's signals, flip decision to 0,
    // and pretend the proof verified (decide() trusts ctx.proofValid).
    const signals = [...f.publicSignals];
    signals[11] = "0";
    const d = decide(taskFromFixture(f, { input: { public_signals: signals } }), baseCtx());
    assert.equal(d.decision, "REJECT");
    assert.equal(d.reason_code, "decision_not_approve");
  });
});

describe("decide() — REJECT paths (bindings / envelope)", () => {
  it("recipient mismatch (task recipient differs from the proof)", () => {
    const f = load("approve");
    const d = decide(taskFromFixture(f, { input: { recipient: OTHER_RECIPIENT } }), baseCtx());
    assert.equal(d.decision, "REJECT");
    assert.equal(d.reason_code, "recipient_mismatch");
  });

  it("vk mismatch (proof's registered vk differs from the task's)", () => {
    const f = load("approve");
    const d = decide(
      taskFromFixture(f, { input: { registered_vk: OTHER_VK, task_vk: OTHER_VK } }),
      baseCtx(),
    );
    assert.equal(d.decision, "REJECT");
    assert.equal(d.reason_code, "vk_mismatch");
  });

  it("unregistered vk (task's registered vk is not this agent's)", () => {
    const f = load("approve");
    const d = decide(taskFromFixture(f), baseCtx({ registeredVk: OTHER_VK }));
    assert.equal(d.decision, "REJECT");
    assert.equal(d.reason_code, "unregistered_vk");
  });

  it("amount mismatch", () => {
    const f = load("approve");
    const d = decide(taskFromFixture(f, { input: { amount: 999 } }), baseCtx());
    assert.equal(d.decision, "REJECT");
    assert.equal(d.reason_code, "amount_mismatch");
  });

  it("invalid task id", () => {
    const f = load("approve");
    const d = decide(taskFromFixture(f, { task_id: "99999" }), baseCtx());
    assert.equal(d.decision, "REJECT");
    assert.equal(d.reason_code, "invalid_task_id");
  });

  it("missing proof", () => {
    const f = load("approve");
    const task = taskFromFixture(f);
    delete task.input.proof;
    delete task.input.public_signals;
    const d = decide(task, baseCtx());
    assert.equal(d.decision, "REJECT");
    assert.equal(d.reason_code, "missing_proof");
    assert.equal(d.proof, undefined, "no proof to include when the task has none");
  });

  it("invalid public signals (wrong count)", () => {
    const f = load("approve");
    const d = decide(
      taskFromFixture(f, { input: { public_signals: ["1", "2", "3"] } }),
      baseCtx(),
    );
    assert.equal(d.decision, "REJECT");
    assert.equal(d.reason_code, "invalid_public_signals");
  });

  it("invalid proof (snarkjs verification failed)", () => {
    const f = load("approve");
    const d = decide(taskFromFixture(f), baseCtx({ proofValid: false }));
    assert.equal(d.decision, "REJECT");
    assert.equal(d.reason_code, "invalid_proof");
    assert.ok(d.proof, "REJECT includes the proof when one exists");
  });

  it("proof not finalized (Kurier was used)", () => {
    const f = load("approve");
    const d = decide(taskFromFixture(f), baseCtx({ kurierUsed: true, proofFinalized: false }));
    assert.equal(d.decision, "REJECT");
    assert.equal(d.reason_code, "proof_not_finalized");
  });

  it("stale timestamp", () => {
    const f = load("approve");
    const d = decide(
      taskFromFixture(f, { timestamp: Math.floor(Date.now() / 1000) - 1000 }),
      baseCtx(),
    );
    assert.equal(d.decision, "REJECT");
    assert.equal(d.reason_code, "stale_task");
  });

  it("malformed task (no task_id / no input)", () => {
    const d1 = decide({ type: "agent-games.proof-gatekeeper.v1" }, baseCtx());
    assert.equal(d1.reason_code, "malformed_task");
    const d2 = decide({ type: "x", task_id: "1", input: null }, baseCtx());
    assert.equal(d2.reason_code, "malformed_task");
  });
});

describe("decide() — policy caps", () => {
  it("policy max transfer cap", () => {
    const f = load("approve");
    const d = decide(taskFromFixture(f), baseCtx({ policyMaxTransferCap: 100n }));
    assert.equal(d.decision, "REJECT");
    assert.equal(d.reason_code, "policy_max_transfer_exceeded");
  });

  it("policy min balance", () => {
    const f = load("approve");
    const d = decide(taskFromFixture(f), baseCtx({ policyMinBalance: 2000n }));
    assert.equal(d.decision, "REJECT");
    assert.equal(d.reason_code, "policy_min_balance_not_met");
  });
});
