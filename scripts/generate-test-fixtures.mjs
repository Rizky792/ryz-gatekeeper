// Generate test-proof fixtures ONCE and save them to test/fixtures/.
// Proof generation (witness + groth16.prove) is slow on a small VM, so the
// test suite loads these fixtures instead of proving on every run.
// Re-run with `npm run test:fixtures` after `npm run build` if the circuit
// or the test inputs change.
//
// Fixtures use TEST values only (recipient 0x1234..., salt 999999, taskId
// 12345). They are safe to commit: they prove nothing about real payments.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { generateTestProof, DEFAULT_TEST_INPUTS } from "../dist/witness.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..");
const FIXTURES_DIR = path.join(ROOT, "test", "fixtures");
const WASM = path.join(ROOT, "circuits", "gatekeeper.wasm");
const ZKEY = path.join(ROOT, "circuits", "gatekeeper_final.zkey");

const VK = DEFAULT_TEST_INPUTS.registeredVkHash;
const OTHER_VK = "0x1111111111111111111111111111111111111111111111111111111111111111";

const CASES = [
  ["approve", { ...DEFAULT_TEST_INPUTS }],
  // The circuit does NOT check balance >= amount (verified by counterexample):
  // balance 200 < amount 250 still evaluates to APPROVE (balance >= minimum
  // 100 is what matters). This fixture pins that semantics.
  [
    "approve-balance-below-amount",
    { ...DEFAULT_TEST_INPUTS, minimum: 100, publicBalance: 200, amount: 250, decision: 1 },
  ],
  [
    "reject-amount-above-max",
    { ...DEFAULT_TEST_INPUTS, amount: 400, maxTransfer: 300, decision: 0 },
  ],
  [
    "reject-balance-below-minimum",
    { ...DEFAULT_TEST_INPUTS, publicBalance: 100, amount: 50, minimum: 250, decision: 0 },
  ],
  [
    "reject-expired",
    { ...DEFAULT_TEST_INPUTS, currentBlock: 1000000, expiryBlock: 1000000, decision: 0 },
  ],
  [
    "reject-task-vk-mismatch",
    { ...DEFAULT_TEST_INPUTS, registeredVkHash: VK, proofVkHash: OTHER_VK, decision: 0 },
  ],
  // recipient != conditionRecipient: the circuit evaluates to REJECT
  // (decision=0). The task's recipient matches publicSignals[7] but not [8].
  [
    "reject-recipient-mismatch",
    {
      ...DEFAULT_TEST_INPUTS,
      conditionRecipient: "0x9999999999999999999999999999999999999999",
      decision: 0,
    },
  ],
];

fs.mkdirSync(FIXTURES_DIR, { recursive: true });
// Each case gets a DISTINCT taskId (12345 + index) so the fixtures are
// distinct tasks for the HTTP dedup tests (same task_id + different proof
// would otherwise collide in the seen-proof store).
for (let i = 0; i < CASES.length; i++) {
  const [name, inputs] = CASES[i];
  const casedInputs = { ...inputs, taskId: 12345 + i };
  const t0 = Date.now();
  const { proof, publicSignals, proveMs, witnessMs } = await generateTestProof(casedInputs, {
    wasmPath: WASM,
    zkeyPath: ZKEY,
  });
  const fixture = {
    name,
    inputs: Object.fromEntries(Object.entries(casedInputs).map(([k, v]) => [k, String(v)])),
    proof,
    publicSignals,
    proveMs,
    witnessMs,
    generatedAt: new Date().toISOString(),
  };
  fs.writeFileSync(path.join(FIXTURES_DIR, `${name}.json`), JSON.stringify(fixture, null, 2));
  console.log(`${name}: taskId=${casedInputs.taskId} witness ${witnessMs}ms, prove ${proveMs}ms, total ${Date.now() - t0}ms`);
}
console.log(`wrote ${CASES.length} fixtures to ${FIXTURES_DIR}`);
// snarkjs leaves the Node event loop alive after proving; exit explicitly.
process.exit(0);
