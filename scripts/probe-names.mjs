// Dictionary probe: for each candidate signal name, call wtns.calculate with
// a single-key input {"<name>": "0"} and classify the error:
//   "Signal X not found"            -> name unknown
//   "Too many values for input X"   -> size == 0 (unknown / zero-size)
//   "Not enough values for input X" -> name known, array signal, size > 1
//   "Not all inputs have been set"  -> name known, scalar (size == 1), accepted
// Method proven on the vfy-policy circuit (see ../build-report.md).
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
const snarkjs = require("snarkjs");

const WASM = "./circuits/gatekeeper.wasm";

const NAMES = [
  // from the task envelope / starter prompt
  "amount", "recipient", "registered_vk", "task_vk", "registeredVk", "taskVk",
  "proof", "public_signals", "publicSignals", "task_id", "taskId", "threshold",
  "action", "statement", "vkHash", "vk_hash", "vk", "verificationKey",
  "verificationKeyHash", "statementHash", "paymentHash", "payment",
  // payment / amount variants
  "value", "payer", "payee", "minAmount", "maxAmount", "limit", "amountMin",
  "amountMax", "thresholdAmount", "token", "tokenAddress", "currency",
  "expiry", "deadline", "timestamp", "chainId", "domain", "domainSeparator",
  // reference / replay variants
  "txHash", "proofTx", "txRef", "reference", "proofReference", "proofRef",
  "used", "isUsed", "nullifier", "nonce", "salt", "secret", "seed",
  // statement / hash variants
  "hash", "inputHash", "publicInputsHash", "publicHash", "inputsHash",
  "statement_hash", "payment_hash", "dataHash", "computedHash", "rootHash",
  "root", "merkleRoot", "commitment", "stateHash", "state", "policyHash",
  // decision variants
  "valid", "verified", "decision", "approve", "reject", "isValid",
  "actionCode", "actionType", "operation", "op", "kind", "type", "mode",
  "version", "circuitVersion", "protocol", "curve",
  // identity variants
  "signature", "signer", "pubkey", "address", "recipientHash", "leaf",
  "index", "path", "siblings",
  // snake_case variants
  "registered_vk_hash", "task_vk_hash", "public_signals_hash",
  "min_amount", "max_amount", "tx_hash", "proof_tx", "proof_reference",
  // shared-template names (from the vfy-policy circuit, in case the
  // circuits share a template)
  "selfBalance", "opponentBalance", "matchId", "turnNumber", "strategyParams",
  "policy", "strategy", "strategyHash", "historyHash", "matchIdHash",
  "move", "input", "inputs", "in", "x", "a", "b", "c", "pub", "hash",
];

const found = [];
for (const name of NAMES) {
  try {
    await snarkjs.wtns.calculate({ [name]: "0" }, WASM, "/tmp/gk-probe-name.wtns");
    console.log(`${name}: ACCEPTED-ALL? (no error — unexpected)`);
    found.push(name);
  } catch (e) {
    const msg = (e && e.message ? e.message : String(e)).replace(/\n/g, " ").trim();
    let cls = "OTHER";
    if (msg.includes("not found")) cls = "UNKNOWN";
    else if (msg.includes("Too many values")) cls = "SIZE-0/UNKNOWN";
    else if (msg.includes("Not enough values")) cls = "KNOWN-ARRAY size>1";
    else if (msg.includes("Not all inputs have been set")) cls = "KNOWN-SCALAR size=1";
    if (cls.startsWith("KNOWN")) {
      console.log(`>>> ${name}: ${cls} :: ${msg.slice(0, 100)}`);
      found.push(name);
    } else {
      console.log(`${name}: ${cls}`);
    }
  }
}
console.log("KNOWN:", JSON.stringify(found));
console.log("done");
