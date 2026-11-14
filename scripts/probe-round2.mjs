// Round 2: threshold array-size sweep + second dictionary.
// "threshold" with a scalar "0" errors "Too many values for input signal
// threshold" — it may be an ARRAY signal. Sweep lengths 0..8.
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
const snarkjs = require("snarkjs");

const WASM = "./circuits/gatekeeper.wasm";

console.log("--- threshold size sweep ---");
for (let len = 0; len <= 8; len++) {
  const arr = new Array(len).fill("0");
  try {
    await snarkjs.wtns.calculate({ threshold: arr }, WASM, "/tmp/gk-probe-thr.wtns");
    console.log(`threshold len=${len}: ACCEPTED-ALL?`);
  } catch (e) {
    const msg = (e && e.message ? e.message : String(e)).replace(/\n/g, " ").trim();
    console.log(`threshold len=${len}: ${msg.slice(0, 110)}`);
  }
}

console.log("--- dictionary round 2 ---");
const NAMES = [
  "thresholds", "minThreshold", "maxThreshold", "amountThreshold",
  "payer", "payee", "sender", "receiver", "from", "to", "dest", "destination",
  "action", "actionCode", "actionType", "op", "operation", "kind",
  "expiry", "validUntil", "validFrom", "createdAt",
  "nonce", "id", "uuid", "ref", "reference", "proofId", "statementId",
  "keyHash", "proofHash", "publicInputs", "inputs", "inputHash",
  "statementHash", "paymentHash", "txHash", "tx", "txId",
  "signature", "sig", "signer", "pubKey", "publicKey",
  "token", "asset", "currency", "chain", "chainId", "network",
  "allowance", "balance", "spendable",
  "approved", "isApproved", "allow", "allowed", "permit",
  "taskIndex", "taskNonce", "recipientAddress",
  "fee", "feeAmount", "gas", "cost",
  "memo", "data", "note", "reason", "reasonCode",
  "circuitVersion", "version",
  "domain", "domainSeparator", "separator",
  "root", "merkleRoot", "leaf", "sibling", "path", "index", "commitment",
  "policy", "policyHash", "rule", "rules", "condition",
  "enabled", "active", "paused",
  "owner", "admin", "controller",
  "counter", "count", "seq", "sequence",
  "random", "randomness", "entropy",
  "challenge", "response",
  "a", "b", "c", "x", "y", "z", "v0", "in1", "in2",
  "statement", "statement_hash", "public_hash", "hashOfInputs",
  "vk_hash", "vkHash", "verification_key_hash",
  "registered_vk", "task_vk", "registeredVk", "taskVk",
  "public_signals", "publicSignals", "proof", "proof_tx", "proofTx",
  "min_amount", "max_amount", "amount_min", "amount_max",
  "valid_from", "valid_until", "expires_at",
];
const found = [];
for (const name of NAMES) {
  try {
    await snarkjs.wtns.calculate({ [name]: "0" }, WASM, "/tmp/gk-probe-name2.wtns");
    console.log(`${name}: ACCEPTED-ALL?`);
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
    }
  }
}
console.log("KNOWN round2:", JSON.stringify(found));
console.log("done round 2");
