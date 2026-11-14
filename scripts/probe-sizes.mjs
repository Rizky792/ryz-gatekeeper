// Direct size oracle: call the wasm's getInputSignalSize for each candidate
// name and print the exact size. Size >= 0 means the name is in the input
// table (0 = zero-width, e.g. a bus name); -1 means unknown.
// This distinguishes "truly unknown" from "known but zero-width" — the
// dictionary probes conflated those two cases.
import fs from "node:fs";
import { WitnessCalculatorBuilder } from "circom_runtime";

const wasm = fs.readFileSync("./circuits/gatekeeper.wasm");
const wc = await WitnessCalculatorBuilder(wasm);
console.log("circom version:", wc.circom_version());
console.log("getInputSize():", wc.instance.exports.getInputSize());
console.log("getWitnessSize():", wc.instance.exports.getWitnessSize());

import { fnvHash } from "./fnv.mjs";

function sizeOf(name) {
  const h = fnvHash(name);
  const hMSB = parseInt(h.slice(0, 8), 16);
  const hLSB = parseInt(h.slice(8, 16), 16);
  return wc.instance.exports.getInputSignalSize(hMSB, hLSB);
}

const NAMES = [
  // known so far
  "amount", "recipient", "taskId", "salt", "decision", "threshold",
  // dotted / bus-field variants
  "threshold.amount", "threshold.min", "threshold.max", "threshold.value",
  "threshold.threshold", "threshold.limit", "threshold.minimum",
  "payment.amount", "payment.recipient", "payment.taskId", "payment.threshold",
  "statement.amount", "statement.recipient", "statement.threshold",
  "input.amount", "input.recipient", "input.threshold",
  "main.amount", "main.recipient", "main.threshold",
  // round-1/2 names (re-check sizes, incl. zero-width)
  "registered_vk", "task_vk", "registeredVk", "taskVk", "vkHash", "vk",
  "proof", "public_signals", "publicSignals", "task_id", "action",
  "statement", "statementHash", "paymentHash", "payment", "value",
  "payer", "payee", "minAmount", "maxAmount", "limit", "token",
  "expiry", "deadline", "timestamp", "chainId", "nonce", "signature",
  "txHash", "proofTx", "reference", "proofReference", "nullifier",
  "hash", "inputHash", "publicInputsHash", "root", "commitment",
  "valid", "decision", "approve", "actionCode", "version", "circuitVersion",
  "secret", "seed", "randomness", "policyHash", "stateHash", "dataHash",
  "publicHash", "inputsHash", "keyHash", "proofHash", "tx", "txId",
  "sender", "receiver", "from", "to", "dest", "destination", "beneficiary",
  "op", "operation", "kind", "type", "mode", "owner", "admin",
  "counter", "count", "seq", "sequence", "id", "uuid", "ref",
  "fee", "gas", "cost", "memo", "data", "note", "reason", "reasonCode",
  "domain", "separator", "leaf", "index", "path", "sibling",
  "policy", "rule", "rules", "condition", "enabled", "active",
  "random", "entropy", "challenge", "response", "a", "b", "c", "x", "y", "z",
  "approved", "isApproved", "allow", "permit", "thresholds",
  "minThreshold", "maxThreshold", "amountThreshold", "requiredAmount",
  "paymentAmount", "authorizedAmount", "approvedAmount", "limitAmount",
  "sender", "receiver", "expires", "expiration", "validity", "notBefore",
  "notAfter", "seqNo", "sequenceNumber", "counterValue", "hash1", "hash2",
  "tokenId", "spender", "allowanceAmount", "gate", "gatekeeper", "verifier",
  "thresholdMet", "thresholdCheck", "aboveThreshold", "meetsThreshold",
  "recipientOk", "amountOk", "task", "taskHash", "taskType", "taskIndex",
  "pepper", "rand", "inAmount", "inRecipient", "in_amount",
  "thresholdValue", "threshold_amount", "min_amount", "required_amount",
  "paymentId", "paymentRef", "authAmount", "expires_at", "valid_from",
  "valid_until", "proof_tx", "proof_reference", "public_signals_hash",
  "registered_vk_hash", "task_vk_hash", "verification_key_hash",
  "statement_hash", "payment_hash", "tx_hash", "min_amount", "max_amount",
  "amount_min", "amount_max", "public_hash", "hashOfInputs", "inputs",
  "input", "in", "pub", "hash", "vk_hash",
];

const known = [];
for (const name of NAMES) {
  const s = sizeOf(name);
  if (s >= 0) {
    console.log(`>>> ${name}: size=${s}`);
    known.push([name, s]);
  }
}
console.log("KNOWN (name,size):", JSON.stringify(known));
console.log("total known elements:", known.reduce((a, [, s]) => a + s, 0));
console.log("done sizes");
