// Brute-force the 8 unknown input names against their FNV-64 hashes
// (recovered from the wasm data section, probe-table-dump.mjs).
// Pure FNV computation — no wasm calls, so tens of thousands of candidates
// cost seconds. Generates singles, camelCase/snake_case pairs, suffixed
// forms, and numbered forms from a domain wordlist.
import { fnvHash } from "./fnv.mjs";

const TARGETS = new Map([
  ["14418c3ee75f7a4e", 2],
  ["3b2514e2617cb386", 3],
  ["c92fe3ad0447b657", 4],
  ["9c9aac1639b93cc4", 5],
  ["9cef1f487868b4fb", 6],
  ["bab23a24475d685f", 7],
  ["acbdf1453659f53d", 9],
  ["12eb7fd2c76a4dda", 11],
]);

const WORDS = [
  "amount", "recipient", "task", "taskId", "salt", "decision", "threshold",
  "payer", "payee", "sender", "receiver", "action", "vk", "vkHash", "proof",
  "public", "signal", "signals", "statement", "payment", "hash", "nonce",
  "secret", "seed", "expiry", "deadline", "timestamp", "chain", "token",
  "fee", "memo", "data", "note", "reason", "domain", "root", "commitment",
  "policy", "rule", "condition", "valid", "approve", "allow", "permit",
  "owner", "admin", "counter", "count", "seq", "sequence", "id", "uuid",
  "ref", "reference", "index", "path", "leaf", "sibling", "merkle",
  "signature", "signer", "pubkey", "address", "balance", "spendable",
  "allowance", "spender", "gas", "cost", "value", "limit", "min", "max",
  "minimum", "maximum", "required", "authorized", "approved", "target",
  "destination", "beneficiary", "from", "to", "in", "out", "input", "output",
  "private", "witness", "circuit", "version", "protocol", "curve", "mode",
  "kind", "type", "op", "operation", "challenge", "response", "random",
  "entropy", "enabled", "active", "paused", "gate", "gatekeeper", "verifier",
  "check", "result", "outcome", "verdict", "evaluation", "evaluate", "eval",
  "registered", "unregistered", "expected", "actual", "provided", "claimed",
  "submitted", "buyer", "seller", "merchant", "customer", "user", "account",
  "wallet", "holder", "issuer", "authority", "authorizer", "approver",
  "validator", "checker", "guard", "cap", "floor", "ceiling", "bound",
  "bounds", "range", "lower", "upper", "lowerBound", "upperBound", "atLeast",
  "atMost", "gte", "lte", "greaterThan", "lessThan", "digest", "calldata",
  "payload", "message", "msg", "tx", "registry", "whitelist", "blacklist",
  "allowlist", "denylist", "spending", "daily", "policyId", "ruleId",
  "conditionId", "paymentPolicy", "spendingLimit", "dailyLimit", "registryHash",
  "taskVkHash", "vkHashHex", "pubkeyHash", "addressHash", "recipientHash",
  "amountHash", "calldataHash", "payloadHash", "messageHash", "msgHash",
  "commitmentHash", "rootHash", "leafHash", "merkleRoot", "merkleProof",
  "proofData", "proofBytes", "proofHash", "zkProof", "groth16Proof",
  "publicInput", "publicInputHash", "witnessHash", "saltHash", "decisionHash",
  "taskHash", "actionHash", "thresholdHash", "policyHash", "stateHash",
  "dataHash", "publicHash", "inputsHash", "inputHash", "keyHash", "txHash",
  "fn", "func", "function", "method", "call", "opCode", "opcode", "code",
  "flag", "flags", "is", "has", "can", "should", "must", "may", "one",
  "two", "first", "second", "third", "main", "sub", "inner", "outer",
  "left", "right", "top", "bottom", "high", "low", "big", "small",
  "new", "old", "current", "next", "prev", "previous", "last", "final",
  "initial", "original", "total", "sum", "partial", "full", "empty",
  "zero", "one", "true", "false", "yes", "no", "on", "off", "open", "closed",
  "locked", "unlocked", "frozen", "thawed", "spent", "unspent", "used",
  "unused", "seen", "unseen", "known", "unknown", "public", "private",
  "internal", "external", "local", "global", "shared", "common", "unique",
  "single", "double", "triple", "multi", "all", "any", "each", "every",
  "some", "none", "null", "void", "undefined", "empty", "blank",
];

const cap = (w) => w.charAt(0).toUpperCase() + w.slice(1);

const candidates = new Set();
// singles
for (const w of WORDS) candidates.add(w);
// numbered singles
for (const w of WORDS) for (let n = 0; n <= 12; n++) candidates.add(w + n);
// camelCase pairs
for (const a of WORDS) for (const b of WORDS) candidates.add(a + cap(b));
// snake_case pairs
for (const a of WORDS) for (const b of WORDS) candidates.add(a + "_" + b);
// suffix forms
for (const w of WORDS) {
  candidates.add(w + "Hash");
  candidates.add(w + "Value");
  candidates.add(w + "Id");
  candidates.add(w + "Code");
  candidates.add(w + "Type");
  candidates.add("is" + cap(w));
  candidates.add("has" + cap(w));
}
// dotted pairs (bus-style)
for (const a of ["threshold", "payment", "statement", "input", "policy", "task", "proof", "gatekeeper"]) {
  for (const b of WORDS) candidates.add(a + "." + b);
}

console.log("candidates:", candidates.size);
const found = [];
let checked = 0;
for (const c of candidates) {
  const h = fnvHash(c);
  checked++;
  if (TARGETS.has(h)) {
    console.log(`>>> MATCH: "${c}" -> offset ${TARGETS.get(h)} (hash ${h})`);
    found.push([c, TARGETS.get(h)]);
  }
}
console.log(`checked ${checked}, found ${found.length}:`, JSON.stringify(found));
console.log("remaining unmatched offsets:", [...TARGETS.entries()].filter(([, o]) => !found.some(([, fo]) => fo === o)).map(([h, o]) => `off=${o} hash=${h}`).join(" | ") || "none");
console.log("done brute force");
