// Brute-force round 2 for the 3 remaining unknown inputs
// (offsets 6, 7, 11; hashes 9cef1f487868b4fb, bab23a24475d685f, 12eb7fd2c76a4dda).
// Expanded vocabulary (words NOT in round 1) + 3-part structured combos
// (prefix + middle + suffix), since found names include 3-part forms
// (registeredVkHash, proofVkHash).
import { fnvHash } from "./fnv.mjs";

const TARGETS = new Map([
  ["9cef1f487868b4fb", 6],
  ["bab23a24475d685f", 7],
  ["12eb7fd2c76a4dda", 11],
]);

const NEW = [
  "cutoff", "transfer", "pay", "send", "spend", "settle", "authorize",
  "authorise", "deny", "reject", "refuse", "decline", "block", "forbid",
  "move", "choice", "vote", "bid", "offer", "ask", "agent", "player",
  "opponent", "member", "peer", "strategy", "plan", "state", "level",
  "tier", "grade", "score", "rank", "priority", "weight", "source",
  "origin", "comment", "description", "label", "name", "title", "key",
  "group", "set", "list", "array", "map", "table", "directory", "system",
  "platform", "service", "app", "dapp", "contract", "program", "event",
  "match", "round", "turn", "game", "play", "time", "date", "day",
  "month", "year", "hour", "minute", "second", "duration", "period",
  "window", "ttl", "status", "credit", "debit", "fund", "funds", "escrow",
  "vault", "pool", "reserve", "collateral", "asset", "coin", "currency",
  "denom", "unit", "decimals", "precision", "network", "blockchain",
  "layer", "mainnet", "testnet", "identity", "profile", "order",
  "invoice", "bill", "receipt", "request", "claim", "ticket", "coupon",
  "voucher", "rate", "ratio", "percent", "percentage", "factor",
  "multiplier", "price", "worth", "criteria", "criterion", "requirement",
  "constraint", "clause", "term", "terms", "spec", "directive", "mandate",
  "available", "remaining", "requested", "expires", "until", "after",
  "before", "since", "start", "end", "created", "issued", "updated",
  "greater", "less", "equal", "equals", "above", "below", "exceeds",
  "within", "between", "isEqual", "isZero", "greaterThan", "lessThan",
  "recipient", "amount", "balance", "threshold", "minimum", "maximum",
  "payer", "payee", "sender", "receiver", "action", "token", "expiry",
  "nonce", "fee", "timestamp", "signature", "salt", "decision", "taskId",
  "vkHash", "proof", "public", "condition", "registered", "expected",
  "actual", "payment", "statement", "task", "gatekeeper", "evaluation",
  "spending", "daily", "whitelist", "blacklist", "allowlist", "denylist",
  "registry", "circulating", "outstanding", "pending", "cleared",
  "settled", "authorized", "authenticated", "verified", "confirmed",
  "finalized", "included", "submitted", "accepted", "rejected",
  "approved", "denied", "revoked", "expired", "active", "inactive",
  "suspended", "terminated", "completed", "failed", "succeeded",
  "passed", "valid", "invalid", "legit", "genuine", "trusted", "secure",
  "amounts", "recipients", "decisions", "tasks", "salts", "balances",
  "thresholds", "payments", "proofs", "actions", "tokens", "fees",
  "nonces", "signatures", "timestamps", "expiries", "policies",
  "conditions", "rules", "statements", "values", "limits", "minimums",
  "maximums", "payers", "payees", "senders", "receivers", "users",
  "accounts", "wallets", "addresses", "identities", "orders", "claims",
  "tickets", "vouchers", "rates", "prices", "costs", "assets", "coins",
  "currencies", "networks", "chains", "contracts", "programs", "events",
  "matches", "rounds", "turns", "games", "agents", "players", "members",
  "states", "levels", "tiers", "scores", "ranks", "sources", "keys",
  "groups", "sets", "lists", "arrays", "maps", "tables", "systems",
  "platforms", "services", "apps", "dapps", "times", "dates", "days",
  "months", "years", "hours", "minutes", "seconds", "durations",
  "periods", "windows", "statuses", "credits", "debits", "funds",
  "vaults", "pools", "reserves", "secrets", "seeds", "hashes", "roots",
  "leaves", "paths", "indexes", "counters", "sequences", "ids", "uuids",
  "refs", "references", "memos", "notes", "reasons", "domains", "modes",
  "kinds", "types", "ops", "operations", "flags", "versions", "protocols",
  "curves", "domains", "separators", "challenges", "responses",
  "randoms", "entropies", "owners", "admins", "controllers", "guards",
  "verifiers", "validators", "checkers", "approvers", "authorizers",
  "issuers", "authorities", "merchants", "customers", "sellers",
  "buyers", "holders", "spenders", "beneficiaries", "destinations",
  "origins", "targets", "labels", "names", "titles", "comments",
  "descriptions", "specs", "terms", "clauses", "constraints",
  "requirements", "criteria", "evaluations", "outcomes", "verdicts",
  "results", "checks", "decisions",
];
const cap = (w) => w.charAt(0).toUpperCase() + w.slice(1);

const candidates = new Set();
for (const w of NEW) candidates.add(w);
for (const w of NEW) for (let n = 0; n <= 12; n++) candidates.add(w + n);
// pairs within NEW
for (const a of NEW) for (const b of NEW) candidates.add(a + cap(b));
// pairs NEW x old-found-words
const OLD = ["amount", "recipient", "taskId", "salt", "decision", "threshold", "minimum", "maximum", "balance", "vkHash", "proof", "public", "condition", "registered", "expected", "actual", "payment", "statement", "task", "payer", "payee", "sender", "receiver", "action", "token", "expiry", "nonce", "fee", "timestamp", "signature", "hash", "id", "value", "limit", "type", "status", "state", "key", "data", "memo", "reason", "domain", "chain", "version", "fee", "count", "index"];
for (const a of NEW) for (const b of OLD) { candidates.add(a + cap(b)); candidates.add(b + cap(a)); }
// 3-part structured combos
const PRE = ["registered", "proof", "public", "condition", "expected", "actual", "requested", "payment", "statement", "task", "gatekeeper", "evaluation"];
const MID = ["Vk", "Amount", "Recipient", "Minimum", "Maximum", "Threshold", "Balance", "Payer", "Payee", "Sender", "Receiver", "Action", "Token", "Expiry", "Nonce", "Salt", "Task", "Decision", "Hash", "Id", "Fee", "Timestamp", "Signature", "Type", "Value", "Limit", "Chain", "Data", "Memo", "Reason", "Status", "State", "Count", "Index", "Key", "Available", "Remaining", "Current", "Total", "Required", "Authorized"];
const SUF = ["Hash", "Value", "Id", "Code", "Type", "Amount", "Address", "Time", "At", "Limit", "Balance", "Count"];
for (const p of PRE) for (const m of MID) for (const s of SUF) candidates.add(p + m + s);
// dotted forms
for (const a of ["threshold", "payment", "statement", "input", "policy", "task", "proof", "gatekeeper", "condition", "public", "registered"]) {
  for (const b of NEW) candidates.add(a + "." + b);
}

console.log("candidates:", candidates.size);
const found = [];
for (const c of candidates) {
  const h = fnvHash(c);
  if (TARGETS.has(h)) {
    console.log(`>>> MATCH: "${c}" -> offset ${TARGETS.get(h)} (hash ${h})`);
    found.push([c, TARGETS.get(h)]);
  }
}
console.log(`found ${found.length}:`, JSON.stringify(found));
console.log("remaining:", [...TARGETS.entries()].filter(([, o]) => !found.some(([, fo]) => fo === o)).map(([h, o]) => `off=${o} hash=${h}`).join(" | ") || "none");
console.log("done brute force 2");
