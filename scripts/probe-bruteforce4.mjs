// Brute-force round 4 for the LAST unknown input
// (offset 11: 12eb7fd2c76a4dda).
// Covers: single letters + terse numbered names, new money/action words,
// 3-part combos with Current/Latest/Minimum/Maximum/Available middles,
// snake_case 3-part structured names.
import { fnvHash } from "./fnv.mjs";

const TARGET = "12eb7fd2c76a4dda";

const candidates = new Set();
const cap = (w) => w.charAt(0).toUpperCase() + w.slice(1);

// single letters + 2-letter combos
for (let i = 97; i <= 122; i++) candidates.add(String.fromCharCode(i));
for (let i = 97; i <= 122; i++) for (let j = 97; j <= 122; j++) {
  candidates.add(String.fromCharCode(i) + String.fromCharCode(j));
}
// terse numbered names
for (const p of ["in", "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z", "v0", "s0", "pub", "sig", "in0", "in1"]) {
  for (let n = 0; n <= 20; n++) candidates.add(p + n);
}
// new singles
const NEW = [
  "net", "gross", "principal", "interest", "penalty", "reward", "bonus",
  "refund", "cashback", "rebate", "deduction", "withholding", "commission",
  "charge", "toll", "levy", "surcharge", "handling", "judgement",
  "judgment", "ruling", "finding", "determination", "resolution",
  "conclusion", "assessment", "appraisal", "review", "audit", "transaction",
  "api", "transactionFee", "transactionHash", "transactionId", "txFee",
  "txAmount", "txRecipient", "txType", "txValue", "txData", "txNonce",
  "txTimestamp", "txBlock", "txIndex", "txStatus", "txSender", "txReceiver",
  "txPayer", "txToken", "txChainId", "netAmount", "grossAmount", "netValue",
  "grossValue", "principalAmount", "interestAmount", "penaltyAmount",
  "rewardAmount", "bonusAmount", "refundAmount", "cashbackAmount",
  "rebateAmount", "deductionAmount", "commissionAmount", "chargeAmount",
  "judgementAmount", "judgmentAmount", "rulingAmount", "transactionAmount",
  "apiKey", "apiHash", "apiId", "apiAmount", "apiValue",
  "publicCurrentBlock", "conditionCurrentBlock", "registeredCurrentBlock",
  "proofCurrentBlock", "expectedCurrentBlock", "publicLatestBlock",
  "conditionLatestBlock", "publicMinimumAmount", "conditionMinimumAmount",
  "publicMaximumAmount", "conditionMaximumAmount", "publicMinimumBalance",
  "conditionMinimumBalance", "publicAvailableBalance",
  "conditionAvailableBalance", "publicRemainingBalance",
  "conditionRemainingBalance", "publicTotalBalance",
  "conditionTotalBalance", "publicCurrentBalance",
  "conditionCurrentBalance", "publicRequiredBalance",
  "conditionRequiredBalance", "publicNetAmount", "conditionNetAmount",
  "publicGrossAmount", "conditionGrossAmount", "publicPrincipalAmount",
  "conditionPrincipalAmount", "publicInterestAmount",
  "conditionInterestAmount", "publicRewardAmount", "conditionRewardAmount",
  "publicRefundAmount", "conditionRefundAmount", "publicTransactionFee",
  "conditionTransactionFee", "publicTransactionAmount",
  "conditionTransactionAmount", "publicApiKey", "conditionApiKey",
  "publicJudgement", "conditionJudgement", "publicAssessment",
  "conditionAssessment", "publicTransactionId", "conditionTransactionId",
  "publicTransactionHash", "conditionTransactionHash",
];
for (const w of NEW) candidates.add(w);
// 3-part combos: PRE x MID2 x SUF
const PRE = ["registered", "proof", "public", "condition", "expected", "actual", "requested", "payment", "statement", "task", "gatekeeper", "evaluation", "expiry", "block", "current", "latest", "minimum", "maximum", "decision", "amount", "recipient", "balance", "fee", "token", "action", "salt", "nonce", "transaction", "net", "gross"];
const MID2 = ["Current", "Latest", "Minimum", "Maximum", "Available", "Remaining", "Total", "Required", "TaskId", "VkHash", "ExpiryBlock", "Block", "Net", "Gross", "Principal", "Interest", "Reward", "Refund", "Transaction", "Api", "Judgement", "Assessment", "CurrentBlock", "LatestBlock"];
const SUF = ["Hash", "Value", "Id", "Code", "Type", "Amount", "Address", "Time", "At", "Limit", "Balance", "Count", "Number", "Height", "Block", "Fee", "Key"];
for (const p of PRE) for (const m of MID2) for (const s of SUF) candidates.add(p + m + s);
// snake_case 3-part structured
for (const p of ["registered", "proof", "public", "condition", "expected", "actual", "requested", "payment", "statement", "task"]) {
  for (const m of ["vk", "amount", "recipient", "minimum", "maximum", "threshold", "balance", "payer", "action", "token", "expiry", "nonce", "salt", "decision", "fee", "block", "current", "transaction", "net", "gross"]) {
    for (const s of ["hash", "value", "id", "code", "type", "amount", "address", "time", "limit", "balance", "count", "number", "height", "block", "fee", "key"]) {
      candidates.add(`${p}_${m}_${s}`);
    }
  }
}
// snake_case 2-part with new words
for (const a of ["public", "condition", "registered", "proof", "expected", "actual", "task", "payment", "statement", "expiry", "current", "latest", "minimum", "maximum", "net", "gross", "transaction"]) {
  for (const b of ["amount", "recipient", "balance", "block", "current_block", "expiry_block", "fee", "token", "action", "nonce", "salt", "decision", "hash", "id", "value", "limit", "type", "status", "state", "key", "data", "net", "gross", "transaction", "api"]) {
    candidates.add(`${a}_${b}`);
  }
}

console.log("candidates:", candidates.size);
const found = [];
for (const c of candidates) {
  if (fnvHash(c) === TARGET) {
    console.log(`>>> MATCH: "${c}" -> offset 11`);
    found.push(c);
  }
}
console.log(`found ${found.length}:`, JSON.stringify(found));
console.log("done brute force 4");
