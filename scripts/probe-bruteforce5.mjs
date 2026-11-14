// Brute-force round 5 for the LAST unknown input (offset 11: 12eb7fd2c76a4dda).
// Semantics now known: it is an UPPER BOUND on amount (amount <= off11).
// Focused vocabulary: max/limit/cap/ceiling/threshold/quota/allowance/budget
// and amount-like synonyms not covered in rounds 1-4.
import { fnvHash } from "./fnv.mjs";

const TARGET = "12eb7fd2c76a4dda";
const candidates = new Set();
const cap = (w) => w.charAt(0).toUpperCase() + w.slice(1);

// --- 2-word combos: PRE x SUF ---
const PRE = [
  "spend", "spending", "transfer", "payment", "payout", "claim", "send",
  "withdraw", "deposit", "purchase", "trade", "swap", "buy", "sell",
  "amount", "value", "total", "balance", "fee", "token", "daily", "perTx",
  "perTransaction", "tx", "transaction", "public", "condition", "registered",
  "proof", "expected", "actual", "requested", "task", "statement",
  "gatekeeper", "evaluation", "user", "agent", "payer", "recipient",
  "sender", "payee", "owner", "contract", "vault", "pool", "fund",
  "escrow", "collateral", "reserve", "account", "wallet", "policy", "rule",
  "due", "owed", "payable", "receivable", "disbursement", "settlement",
  "remittance", "allocation", "distribution", "grant", "award", "prize",
  "bounty", "needed", "necessary", "essential", "stated", "declared",
  "specified", "agreed", "net", "gross", "principal", "interest", "reward",
  "refund", "bonus", "penalty", "commission", "charge", "upper", "lower",
  "max", "maximum", "min", "minimum", "available", "remaining", "spendable",
  "usable", "current", "initial", "final", "starting", "ending", "opening",
  "closing", "new", "old", "previous", "after", "before", "required",
  "authorized", "authorised", "approved", "allowed", "permitted",
];
const SUF = [
  "Cap", "Ceiling", "Maximum", "Threshold", "Quota", "Allowance", "Budget",
  "Limit", "Bound", "Roof", "Top", "Peak", "Highest", "Largest", "Maximal",
  "Max", "UpperBound", "LowerBound", "UpperLimit", "LowerLimit", "Amount",
  "Value", "Total", "Balance", "Fee", "Token", "Sum", "Quantity", "Units",
  "Count", "Number", "Size", "Magnitude", "Worth", "Price", "Cost", "Rate",
  "Due", "Owed", "Payable", "Receivable", "Disbursement", "Settlement",
  "Remittance", "Allocation", "Distribution", "Grant", "Award", "Prize",
  "Bounty", "Needed", "Necessary", "Essential", "Stated", "Declared",
  "Specified", "Agreed", "Net", "Gross", "Principal", "Interest", "Reward",
  "Refund", "Bonus", "Penalty", "Commission", "Charge", "Funds", "Available",
  "Remaining", "Spendable", "Usable", "Current", "Initial", "Final",
  "Starting", "Ending", "Opening", "Closing", "New", "Old", "Previous",
  "After", "Before", "Required", "Authorized", "Authorised", "Approved",
  "Allowed", "Permitted", "Allowable", "Permissible", "Admissible",
];
for (const p of PRE) for (const s of SUF) candidates.add(p + s);

// --- singles ---
for (const w of [
  "roof", "top", "peak", "highest", "largest", "biggest", "maximal",
  "supremum", "allowable", "permitted", "authorised", "authorized",
  "permissible", "admissible", "tolerated", "acceptable", "uppermost",
  "utmost", "due", "owed", "payable", "receivable", "disbursement",
  "settlement", "remittance", "allocation", "distribution", "grant",
  "award", "prize", "bounty", "needed", "necessary", "essential", "stated",
  "declared", "specified", "agreed", "funds", "fundsAvailable",
  "amountAvailable", "totalAvailable", "valueAvailable", "remainingFunds",
  "upperBound", "lowerBound", "upperLimit", "lowerLimit", "maxAmount",
  "maxValue", "maxTotal", "maxBalance", "maxFee", "maxLimit", "maxCap",
  "maxCeiling", "maxThreshold", "maxQuota", "maxAllowance", "maxBudget",
  "maxBound", "maxSpend", "maxTransfer", "maxPayment", "maxPayout",
  "maxClaim", "maxSend", "maxWithdraw", "maxDeposit", "maxPurchase",
  "maxTrade", "maxSwap", "maxBuy", "maxSell", "maxAllowed", "maxPermitted",
  "maxAuthorised", "maxAuthorized", "maxRoof", "maxTop", "maxPeak",
  "maxHighest", "maxLargest", "maxMaximal", "maxAvailable", "maxRemaining",
  "maxSpendable", "maxUsable", "maxCurrent", "maxRequired", "maxDue",
  "maxOwed", "maxPayable", "maxReceivable", "maxDisbursement",
  "maxSettlement", "maxRemittance", "maxAllocation", "maxDistribution",
  "maxGrant", "maxAward", "maxPrize", "maxBounty", "maxNeeded",
  "maxNecessary", "maxEssential", "maxStated", "maxDeclared",
  "maxSpecified", "maxAgreed", "maxNet", "maxGross", "maxPrincipal",
  "maxInterest", "maxReward", "maxRefund", "maxBonus", "maxPenalty",
  "maxCommission", "maxCharge", "maxFunds", "spendCap", "spendCeiling",
  "spendMaximum", "spendThreshold", "spendQuota", "spendAllowance",
  "spendBudget", "spendLimit", "spendBound", "spendRoof", "spendTop",
  "spendPeak", "spendHighest", "spendLargest", "spendingCap",
  "spendingCeiling", "spendingMaximum", "spendingThreshold",
  "spendingQuota", "spendingAllowance", "spendingBudget", "spendingBound",
  "spendingRoof", "spendingTop", "spendingPeak", "spendingHighest",
  "spendingLargest",
]) candidates.add(w);

// --- 3-part combos: PRE3 x MID3 x SUF3 ---
const PRE3 = ["upper", "lower", "max", "maximum", "amount", "value", "total", "balance", "fee", "token", "public", "condition", "registered", "proof", "expected", "actual", "requested", "task", "statement", "gatekeeper", "evaluation", "spend", "spending", "transfer", "payment", "payout", "claim", "send", "withdraw", "available", "remaining", "required", "authorized", "approved", "daily", "perTx", "perTransaction", "tx", "transaction", "limit", "cap", "ceiling", "threshold", "quota", "allowance", "budget", "bound"];
const MID3 = ["UpperBound", "LowerBound", "Bound", "Limit", "Cap", "Ceiling", "Threshold", "Quota", "Allowance", "Budget", "Highest", "Largest", "Top", "Peak", "Maximal", "Spend", "Transfer", "Payment", "Payout", "Claim", "Send", "Withdraw", "Roof", "Available", "Remaining", "Required", "Amount", "Value", "Total", "Balance", "Fee", "Maximum", "Minimum"];
const SUF3 = ["Amount", "Value", "Total", "Balance", "Fee", "Token", "Limit", "Cap", "Ceiling", "Threshold", "Quota", "Allowance", "Budget", "Bound", "Hash", "Id", "Code", "Type", "Count", "Number", "Sum", "Quantity"];
for (const p of PRE3) for (const m of MID3) for (const s of SUF3) candidates.add(p + m + s);

// --- snake_case 2-part for the new max/limit words ---
for (const a of ["max", "maximum", "upper", "lower", "spend", "spending", "transfer", "payment", "payout", "claim", "send", "withdraw", "available", "remaining", "due", "owed", "payable", "receivable", "amount", "value", "total", "balance", "fee", "token", "public", "condition", "registered", "proof", "expected", "actual", "requested", "task", "statement", "daily", "per_tx", "tx", "transaction"]) {
  for (const b of ["amount", "value", "total", "balance", "fee", "token", "limit", "cap", "ceiling", "threshold", "quota", "allowance", "budget", "bound", "roof", "top", "peak", "highest", "largest", "max", "maximum", "available", "remaining", "due", "owed", "payable", "receivable", "sum", "quantity"]) {
    candidates.add(`${a}_${b}`);
    candidates.add(`${a}_max_${b}`);
    candidates.add(`${a}_upper_${b}`);
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
console.log("done brute force 5");
