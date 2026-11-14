// Brute-force round 3 for the last 2 unknown inputs
// (offset 7: bab23a24475d685f, offset 11: 12eb7fd2c76a4dda).
// Focus: block/expiry vocabulary (expiryBlock was found at offset 6),
// 3-part combos with TaskId/VkHash/ExpiryBlock/Block middles, and
// leftover singles (blinding, tip, tax, ...).
import { fnvHash } from "./fnv.mjs";

const TARGETS = new Map([
  ["bab23a24475d685f", 7],
  ["12eb7fd2c76a4dda", 11],
]);

const NEW = [
  "blinding", "blind", "tip", "tax", "discount", "block", "blockNumber",
  "blockHeight", "currentBlock", "startBlock", "endBlock", "createdBlock",
  "minBlock", "maxBlock", "validBlock", "deadlineBlock", "issueBlock",
  "activationBlock", "effectiveBlock", "settlementBlock", "paymentBlock",
  "taskBlock", "decisionBlock", "expiryTime", "expiryTimestamp",
  "expiresAt", "validUntil", "validFrom", "notBefore", "notAfter",
  "startTime", "endTime", "createdAt", "issuedAt", "updatedAt",
  "blocktime", "blockTime", "latestBlock", "targetBlock", "nextBlock",
  "prevBlock", "previousBlock", "lastBlock", "firstBlock", "genesisBlock",
  "expiryBlockHash", "expiryBlockNumber", "expiryBlockHeight",
  "expiryBlockTime", "expiryBlockId", "expiryBlockValue", "expiryBlockAt",
  "expiryBlockLimit", "blockHash", "blockId", "blockTime", "blockValue",
  "blockLimit", "blockAt", "blockCode", "blockType", "blockAmount",
  "blockRecipient", "blockDecision", "blockSalt", "blockNonce",
  "blockTimestamp", "blockExpiry", "blockThreshold", "blockMinimum",
  "blockMaximum", "blockBalance", "blockFee", "blockToken", "blockAction",
  "blockPayer", "blockChain", "blockChainId", "blockVkHash", "blockTaskId",
  "taskExpiryBlock", "conditionExpiryBlock", "publicExpiryBlock",
  "proofExpiryBlock", "expectedExpiryBlock", "registeredExpiryBlock",
  "decisionExpiryBlock", "amountExpiryBlock", "recipientExpiryBlock",
  "minimumExpiryBlock", "balanceExpiryBlock", "feeExpiryBlock",
  "tokenExpiryBlock", "actionExpiryBlock", "saltExpiryBlock",
  "nonceExpiryBlock", "hashExpiryBlock", "idExpiryBlock", "valueExpiryBlock",
  "limitExpiryBlock", "typeExpiryBlock", "statusExpiryBlock",
  "chainExpiryBlock", "dataExpiryBlock", "memoExpiryBlock",
  "reasonExpiryBlock", "keyExpiryBlock", "countExpiryBlock",
  "indexExpiryBlock", "signatureExpiryBlock", "timestampExpiryBlock",
  "currentBlockNumber", "currentBlockHeight", "currentBlockHash",
  "currentBlockTime", "currentBlockId", "currentBlockValue",
  "latestBlockNumber", "latestBlockHeight", "latestBlockHash",
  "latestBlockTime", "latestBlockId",
  "minBlockNumber", "maxBlockNumber", "minBlockHeight", "maxBlockHeight",
  "startBlockNumber", "endBlockNumber", "createdBlockNumber",
  "validBlockNumber", "deadlineBlockNumber", "issueBlockNumber",
  "activationBlockNumber", "effectiveBlockNumber", "settlementBlockNumber",
  "paymentBlockNumber", "taskBlockNumber", "decisionBlockNumber",
  "saltBlockNumber", "nonceBlockNumber", "feeBlockNumber",
  "tokenBlockNumber", "actionBlockNumber", "balanceBlockNumber",
  "amountBlockNumber", "recipientBlockNumber", "thresholdBlockNumber",
  "minimumBlockNumber", "maximumBlockNumber", "vkBlockNumber",
  "hashBlockNumber", "idBlockNumber", "valueBlockNumber",
  "limitBlockNumber", "typeBlockNumber", "statusBlockNumber",
  "chainBlockNumber", "dataBlockNumber", "keyBlockNumber",
  "countBlockNumber", "indexBlockNumber", "signatureBlockNumber",
  "timestampBlockNumber", "expiryBlockNumber",
];
const cap = (w) => w.charAt(0).toUpperCase() + w.slice(1);

const candidates = new Set();
for (const w of NEW) candidates.add(w);
for (const w of NEW) for (let n = 0; n <= 12; n++) candidates.add(w + n);
// 3-part combos with TaskId / VkHash / ExpiryBlock / Block middles
const PRE = ["registered", "proof", "public", "condition", "expected", "actual", "requested", "payment", "statement", "task", "gatekeeper", "evaluation", "expiry", "block", "current", "latest", "minimum", "maximum", "decision", "amount", "recipient", "balance", "fee", "token", "action", "salt", "nonce"];
const MID = ["TaskId", "VkHash", "ExpiryBlock", "Block", "BlockNumber", "BlockHeight", "BlockHash", "BlockTime", "BlockId", "Expiry", "Timestamp", "Time", "Number", "Height", "Hash", "Value", "Amount", "Minimum", "Maximum", "Threshold", "Balance", "Recipient", "Decision", "Salt", "Nonce", "Fee", "Token", "Action", "Payer", "Limit", "Type", "Status", "State", "Count", "Index", "Key", "Chain", "Data"];
const SUF = ["Hash", "Value", "Id", "Code", "Type", "Amount", "Address", "Time", "At", "Limit", "Balance", "Count", "Number", "Height", "Block"];
for (const p of PRE) for (const m of MID) for (const s of SUF) candidates.add(p + m + s);
// pairs NEW x common
const COMMON = ["amount", "recipient", "taskId", "salt", "decision", "threshold", "minimum", "maximum", "balance", "vkHash", "proof", "public", "condition", "registered", "expected", "actual", "payment", "statement", "task", "payer", "action", "token", "expiry", "nonce", "fee", "timestamp", "signature", "hash", "id", "value", "limit", "type", "block", "expiryBlock", "currentBlock"];
for (const a of NEW) for (const b of COMMON) { candidates.add(a + cap(b)); candidates.add(b + cap(a)); }

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
console.log("done brute force 3");
