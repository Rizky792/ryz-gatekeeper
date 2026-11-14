// Sweep the gatekeeper circuit: try many input combinations with
// decision=1 and report which ones produce a full witness (all checks pass)
// vs assert-fail at line 102 (some check fails). Each case prints PASS/FAIL.
// All values come from env vars so a bash loop can drive cases.
import fs from "node:fs";
import { WitnessCalculatorBuilder } from "circom_runtime";
import { fnvHash } from "./fnv.mjs";

const FIELD_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
function normalize(n) {
  let res = BigInt(n) % FIELD_PRIME;
  if (res < 0) res += FIELD_PRIME;
  return res;
}
function toArray32(s, size) {
  const res = [];
  let rem = BigInt(s);
  const radix = BigInt(0x100000000);
  while (rem) { res.unshift(Number(rem % radix)); rem = rem / radix; }
  if (size) { let i = size - res.length; while (i > 0) { res.unshift(0); i--; } }
  return res;
}

const wasm = fs.readFileSync("./circuits/gatekeeper.wasm");
const wc = await WitnessCalculatorBuilder(wasm);
const ex = wc.instance.exports;
const n32 = wc.n32;

const E = process.env;
const VK = E.VK ?? "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";
const inputs = [
  ["registeredVkHash", E.REGVK ?? VK],
  ["proofVkHash", E.PROOFVK ?? VK],
  ["minimum", E.MINIMUM ?? "250"],
  ["publicBalance", E.BALANCE ?? "1000"],
  ["expiryBlock", E.EXPIRY ?? "1000000"],
  ["currentBlock", E.CURRENT ?? "999000"],
  ["recipient", E.RECIPIENT ?? "0x1234567890abcdef1234567890abcdef12345678"],
  ["conditionRecipient", E.CONDRECIPIENT ?? "0x1234567890abcdef1234567890abcdef12345678"],
  ["amount", E.AMOUNT ?? "250"],
  ["12eb7fd2c76a4dda", E.OFF11 ?? "0"],
  ["decision", E.DECISION ?? "1"],
  ["taskId", E.TASKID ?? "12345"],
  ["salt", E.SALT ?? "999999"],
];
const pairs = inputs.map(([k, v]) => [(/^[0-9a-f]{16}$/.test(k) ? k : fnvHash(k)), BigInt(v)]);

const label = E.LABEL ?? "case";
try {
  ex.init(0);
  for (const [h, val] of pairs) {
    const hMSB = parseInt(h.slice(0, 8), 16);
    const hLSB = parseInt(h.slice(8, 16), 16);
    const arrFr = toArray32(normalize(val), n32);
    for (let j = 0; j < n32; j++) ex.writeSharedRWMemory(j, arrFr[n32 - 1 - j]);
    ex.setInputSignal(hMSB, hLSB, 0);
  }
  // Read witness[1] (publicSignals[0]) on success.
  ex.getWitness(1);
  let w1 = 0n;
  for (let j = 0; j < n32; j++) w1 += BigInt(ex.readSharedRWMemory(j) >>> 0) * (BigInt(0x100000000) ** BigInt(j));
  console.log(`${label}: PASS w1=${w1.toString()}`);
} catch (e) {
  const msg = (e && e.message ? e.message : String(e)).replace(/\n/g, " ").trim().slice(0, 120);
  console.log(`${label}: FAIL :: ${msg}`);
}
