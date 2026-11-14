// Round-trip test: write a big value to shared RW memory and read it back
// WITHOUT calling setInputSignal. If this round-trips exactly, my I/O is
// correct and the small deltas seen in witness values come from the wasm's
// signal handling (setInputSignal / circuit), not from my code.
import fs from "node:fs";
import { WitnessCalculatorBuilder } from "circom_runtime";

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

for (const label of ["recipient", "vkhash"]) {
  const val = label === "recipient"
    ? BigInt("0x1234567890abcdef1234567890abcdef12345678")
    : BigInt("0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0");
  const arrFr = toArray32(normalize(val), n32);
  for (let j = 0; j < n32; j++) ex.writeSharedRWMemory(j, arrFr[n32 - 1 - j]);
  let back = 0n;
  for (let j = 0; j < n32; j++) back += BigInt(ex.readSharedRWMemory(j)) * (BigInt(0x100000000) ** BigInt(j));
  console.log(`${label}: write/read round-trip exact? ${back === normalize(val)} (diff 0x${(normalize(val) - back).toString(16)})`);
}
console.log("done round-trip");
