// Build a gatekeeper witness WITHOUT knowing all input names:
// inputs are set by FNV-64 hash directly through the wasm exports
// (setInputSignal takes hMSB/hLSB). The 12 known inputs use fnvHash(name);
// offset 11 (name unknown) uses its raw hash from the wasm data section.
// Then writes a snarkjs-format .wtns file and prints the witness so the
// public-signal layout can be mapped by value.
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
  while (rem) {
    res.unshift(Number(rem % radix));
    rem = rem / radix;
  }
  if (size) {
    let i = size - res.length;
    while (i > 0) { res.unshift(0); i--; }
  }
  return res;
}

const wasm = fs.readFileSync("./circuits/gatekeeper.wasm");
const wc = await WitnessCalculatorBuilder(wasm);
const ex = wc.instance.exports;
const n32 = wc.n32;
console.log("circom v" + wc.circom_version(), "inputSize=" + ex.getInputSize(), "witnessSize=" + ex.getWitnessSize(), "n32=" + n32);

// --- inputs: [hashHex, value] ---
const VK_HASH = "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";
const RECIPIENT = "0x1234567890abcdef1234567890abcdef12345678";
const inputs = [
  ["registeredVkHash", VK_HASH],
  ["proofVkHash", VK_HASH],
  ["minimum", "250"],
  ["publicBalance", "1000"],
  ["expiryBlock", "1000000"],
  ["currentBlock", "999000"],
  ["recipient", RECIPIENT],
  ["conditionRecipient", RECIPIENT],
  ["amount", "250"],
  // offset 11 — name unknown, hash from wasm data section:
  ["12eb7fd2c76a4dda", process.env.OFF11 ?? "0"],
  ["decision", process.env.DECISION ?? "1"],
  ["taskId", "12345"],
  ["salt", "999999"],
];
// Resolve names to hashes.
const pairs = inputs.map(([k, v]) => {
  const h = /^[0-9a-f]{16}$/.test(k) ? k : fnvHash(k);
  return [h, BigInt(v)];
});

ex.init(0);
let counter = 0;
for (const [h, val] of pairs) {
  const hMSB = parseInt(h.slice(0, 8), 16);
  const hLSB = parseInt(h.slice(8, 16), 16);
  const arrFr = toArray32(normalize(val), n32);
  for (let j = 0; j < n32; j++) ex.writeSharedRWMemory(j, arrFr[n32 - 1 - j]);
  try {
    ex.setInputSignal(hMSB, hLSB, 0);
    counter++;
  } catch (e) {
    console.log(`setInputSignal FAILED for hash ${h}:`, e.message);
    process.exit(1);
  }
}
console.log(`inputs set: ${counter} / ${ex.getInputSize()}`);

// Read the full witness.
const witnessSize = ex.getWitnessSize();
const witness = [];
for (let i = 0; i < witnessSize; i++) {
  ex.getWitness(i);
  let v = 0n;
  for (let j = 0; j < n32; j++) {
    v += BigInt(ex.readSharedRWMemory(j) >>> 0) * (BigInt(0x100000000) ** BigInt(j));
  }
  witness.push(v);
}
console.log("witness[0] (constant):", witness[0].toString());
console.log("--- public-signal range witness[1..13] ---");
for (let i = 1; i <= 13; i++) {
  console.log(`witness[${i}] = ${witness[i].toString()} (0x${witness[i].toString(16)})`);
}
console.log("--- first private witness entries ---");
for (let i = 14; i <= 20; i++) {
  console.log(`witness[${i}] = ${witness[i].toString()}`);
}

// Write .wtns (snarkjs v2 format), replicating circom_runtime calculateWTNSBin.
const buff32 = new Uint32Array(witnessSize * n32 + n32 + 11);
const buff = new Uint8Array(buff32.buffer);
buff[0] = "w".charCodeAt(0);
buff[1] = "t".charCodeAt(0);
buff[2] = "n".charCodeAt(0);
buff[3] = "s".charCodeAt(0);
buff32[1] = 2;
buff32[2] = 2;
buff32[3] = 1;
const n8 = n32 * 4;
const idSection1length = 8 + n8;
const idSection1lengthHex = idSection1length.toString(16);
buff32[4] = parseInt(idSection1lengthHex.slice(0, 8), 16);
buff32[5] = parseInt(idSection1lengthHex.slice(8, 16), 16);
buff32[6] = n8;
ex.getRawPrime();
let pos = 7;
for (let j = 0; j < n32; j++) buff32[pos + j] = ex.readSharedRWMemory(j);
pos += n32;
buff32[pos] = witnessSize;
pos++;
buff32[pos] = 2;
pos++;
const idSection2length = n8 * witnessSize;
const idSection2lengthHex = idSection2length.toString(16);
buff32[pos] = parseInt(idSection2lengthHex.slice(0, 8), 16);
buff32[pos + 1] = parseInt(idSection2lengthHex.slice(8, 16), 16);
pos += 2;
for (let i = 0; i < witnessSize; i++) {
  ex.getWitness(i);
  for (let j = 0; j < n32; j++) buff32[pos + j] = ex.readSharedRWMemory(j);
  pos += n32;
}
fs.writeFileSync("/tmp/gk-test2.wtns", Buffer.from(buff.buffer));
console.log("wrote /tmp/gk-test2.wtns");
console.log("done witness");
