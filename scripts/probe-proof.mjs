// End-to-end proof test: build an APPROVE witness (decision=1), generate a
// Groth16 proof with snarkjs, verify it, and measure timing.
// Uses the hash-keyed witness builder (maxTransfer set by FNV hash).
import fs from "node:fs";
import { WitnessCalculatorBuilder } from "circom_runtime";
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
const snarkjs = require("snarkjs");
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

const t0 = Date.now();
const wasm = fs.readFileSync("./circuits/gatekeeper.wasm");
const wc = await WitnessCalculatorBuilder(wasm);
const ex = wc.instance.exports;
const n32 = wc.n32;

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
  ["maxTransfer", "300"],
  ["decision", "1"],
  ["taskId", "12345"],
  ["salt", "999999"],
];
const pairs = inputs.map(([k, v]) => [fnvHash(k), BigInt(v)]);
ex.init(0);
for (const [h, val] of pairs) {
  const hMSB = parseInt(h.slice(0, 8), 16);
  const hLSB = parseInt(h.slice(8, 16), 16);
  const arrFr = toArray32(normalize(val), n32);
  for (let j = 0; j < n32; j++) ex.writeSharedRWMemory(j, arrFr[n32 - 1 - j]);
  ex.setInputSignal(hMSB, hLSB, 0);
}
const tWitness = Date.now();
console.log(`witness built in ${tWitness - t0} ms`);

// Write .wtns (snarkjs v2 format) — buff32 is Uint32Array so signed limbs
// are converted to unsigned automatically on assignment.
const witnessSize = ex.getWitnessSize();
const buff32 = new Uint32Array(witnessSize * n32 + n32 + 11);
const buff = new Uint8Array(buff32.buffer);
buff[0] = "w".charCodeAt(0); buff[1] = "t".charCodeAt(0);
buff[2] = "n".charCodeAt(0); buff[3] = "s".charCodeAt(0);
buff32[1] = 2; buff32[2] = 2; buff32[3] = 1;
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
buff32[pos] = witnessSize; pos++;
buff32[pos] = 2; pos++;
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
const wtnsPath = "/tmp/gk-approve.wtns";
fs.writeFileSync(wtnsPath, Buffer.from(buff.buffer));
console.log(`wrote ${wtnsPath} (${fs.statSync(wtnsPath).size} bytes)`);

// Generate the proof.
const tProve0 = Date.now();
const { proof, publicSignals } = await snarkjs.groth16.prove("./circuits/gatekeeper_final.zkey", wtnsPath);
const tProve = Date.now();
console.log(`groth16.prove took ${tProve - tProve0} ms`);
console.log("publicSignals:", JSON.stringify(publicSignals));

// Verify the proof.
const vkey = JSON.parse(fs.readFileSync("./circuits/gatekeeper.vkey.json", "utf8"));
const tVer0 = Date.now();
const ok = await snarkjs.groth16.verify(vkey, publicSignals, proof);
const tVer = Date.now();
console.log(`groth16.verify took ${tVer - tVer0} ms, valid = ${ok}`);
console.log(`total (witness+prove+verify): ${tVer - t0} ms`);
console.log("proof pi_a[0] (truncated):", proof.pi_a[0].slice(0, 20) + "...");
fs.writeFileSync("/tmp/gk-approve-proof.json", JSON.stringify({ proof, publicSignals }, null, 2));
console.log("saved /tmp/gk-approve-proof.json");
console.log("done proof test");
