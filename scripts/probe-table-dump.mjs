// Dump segment 18 (the input-signal hash table) as 16-byte records:
// (hashLSB u32, hashMSB u32, offset u32, size u32).
// Records with size > 0 are input signals. Print them all, and mark the
// 5 already-known ones.
import fs from "node:fs";
import { fnvHash } from "./fnv.mjs";

const buf = fs.readFileSync("./circuits/gatekeeper.wasm");
const SEG_OFF = 715697;
const SEG_SIZE = 4096;
const seg = buf.subarray(SEG_OFF, SEG_OFF + SEG_SIZE);

const knownHashes = new Set(
  ["amount", "recipient", "taskId", "salt", "decision"].map((n) => fnvHash(n)),
);

console.log("records in segment 18 (16-byte stride):");
let nonzero = 0;
for (let r = 0; r < SEG_SIZE / 16; r++) {
  const base = r * 16;
  const lsb = seg.readUInt32LE(base);
  const msb = seg.readUInt32LE(base + 4);
  const off = seg.readUInt32LE(base + 8);
  const size = seg.readUInt32LE(base + 12);
  if (lsb === 0 && msb === 0 && off === 0 && size === 0) continue;
  nonzero++;
  const hashHex = msb.toString(16).padStart(8, "0") + lsb.toString(16).padStart(8, "0");
  const known = knownHashes.has(hashHex) ? "  <<< KNOWN" : "";
  console.log(`rec ${r}: hash=${hashHex} offset=${off} size=${size}${known}`);
}
console.log("nonzero records:", nonzero);
console.log("done table dump");
