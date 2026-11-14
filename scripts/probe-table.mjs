// Extract the input-signal table from the gatekeeper wasm.
// The wasm's getInputSignalSize maps FNV-64 hashes -> sizes. The table lives
// in the wasm data section as (hashMSB u32, hashLSB u32, size u32) triples
// (or similar). Find the entries for the 5 known inputs, then read the
// neighbouring entries to recover ALL 13 (hash, size) pairs.
import fs from "node:fs";
import { fnvHash } from "./fnv.mjs";

const buf = fs.readFileSync("./circuits/gatekeeper.wasm");
console.log("wasm size:", buf.length);

function hashParts(name) {
  const h = fnvHash(name);
  return {
    msb: parseInt(h.slice(0, 8), 16),
    lsb: parseInt(h.slice(8, 16), 16),
  };
}

// Search for a u32 pair (a,b) as little-endian bytes.
function findPair(a, b) {
  const needle = Buffer.alloc(8);
  needle.writeUInt32LE(a, 0);
  needle.writeUInt32LE(b, 4);
  const hits = [];
  let idx = buf.indexOf(needle);
  while (idx !== -1) {
    hits.push(idx);
    idx = buf.indexOf(needle, idx + 1);
  }
  return hits;
}

const KNOWN = ["amount", "recipient", "taskId", "salt", "decision"];
for (const name of KNOWN) {
  const { msb, lsb } = hashParts(name);
  const msbFirst = findPair(msb, lsb);
  const lsbFirst = findPair(lsb, msb);
  console.log(`${name}: fnv=${fnvHash(name)} msb=0x${msb.toString(16)} lsb=0x${lsb.toString(16)}`);
  console.log(`  [msb,lsb] hits at offsets: ${JSON.stringify(msbFirst)}`);
  console.log(`  [lsb,msb] hits at offsets: ${JSON.stringify(lsbFirst)}`);
  for (const off of [...msbFirst, ...lsbFirst]) {
    // Dump 64 bytes around the hit as u32 LE values.
    const start = Math.max(0, off - 16);
    const u32s = [];
    for (let i = start; i < Math.min(buf.length, off + 48); i += 4) {
      u32s.push(buf.readUInt32LE(i));
    }
    console.log(`  around ${off}: [${u32s.join(", ")}]`);
  }
}
console.log("done table hunt");
