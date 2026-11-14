// Probe the wasm shared RW memory directly: write distinct markers to each
// of the 8 limb positions and read them back, to find which positions are
// corrupted and how. Then write a single known limb to each position alone.
import fs from "node:fs";
import { WitnessCalculatorBuilder } from "circom_runtime";

const wasm = fs.readFileSync("./circuits/gatekeeper.wasm");
const wc = await WitnessCalculatorBuilder(wasm);
const ex = wc.instance.exports;
const n32 = wc.n32;
console.log("n32 =", n32);

// Test 1: markers 1000+j at each position.
for (let j = 0; j < n32; j++) ex.writeSharedRWMemory(j, 1000 + j);
const read1 = [];
for (let j = 0; j < n32; j++) read1.push(ex.readSharedRWMemory(j));
console.log("markers written [1000..1007], read back:", JSON.stringify(read1));

// Test 2: write 0x12345678 to each position alone (others 0), read all.
for (let target = 0; target < n32; target++) {
  for (let j = 0; j < n32; j++) ex.writeSharedRWMemory(j, 0);
  ex.writeSharedRWMemory(target, 0x12345678);
  const vals = [];
  for (let j = 0; j < n32; j++) vals.push(ex.readSharedRWMemory(j));
  console.log(`target pos ${target}: read =`, JSON.stringify(vals.map(v => "0x" + v.toString(16))));
}

// Test 3: write 0xFFFFFFFF to each position alone.
for (let target = 0; target < n32; target++) {
  for (let j = 0; j < n32; j++) ex.writeSharedRWMemory(j, 0);
  ex.writeSharedRWMemory(target, 0xFFFFFFFF);
  const vals = [];
  for (let j = 0; j < n32; j++) vals.push(ex.readSharedRWMemory(j));
  console.log(`0xFFFFFFFF @ pos ${target}: read =`, JSON.stringify(vals.map(v => "0x" + (v >>> 0).toString(16))));
}
console.log("done mem probe");
