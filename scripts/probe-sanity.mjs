// Sanity check for the size oracle: print raw getInputSignalSize values
// for known-good names, a threshold, and obviously-bogus names — on BOTH
// the gatekeeper wasm and the vfy-policy wasm (where the oracle is proven
// to return -1 for unknown names).
import fs from "node:fs";
import { WitnessCalculatorBuilder } from "circom_runtime";
import { fnvHash } from "./fnv.mjs";

async function probe(wasmPath, names) {
  const wasm = fs.readFileSync(wasmPath);
  const wc = await WitnessCalculatorBuilder(wasm);
  console.log(`--- ${wasmPath} (circom v${wc.circom_version()}, inputSize=${wc.instance.exports.getInputSize()})`);
  for (const name of names) {
    const h = fnvHash(name);
    const hMSB = parseInt(h.slice(0, 8), 16);
    const hLSB = parseInt(h.slice(8, 16), 16);
    const s = wc.instance.exports.getInputSignalSize(hMSB, hLSB);
    console.log(`  ${name}: size=${s}`);
  }
}

const NAMES = ["amount", "decision", "threshold", "zzzqqq_nonexistent", "asdfghjkl", "selfBalance", "strategyParams"];
await probe("./circuits/gatekeeper.wasm", NAMES);
await probe("../ryz-steal-vfy/circuits/vfy-policy.wasm", NAMES);
console.log("done sanity");
