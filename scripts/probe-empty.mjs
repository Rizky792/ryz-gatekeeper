// Empty-input probe: what does the wasm complain about first when no
// inputs are set? The error names the first missing signal, which reveals
// the circuit's input ordering hints.
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
const snarkjs = require("snarkjs");

const WASM = "./circuits/gatekeeper.wasm";

for (const input of [{}, { amount: "0" }, { recipient: "0" }, { threshold: "0" }]) {
  try {
    await snarkjs.wtns.calculate(input, WASM, "/tmp/gk-probe-empty.wtns");
    console.log(JSON.stringify(input), "-> ACCEPTED-ALL?");
  } catch (e) {
    const msg = (e && e.message ? e.message : String(e)).replace(/\n/g, " ").trim();
    console.log(JSON.stringify(input), "->", msg.slice(0, 300));
  }
}
console.log("done");
