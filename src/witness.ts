// Local witness + proof generation for the gatekeeper circuit.
// DEV/TEST ONLY: the agent never generates proofs in production (it only
// verifies the proofs the platform sends). This module exists so the test
// suite can mint valid APPROVE and REJECT proofs locally without a platform.
//
// The circuit's .circom source was never published, so the witness is built
// by setting each input through the wasm exports directly, keyed by the
// FNV-1a hash of the input name (the same hash circom_runtime uses). This is
// the method proven in ~/workspace/agent-games/build-report-gatekeeper.md.
//
// NOTE on readSharedRWMemory: the wasm export returns a SIGNED 32-bit int.
// A limb >= 2^31 comes back negative; convert with `>>> 0` before turning
// it into a BigInt, or large field elements read back wrong (the .wtns file
// itself is safe — it is written into a Uint32Array, which converts
// automatically).

import fs from "node:fs";
import path from "node:path";
import { WitnessCalculatorBuilder } from "circom_runtime";
import { fnvHash } from "./fnv.js";
import { FIELD_PRIME, toField } from "./circuit.js";
import type { Groth16Proof } from "./types.js";

// snarkjs has no `default` export (same fix as the Steal agent).
import snarkjs = require("snarkjs");

export interface CircuitInputs {
  registeredVkHash: string | bigint;
  proofVkHash: string | bigint;
  minimum: bigint | number | string;
  publicBalance: bigint | number | string;
  expiryBlock: bigint | number | string;
  currentBlock: bigint | number | string;
  recipient: string | bigint;
  conditionRecipient: string | bigint;
  amount: bigint | number | string;
  maxTransfer: bigint | number | string;
  decision: 0 | 1 | bigint;
  taskId: bigint | number | string;
  salt: bigint | number | string;
}

export const DEFAULT_TEST_INPUTS: CircuitInputs = {
  registeredVkHash:
    "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0",
  proofVkHash:
    "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0",
  minimum: 250,
  publicBalance: 1000,
  expiryBlock: 1000000,
  currentBlock: 999000,
  recipient: "0x1234567890abcdef1234567890abcdef12345678",
  conditionRecipient: "0x1234567890abcdef1234567890abcdef12345678",
  amount: 250,
  maxTransfer: 300,
  decision: 1,
  taskId: 12345,
  salt: 999999,
};

function normalize(n: bigint): bigint {
  let r = n % FIELD_PRIME;
  if (r < 0n) r += FIELD_PRIME;
  return r;
}

function toArray32(s: bigint, size: number): number[] {
  const res: number[] = [];
  let rem = BigInt(s);
  const radix = BigInt(0x100000000);
  while (rem) {
    res.unshift(Number(rem % radix));
    rem = rem / radix;
  }
  if (size) {
    let i = size - res.length;
    while (i > 0) {
      res.unshift(0);
      i--;
    }
  }
  return res;
}

function inputToBigint(v: string | bigint | number): bigint {
  if (typeof v === "bigint") return v;
  if (typeof v === "number") return BigInt(v);
  const s = v.trim();
  return BigInt(s); // accepts "0x..." and decimal strings
}

/** Input names in witness order (offsets 2..14). */
const INPUT_ORDER: (keyof CircuitInputs)[] = [
  "registeredVkHash",
  "proofVkHash",
  "minimum",
  "publicBalance",
  "expiryBlock",
  "currentBlock",
  "recipient",
  "conditionRecipient",
  "amount",
  "maxTransfer",
  "decision",
  "taskId",
  "salt",
];

export interface BuiltWitness {
  /** snarkjs-format .wtns bytes. */
  wtns: Buffer;
  /** Full witness (index 0 is the constant 1; 1..13 are the public signals). */
  witness: bigint[];
  /** Public signals as decimal strings (witness[1..13]). */
  publicSignals: string[];
}

/** Build a gatekeeper witness from circuit inputs. Throws when the circuit
 *  asserts (i.e. when `decision` disagrees with the evaluation of the
 *  inputs — e.g. decision=1 while a check fails). */
export async function buildWitness(inputs: CircuitInputs, wasmPath: string): Promise<BuiltWitness> {
  const wasm = fs.readFileSync(wasmPath);
  const wc = await WitnessCalculatorBuilder(wasm);
  const ex = wc.instance.exports;
  const n32: number = wc.n32;

  ex.init(0);
  for (const name of INPUT_ORDER) {
    const h = fnvHash(name);
    const hMSB = parseInt(h.slice(0, 8), 16);
    const hLSB = parseInt(h.slice(8, 16), 16);
    const arrFr = toArray32(normalize(inputToBigint(inputs[name])), n32);
    for (let j = 0; j < n32; j++) ex.writeSharedRWMemory(j, arrFr[n32 - 1 - j]);
    ex.setInputSignal(hMSB, hLSB, 0);
  }

  const witnessSize: number = ex.getWitnessSize();
  const witness: bigint[] = [];
  for (let i = 0; i < witnessSize; i++) {
    ex.getWitness(i);
    let v = 0n;
    for (let j = 0; j < n32; j++) {
      v += BigInt(ex.readSharedRWMemory(j) >>> 0) * (BigInt(0x100000000) ** BigInt(j));
    }
    witness.push(v);
  }

  // Write the .wtns file (snarkjs v2 format), replicating circom_runtime's
  // calculateWTNSBin. buff32 is a Uint32Array, so signed limbs convert to
  // unsigned automatically on assignment.
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

  return {
    wtns: Buffer.from(buff.buffer),
    witness,
    publicSignals: witness.slice(1, 14).map((w) => w.toString()),
  };
}

export interface GeneratedProof {
  proof: Groth16Proof;
  publicSignals: string[];
  /** Milliseconds spent in groth16.prove. */
  proveMs: number;
  /** Milliseconds spent building the witness. */
  witnessMs: number;
}

/** Build a witness and prove it with the gatekeeper zkey. */
export async function generateTestProof(
  inputs: CircuitInputs,
  opts: { wasmPath: string; zkeyPath: string; wtnsPath?: string },
): Promise<GeneratedProof> {
  const t0 = Date.now();
  const { wtns, publicSignals } = await buildWitness(inputs, opts.wasmPath);
  const witnessMs = Date.now() - t0;
  const wtnsPath = opts.wtnsPath ?? path.join("/tmp", `gk-test-${Date.now()}.wtns`);
  fs.writeFileSync(wtnsPath, wtns);
  const t1 = Date.now();
  const { proof } = await snarkjs.groth16.prove(opts.zkeyPath, wtnsPath);
  const proveMs = Date.now() - t1;
  return { proof, publicSignals, proveMs, witnessMs };
}

export { toField };
