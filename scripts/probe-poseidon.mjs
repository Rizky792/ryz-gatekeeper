// Test Poseidon constructions for publicSignals[0] (w1) against 3 vectors.
// w1 depends only on (taskId, salt).
import { buildPoseidon } from "circomlibjs";

const poseidon = await buildPoseidon();
const F = poseidon.F;

const vectors = [
  { taskId: 12345n, salt: 999999n, w1: 825200592033093192580527800177737244152302871154489164750716978908393020251n },
  { taskId: 12345n, salt: 123456n, w1: 4897575860809641223786465041415601190282247386217973944231592519404945072120n },
  { taskId: 777n, salt: 999999n, w1: 20068657689870165699243590848134927940439492217182871102752475857687198427192n },
];

function H(inputs) {
  return F.toObject(poseidon(inputs));
}

const candidates = [
  ["poseidon([taskId, salt])", (v) => H([v.taskId, v.salt])],
  ["poseidon([salt, taskId])", (v) => H([v.salt, v.taskId])],
  ["poseidon([taskId])", (v) => H([v.taskId])],
  ["poseidon([salt])", (v) => H([v.salt])],
  ["poseidon([2, taskId, salt])", (v) => H([2n, v.taskId, v.salt])],
  ["poseidon([2, salt, taskId])", (v) => H([2n, v.salt, v.taskId])],
  ["poseidon([taskId, salt, 2])", (v) => H([v.taskId, v.salt, 2n])],
  ["poseidon([salt, taskId, 2])", (v) => H([v.salt, v.taskId, 2n])],
  ["poseidon([0, taskId, salt])", (v) => H([0n, v.taskId, v.salt])],
  ["poseidon([taskId, salt, 0])", (v) => H([v.taskId, v.salt, 0n])],
  ["poseidon([taskId, salt, salt])", (v) => H([v.taskId, v.salt, v.salt])],
  ["poseidon([salt, salt, taskId])", (v) => H([v.salt, v.salt, v.taskId])],
  ["poseidon([taskId, taskId, salt])", (v) => H([v.taskId, v.taskId, v.salt])],
  ["poseidon([1, taskId, salt])", (v) => H([1n, v.taskId, v.salt])],
  ["poseidon([taskId, salt, 1])", (v) => H([v.taskId, v.salt, 1n])],
];

for (const [name, fn] of candidates) {
  let ok = true;
  for (const v of vectors) {
    try {
      if (fn(v) !== v.w1) { ok = false; break; }
    } catch (e) { ok = false; break; }
  }
  console.log(`${ok ? ">>> MATCH" : "    no   "} ${name}`);
}
console.log("done poseidon");
