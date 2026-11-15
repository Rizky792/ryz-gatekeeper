// RYZ-GK — Proof Gatekeeper agent for the zkVerify Agent Games (practice mode).
// Express server: GET /health, GET /, POST /agent AND POST / (the platform
// POSTs the signed preflight to the registered endpoint URL itself, i.e. the
// root path — a POST / with no route used to answer 404 and fail preflight).
// The platform POSTs task payloads; the agent verifies the HMAC, verifies the
// ZK proof (locally with snarkjs, plus Kurier finalization when a key is
// configured), runs the pure decision logic in gatekeeper.ts, and signs every
// response.
//
// Fail-closed everywhere: a missing/invalid signature is a 401, a malformed
// envelope is a 400, a timeout or internal error is a REJECT decision, and
// any failing check is a REJECT with a snake_case reason code.
// The HMAC secret, the raw body, and full task payloads are NEVER logged.

import express from "express";
import fs from "node:fs";
import path from "node:path";
import { loadConfig } from "./config.js";
import { verifyHmac, signResponse } from "./hmac.js";
import { decide, type DecideContext } from "./gatekeeper.js";
import {
  verifyProofLocally,
  submitProofToKurier,
  waitForKurierFinalized,
} from "./zkverify.js";
import { SeenProofStore, proofHash } from "./store.js";
import { PUBLIC_SIGNAL_COUNT } from "./circuit.js";
import type { Decision, GatekeeperTask, PreflightTask } from "./types.js";

const AGENT_NAME = "RYZ-GK";
const PROTOCOL_VERSION = "v1";

const config = loadConfig();
const store = new SeenProofStore(config.dataDir);

if (!config.hmacSecret) {
  console.warn(
    "[warn] AGENT_GAMES_HMAC_SECRET is not set — running in TEST MODE: " +
      "HMAC verification is skipped and responses are unsigned. " +
      "Set the secret (dashboard -> Rotate Secret) before registering.",
  );
}
if (!config.kurierApiKey) {
  console.warn(
    "[warn] KURIER_API_KEY is not set — proof finalization via Kurier is " +
      "skipped; local snarkjs verification gates APPROVE. See README.md.",
  );
}
// Fail fast when the verification key is missing: without it every proof
// would (correctly but confusingly) fail verification.
const vkeyPath = path.join(config.circuitsDir, "gatekeeper.vkey.json");
if (!fs.existsSync(vkeyPath)) {
  console.error(`[fatal] gatekeeper verification key not found: ${vkeyPath}`);
  process.exit(1);
}

const app = express();
// Capture the RAW body bytes: the HMAC is computed over them, before any
// JSON parsing. express.raw gives us a Buffer for every content type.
// Mounted globally (not only on /agent): the platform POSTs preflight/tasks
// to the endpoint root "/" as well, and those need the raw body too.
app.use(express.raw({ type: "*/*", limit: "2mb" }));

function sendSigned(res: express.Response, status: number, body: unknown): void {
  const raw = Buffer.from(JSON.stringify(body), "utf8");
  if (config.hmacSecret) {
    res.setHeader("x-agent-games-signature", signResponse(config.hmacSecret, raw));
  }
  res.status(status).type("application/json").send(raw);
}

function logDecision(taskId: string, d: Decision, ms: number): void {
  // Only metadata is logged: never the secret, the raw body, or the payload.
  console.log(
    `[${AGENT_NAME}] task=${taskId} decision=${d.decision} reason=${d.reason_code} ` +
      `${d.proof_tx ? `proof_tx=${d.proof_tx} ` : ""}(${ms}ms)`,
  );
}

app.get("/health", (_req, res) => {
  res.json({ ok: true, protocolVersion: PROTOCOL_VERSION });
});

app.get("/", (_req, res) => {
  res.json({ ok: true, agent: AGENT_NAME, protocolVersion: PROTOCOL_VERSION });
});

app.post(["/", "/agent"], async (req, res) => {
  const started = Date.now();
  const rawBody: Buffer = Buffer.isBuffer(req.body) ? req.body : Buffer.from([]);
  const signature = req.header("x-agent-games-signature");

  // --- HMAC verification comes before any decision logic ---
  if (config.hmacSecret && !verifyHmac(config.hmacSecret, rawBody, signature)) {
    sendSigned(res, 401, { error: "invalid_signature" });
    return;
  }
  if (!config.hmacSecret && signature) {
    console.warn("[warn] signature header present but no secret is configured; ignoring it (test mode).");
  }

  // --- parse the envelope ---
  let body: any;
  try {
    body = JSON.parse(rawBody.toString("utf8"));
  } catch {
    sendSigned(res, 400, { error: "invalid_json" });
    return;
  }
  if (!body || typeof body !== "object" || typeof body.type !== "string") {
    sendSigned(res, 400, { error: "malformed_envelope" });
    return;
  }

  // --- preflight: liveness + signature check before the agent is active ---
  if (body.type === "agent-games.preflight.v1") {
    const pf = body as PreflightTask;
    const age = Math.floor(Date.now() / 1000) - (pf.timestamp ?? 0);
    if (!pf.agent_id || !pf.challenge || !Number.isFinite(pf.timestamp) || age > 300 || age < -60) {
      sendSigned(res, 401, { error: "invalid_preflight" });
      return;
    }
    sendSigned(res, 200, { ok: true, protocolVersion: PROTOCOL_VERSION });
    return;
  }

  if (body.type !== "agent-games.proof-gatekeeper.v1") {
    sendSigned(res, 400, { error: "unknown_type" });
    return;
  }

  // --- task handling with a hard deadline (fail closed on timeout) ---
  const task = body as GatekeeperTask;
  const taskId = typeof task.task_id === "string" ? task.task_id : "";
  // A task without an id or an input object is a malformed envelope (400),
  // not a decision — decide() only sees structurally valid tasks.
  if (!taskId || !task.input || typeof task.input !== "object") {
    sendSigned(res, 400, { error: "malformed_task" });
    return;
  }
  try {
    const decision = await Promise.race([
      handleTask(task),
      new Promise<Decision>((resolve) =>
        setTimeout(
          () => resolve({ decision: "REJECT", reason_code: "timeout" }),
          config.requestTimeoutMs,
        ),
      ),
    ]);
    logDecision(taskId || "(no task_id)", decision, Date.now() - started);
    sendSigned(res, 200, decision);
  } catch (e: any) {
    console.error(`[${AGENT_NAME}] internal error on task=${taskId}:`, e?.message ?? String(e));
    const d: Decision = { decision: "REJECT", reason_code: "internal_error" };
    if (task.input?.proof) {
      d.proof = task.input.proof;
      if (Array.isArray(task.input.public_signals)) d.public_signals = task.input.public_signals;
    }
    sendSigned(res, 200, d);
  }
});

async function handleTask(task: GatekeeperTask): Promise<Decision> {
  const nowSeconds = Math.floor(Date.now() / 1000);
  const input = task.input ?? ({} as GatekeeperTask["input"]);

  // Envelope shape: a task without an id or an input object is malformed.
  if (!task.task_id || typeof task.task_id !== "string" || !input || typeof input !== "object") {
    return { decision: "REJECT", reason_code: "malformed_task" };
  }

  const statementHash =
    Array.isArray(input.public_signals) && typeof input.public_signals[0] === "string"
      ? input.public_signals[0]
      : null;
  const pHash = input.proof ? proofHash(input.proof, input.public_signals ?? null) : null;

  // --- dedup / idempotency (before any verification work) ---
  // The unique proof reference is the proofHash (proof + publicSignals).
  // publicSignals[0] alone is NOT unique (it depends only on salt+taskId).
  // A replay requires the SAME task_id, the SAME proof, AND the same task
  // bindings (recipient/amount/vks) — a retry with different bindings is
  // not a retry; it is rejected as proof_reused.
  const bindings = {
    recipient: String(input.recipient ?? ""),
    amount: String(input.amount ?? ""),
    registeredVk: String(input.registered_vk ?? ""),
    taskVk: String(input.task_vk ?? ""),
  };
  const priorByTask = store.byTask(task.task_id);
  if (priorByTask) {
    const sameProof = !!pHash && priorByTask.proofHash === pHash;
    const sameBindings =
      priorByTask.recipient === bindings.recipient &&
      priorByTask.amount === bindings.amount &&
      priorByTask.registeredVk === bindings.registeredVk &&
      priorByTask.taskVk === bindings.taskVk;
    if (sameProof && sameBindings) {
      // Platform retry of the same task with the same proof: replay the
      // original decision (idempotent), do not re-verify or re-decide.
      const replay: Decision = {
        decision: priorByTask.decision,
        reason_code: priorByTask.reasonCode,
      };
      if (input.proof) {
        replay.proof = input.proof;
        if (Array.isArray(input.public_signals)) replay.public_signals = input.public_signals;
      }
      if (priorByTask.proofTx) replay.proof_tx = priorByTask.proofTx;
      return replay;
    }
    // Same task_id but a different proof or different bindings: the first
    // submission wins.
    return rejectWithProof(task, "proof_reused");
  }
  if (pHash) {
    const otherTask = store.taskIdForProofHash(pHash);
    if (otherTask && otherTask !== task.task_id) {
      // This exact proof was already used for another task.
      return rejectWithProof(task, "proof_reused");
    }
  }

  // --- local proof verification (snarkjs) ---
  let proofValid = false;
  const signalsWellFormed =
    Array.isArray(input.public_signals) &&
    input.public_signals.length === PUBLIC_SIGNAL_COUNT &&
    input.public_signals.every((s) => typeof s === "string");
  if (input.proof && signalsWellFormed) {
    const v = await verifyProofLocally(input.proof, input.public_signals as string[], config.circuitsDir);
    proofValid = v.valid;
    if (!v.valid && v.error) console.warn(`[${AGENT_NAME}] local verify failed: ${v.error}`);
  }

  const baseCtx: DecideContext = {
    registeredVk: config.registeredVk,
    policyMaxTransferCap: config.policyMaxTransferCap,
    policyMinBalance: config.policyMinBalance,
    policyRequireBalanceCoversAmount: config.policyRequireBalanceCoversAmount,
    proofValid,
    proofFinalized: true, // local-only unless Kurier is consulted below
    kurierUsed: false,
    nowSeconds,
    taskMaxAgeSeconds: config.taskMaxAgeSeconds,
  };

  // First pass: decide on local verification only. If it REJECTs, there is
  // no reason to spend time on Kurier — return the REJECT immediately.
  const first = decide(task, baseCtx);
  if (first.decision === "REJECT") {
    record(task, statementHash, pHash, first);
    return first;
  }

  // It would APPROVE locally. When a Kurier key is configured, finalization
  // on the zkVerify network is required before APPROVE.
  if (config.kurierApiKey && input.proof && signalsWellFormed) {
    const sub = await submitProofToKurier(input.proof, input.public_signals as string[], config.kurierApiKey);
    if (!sub.submitted || !sub.jobId) {
      const d = rejectWithProof(task, "proof_not_finalized");
      record(task, statementHash, pHash, d);
      return d;
    }
    const status = await waitForKurierFinalized(sub.jobId, config.kurierApiKey, config.kurierTimeoutMs);
    if (status.status !== "Finalized") {
      const d = rejectWithProof(task, "proof_not_finalized");
      record(task, statementHash, pHash, d);
      return d;
    }
    const finalDecision: Decision = { ...first, proof_tx: status.proofTx };
    record(task, statementHash, pHash, finalDecision);
    return finalDecision;
  }

  record(task, statementHash, pHash, first);
  return first;
}

function rejectWithProof(task: GatekeeperTask, reasonCode: string): Decision {
  const d: Decision = { decision: "REJECT", reason_code: reasonCode };
  if (task.input?.proof) {
    d.proof = task.input.proof;
    if (Array.isArray(task.input.public_signals)) d.public_signals = task.input.public_signals;
  }
  return d;
}

function record(
  task: GatekeeperTask,
  statementHash: string | null,
  pHash: string | null,
  d: Decision,
): void {
  // Only record when there is a proof to dedup on (statementHash is kept
  // for traceability; the dedup key is the proofHash).
  if (!pHash) return;
  const input = task.input ?? ({} as GatekeeperTask["input"]);
  store.record({
    taskId: task.task_id,
    statementHash: statementHash ?? "",
    proofHash: pHash,
    decision: d.decision,
    reasonCode: d.reason_code,
    proofTx: d.proof_tx,
    decidedAt: new Date().toISOString(),
    recipient: String(input.recipient ?? ""),
    amount: String(input.amount ?? ""),
    registeredVk: String(input.registered_vk ?? ""),
    taskVk: String(input.task_vk ?? ""),
  });
}

app.use((_req, res) => {
  res.status(404).json({ error: "not_found" });
});

app.listen(config.port, () => {
  console.log(`[${AGENT_NAME}] listening on :${config.port} (protocolVersion ${PROTOCOL_VERSION})`);
  console.log(`[${AGENT_NAME}] health: GET /health | tasks: POST /agent`);
});
