// End-to-end HTTP tests for the RYZ-GK server (src/index.ts).
// Spawns the real server as a child process with a TEST secret and a temp
// data dir (isolated dedup store), then exercises it over HTTP with fetch.
// Run: npm test (after npm run build; fixtures via npm run test:fixtures)
import { describe, it, before, after, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import { createHmac } from "node:crypto";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..");
const FIXTURES = path.join(__dirname, "fixtures");

const TEST_SECRET = "test-secret-ryz-gk-do-not-use-in-production";
const VK = "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";
const OTHER_VK = "0x1111111111111111111111111111111111111111111111111111111111111111";
const OTHER_RECIPIENT = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

function load(name) {
  return JSON.parse(fs.readFileSync(path.join(FIXTURES, `${name}.json`), "utf8"));
}

function taskFromFixture(fixture, overrides = {}) {
  const inp = fixture.inputs;
  const task = {
    type: "agent-games.proof-gatekeeper.v1",
    task_id: String(inp.taskId),
    mode: "practice",
    input: {
      registered_vk: inp.registeredVkHash,
      task_vk: inp.proofVkHash,
      amount: Number(inp.amount),
      recipient: inp.recipient,
      proof: fixture.proof,
      public_signals: fixture.publicSignals,
    },
    timestamp: Math.floor(Date.now() / 1000),
  };
  if (overrides.input) {
    task.input = { ...task.input, ...overrides.input };
    delete overrides.input;
  }
  return { ...task, ...overrides };
}

function sign(secret, rawBody) {
  return createHmac("sha256", secret).update(rawBody).digest("hex");
}

async function postAgent(base, body, { secret = TEST_SECRET, signIt = true, raw = null } = {}) {
  const rawBody = raw ?? Buffer.from(JSON.stringify(body), "utf8");
  const headers = { "Content-Type": "application/json" };
  if (signIt && secret) headers["x-agent-games-signature"] = sign(secret, rawBody);
  const res = await fetch(`${base}/agent`, { method: "POST", headers, body: rawBody });
  const text = await res.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch {
    /* non-JSON body */
  }
  return { res, json, text };
}

function verifyResponseSignature(res, text) {
  const sig = res.headers.get("x-agent-games-signature");
  assert.ok(sig, "response must carry x-agent-games-signature");
  assert.equal(sig, sign(TEST_SECRET, Buffer.from(text, "utf8")), "response signature must verify");
}

async function waitForHealth(base, timeoutMs = 15000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(`${base}/health`);
      if (res.ok) return;
    } catch {
      /* not up yet */
    }
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new Error(`server did not become healthy at ${base}`);
}

function startServer(port, extraEnv = {}) {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "ryz-gk-test-"));
  const env = {
    ...process.env,
    AGENT_GAMES_HMAC_SECRET: TEST_SECRET,
    PORT: String(port),
    DATA_DIR: dataDir,
    CIRCUITS_DIR: path.join(ROOT, "circuits"),
    REGISTERED_VK: VK,
    KURIER_API_KEY: "",
    ...extraEnv,
  };
  const child = spawn("node", [path.join(ROOT, "dist", "index.js")], {
    env,
    stdio: ["ignore", "pipe", "pipe"],
  });
  // Drain stdio so the child never blocks on a full pipe.
  child.stdout.on("data", () => {});
  child.stderr.on("data", () => {});
  return { child, dataDir, base: `http://127.0.0.1:${port}` };
}

describe("HTTP — health & preflight", () => {
  let srv;
  before(async () => {
    srv = startServer(18771);
    await waitForHealth(srv.base);
  });
  after(() => {
    srv.child.kill();
    fs.rmSync(srv.dataDir, { recursive: true, force: true });
  });

  it("GET /health returns ok + protocolVersion v1", async () => {
    const res = await fetch(`${srv.base}/health`);
    assert.equal(res.status, 200);
    assert.deepEqual(await res.json(), { ok: true, protocolVersion: "v1" });
  });

  it("signed preflight passes and the reply is signed", async () => {
    const body = {
      type: "agent-games.preflight.v1",
      agent_id: "ag_test",
      timestamp: Math.floor(Date.now() / 1000),
      challenge: "preflight_test_123",
    };
    const { res, json, text } = await postAgent(srv.base, body);
    assert.equal(res.status, 200);
    assert.deepEqual(json, { ok: true, protocolVersion: "v1" });
    verifyResponseSignature(res, text);
  });

  it("unsigned preflight is 401 when a secret is configured", async () => {
    const body = {
      type: "agent-games.preflight.v1",
      agent_id: "ag_test",
      timestamp: Math.floor(Date.now() / 1000),
      challenge: "preflight_test_456",
    };
    const { res } = await postAgent(srv.base, body, { signIt: false });
    assert.equal(res.status, 401);
  });

  it("stale preflight is 401", async () => {
    const body = {
      type: "agent-games.preflight.v1",
      agent_id: "ag_test",
      timestamp: Math.floor(Date.now() / 1000) - 1000,
      challenge: "preflight_test_789",
    };
    const { res } = await postAgent(srv.base, body);
    assert.equal(res.status, 401);
  });
});

describe("HTTP — auth & envelope errors", () => {
  let srv;
  before(async () => {
    srv = startServer(18772);
    await waitForHealth(srv.base);
  });
  after(() => {
    srv.child.kill();
    fs.rmSync(srv.dataDir, { recursive: true, force: true });
  });

  it("wrong HMAC is 401", async () => {
    const { res } = await postAgent(srv.base, taskFromFixture(load("approve")), {
      secret: "wrong-secret",
    });
    assert.equal(res.status, 401);
  });

  it("missing signature is 401", async () => {
    const { res } = await postAgent(srv.base, taskFromFixture(load("approve")), { signIt: false });
    assert.equal(res.status, 401);
  });

  it("malformed JSON is 400", async () => {
    const { res } = await postAgent(srv.base, null, { raw: Buffer.from("{not json", "utf8") });
    assert.equal(res.status, 400);
  });

  it("unknown type is 400", async () => {
    const { res } = await postAgent(srv.base, { type: "agent-games.unknown.v1" });
    assert.equal(res.status, 400);
  });

  it("task without input is 400", async () => {
    const { res } = await postAgent(srv.base, {
      type: "agent-games.proof-gatekeeper.v1",
      task_id: "12345",
    });
    assert.equal(res.status, 400);
  });

  it("task without task_id is 400", async () => {
    const task = taskFromFixture(load("approve"));
    delete task.task_id;
    const { res } = await postAgent(srv.base, task);
    assert.equal(res.status, 400);
  });
});

describe("HTTP — task decisions", () => {
  // Fresh server (fresh dedup store) per test: every fixture task_id is
  // used at most once here, so no test is polluted by an earlier decision.
  let srv;
  let portCounter = 18800;
  beforeEach(async () => {
    srv = startServer(portCounter++);
    await waitForHealth(srv.base);
  });
  afterEach(() => {
    srv.child.kill();
    fs.rmSync(srv.dataDir, { recursive: true, force: true });
  });

  it("APPROVE happy path (signed response, under the 60s deadline)", async () => {
    const t0 = Date.now();
    const { res, json, text } = await postAgent(srv.base, taskFromFixture(load("approve")));
    const ms = Date.now() - t0;
    assert.equal(res.status, 200);
    assert.equal(json.decision, "APPROVE");
    assert.equal(json.reason_code, "ok");
    assert.ok(json.proof, "APPROVE includes the proof");
    assert.equal(json.public_signals.length, 13);
    assert.equal(json.proof_tx, undefined, "no Kurier key => no proof_tx");
    verifyResponseSignature(res, text);
    assert.ok(ms < 60000, `response took ${ms}ms, must be under 60s`);
    console.log(`    (APPROVE round-trip: ${ms}ms)`);
  });

  it("APPROVE when balance < amount (circuit semantics)", async () => {
    const { res, json } = await postAgent(srv.base, taskFromFixture(load("approve-balance-below-amount")));
    assert.equal(res.status, 200);
    assert.equal(json.decision, "APPROVE");
  });

  it("REJECT amount above maxTransfer", async () => {
    const { json } = await postAgent(srv.base, taskFromFixture(load("reject-amount-above-max")));
    assert.equal(json.decision, "REJECT");
    assert.equal(json.reason_code, "amount_above_max_transfer");
    assert.ok(json.proof, "REJECT includes the proof when one exists");
  });

  it("REJECT balance below minimum", async () => {
    const { json } = await postAgent(srv.base, taskFromFixture(load("reject-balance-below-minimum")));
    assert.equal(json.decision, "REJECT");
    assert.equal(json.reason_code, "balance_below_minimum");
  });

  it("REJECT expired", async () => {
    const { json } = await postAgent(srv.base, taskFromFixture(load("reject-expired")));
    assert.equal(json.decision, "REJECT");
    assert.equal(json.reason_code, "expired");
  });

  it("REJECT vk substitution", async () => {
    const { json } = await postAgent(srv.base, taskFromFixture(load("reject-task-vk-mismatch")));
    assert.equal(json.decision, "REJECT");
    assert.equal(json.reason_code, "vk_substitution");
  });

  it("REJECT task vk mismatch", async () => {
    const { json } = await postAgent(
      srv.base,
      taskFromFixture(load("reject-task-vk-mismatch"), { input: { task_vk: VK } }),
    );
    assert.equal(json.decision, "REJECT");
    assert.equal(json.reason_code, "task_vk_mismatch");
  });

  it("REJECT condition recipient mismatch", async () => {
    const { json } = await postAgent(srv.base, taskFromFixture(load("reject-recipient-mismatch")));
    assert.equal(json.decision, "REJECT");
    assert.equal(json.reason_code, "condition_recipient_mismatch");
  });

  it("REJECT recipient mismatch (task-level)", async () => {
    const { json } = await postAgent(
      srv.base,
      taskFromFixture(load("approve"), { input: { recipient: OTHER_RECIPIENT } }),
    );
    assert.equal(json.decision, "REJECT");
    assert.equal(json.reason_code, "recipient_mismatch");
  });

  it("REJECT vk mismatch (task-level)", async () => {
    const { json } = await postAgent(
      srv.base,
      taskFromFixture(load("approve"), { input: { registered_vk: OTHER_VK, task_vk: OTHER_VK } }),
    );
    assert.equal(json.decision, "REJECT");
    assert.equal(json.reason_code, "vk_mismatch");
  });

  it("REJECT invalid proof (tampered pi_a)", async () => {
    const fixture = load("approve");
    const tampered = JSON.parse(JSON.stringify(fixture));
    tampered.proof.pi_a[0] = "12345";
    const { json } = await postAgent(srv.base, taskFromFixture(tampered));
    assert.equal(json.decision, "REJECT");
    assert.equal(json.reason_code, "invalid_proof");
  });

  it("REJECT missing proof (no proof field)", async () => {
    const task = taskFromFixture(load("approve"));
    delete task.input.proof;
    delete task.input.public_signals;
    const { json } = await postAgent(srv.base, task);
    assert.equal(json.decision, "REJECT");
    assert.equal(json.reason_code, "missing_proof");
    assert.equal(json.proof, undefined);
  });

  it("REJECT invalid public signals (wrong count)", async () => {
    const { json } = await postAgent(
      srv.base,
      taskFromFixture(load("approve"), { input: { public_signals: ["1", "2"] } }),
    );
    assert.equal(json.decision, "REJECT");
    assert.equal(json.reason_code, "invalid_public_signals");
  });
});

describe("HTTP — dedup & idempotency", () => {
  let srv;
  before(async () => {
    srv = startServer(18774);
    await waitForHealth(srv.base);
  });
  after(() => {
    srv.child.kill();
    fs.rmSync(srv.dataDir, { recursive: true, force: true });
  });

  it("replay: same task + same proof returns the cached APPROVE", async () => {
    const task = taskFromFixture(load("approve"));
    const first = await postAgent(srv.base, task);
    assert.equal(first.json.decision, "APPROVE");
    const second = await postAgent(srv.base, task);
    assert.equal(second.json.decision, "APPROVE");
    assert.equal(second.json.reason_code, "ok");
  });

  it("proof reused under a different task_id is REJECTed", async () => {
    const task = taskFromFixture(load("approve"), { task_id: "99999" });
    const { json } = await postAgent(srv.base, task);
    assert.equal(json.decision, "REJECT");
    assert.equal(json.reason_code, "proof_reused");
  });

  it("same task_id with a different proof is REJECTed", async () => {
    const task = taskFromFixture(load("approve-balance-below-amount"), {
      task_id: load("approve").inputs.taskId, // "12345" — already answered above
    });
    const { json } = await postAgent(srv.base, task);
    assert.equal(json.decision, "REJECT");
    assert.equal(json.reason_code, "proof_reused");
  });
});

describe("HTTP — timeout fails closed", () => {
  let srv;
  before(async () => {
    srv = startServer(18775, { REQUEST_TIMEOUT_MS: "1" });
    await waitForHealth(srv.base);
  });
  after(() => {
    srv.child.kill();
    fs.rmSync(srv.dataDir, { recursive: true, force: true });
  });

  it("a 1ms deadline returns REJECT/timeout instead of hanging", async () => {
    const { res, json } = await postAgent(srv.base, taskFromFixture(load("approve")));
    assert.equal(res.status, 200);
    assert.equal(json.decision, "REJECT");
    assert.equal(json.reason_code, "timeout");
  });
});
