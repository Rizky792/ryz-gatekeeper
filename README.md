# RYZ-GK — Proof Gatekeeper agent (Agent Games, zkVerify)

A production-ready TypeScript (Node 20) agent for the **Proof Gatekeeper**
event in the zkVerify Agent Games. The platform POSTs task payloads to the
agent endpoint; the agent verifies the HMAC, verifies the zero-knowledge
proof (locally with snarkjs, plus Kurier finalization when a key is
configured), and decides whether to **APPROVE** or **REJECT** a
payment request backed by that proof. A proof can verify perfectly and still
authorize the wrong action, so the agent re-checks the statement, the
registered verification key, the circuit, the public inputs, and the
transaction reference before it approves. **Fail closed everywhere:** any
missing, uncertain, or failing check is a REJECT.

- Agent name (default): **RYZ-GK** (the dashboard needs a unique name per agent)
- Mode: **practice** (second agent; the first is the Steal-the-VFY agent `Ryz`)
- Protocol version: `v1`
- Turn deadline: **60 seconds** (the agent answers in ~1 s locally)

## The gatekeeper circuit (reverse-engineered)

The `.circom` source was never published, so the circuit was determined
empirically from the published `wasm` + `zkey` (method + full evidence in
`~/workspace/agent-games/build-report-gatekeeper.md`). Verified facts:

- Circuit `gatekeeper`, Groth16 / BN128, Circom 2. Template
  `GatekeeperEvaluation`. vkHash
  `0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`.
- **13 public signals** (`nPublic=13`), layout `publicSignals[0..12]`:
  `[0]` statementHash = Poseidon(salt, taskId) · `[1]` registeredVkHash ·
  `[2]` proofVkHash · `[3]` minimum · `[4]` publicBalance ·
  `[5]` expiryBlock · `[6]` currentBlock · `[7]` recipient ·
  `[8]` conditionRecipient · `[9]` amount · `[10]` maxTransfer ·
  `[11]` decision (0|1) · `[12]` taskId.
  `salt` (private) is the 14th witness input, not a public signal.
- **APPROVE conditions** (all must hold for `decision == 1`):
  `proofVkHash == registeredVkHash` · `recipient == conditionRecipient` ·
  `publicBalance >= minimum` · `amount <= maxTransfer` ·
  `currentBlock < expiryBlock` (strict) ·
  `taskId, salt, recipient, vkHash` all nonzero · `decision == evaluation`.
- **Not checked by the circuit** (verified by counterexample): the circuit
  does **not** require `publicBalance >= amount`. A witness with
  balance 200, amount 250, minimum 100, decision 1 computes fine. `minimum`
  is a minimum-**balance** threshold, not a minimum amount, and the amount is
  bounded only by `maxTransfer`. The agent follows the circuit by default;
  enable `POLICY_REQUIRE_BALANCE_COVERS_AMOUNT=1` for the stricter gate.
- Input names (witness order): `registeredVkHash, proofVkHash, minimum,
  publicBalance, expiryBlock, currentBlock, recipient, conditionRecipient,
  amount, maxTransfer, decision, taskId, salt`.

## Project structure

```
package.json            Express + TypeScript + viem + snarkjs + circomlibjs
src/config.ts           env: AGENT_GAMES_HMAC_SECRET, ZKVERIFY_RPC_URL,
                        AGENT_ENDPOINT_URL, KURIER_API_KEY, PORT, policy caps
src/index.ts            Express app: GET /health, POST /agent
src/hmac.ts             verify/sign x-agent-games-signature (HMAC-SHA256,
                        raw body, constant-time compare)
src/gatekeeper.ts       decide(task, ctx) — pure, testable decision logic
src/zkverify.ts         local snarkjs verification + Kurier submitProof /
                        finalization polling
src/witness.ts          DEV/TEST ONLY: build a gatekeeper witness (hash-keyed)
                        and generate test proofs locally
src/circuit.ts          circuit constants, public-signal layout, field
                        helpers, taskIdToField, Poseidon(salt, taskId)
src/store.ts            file-backed seen-proof store (dedup / idempotency)
src/types.ts            Task, Proof, PublicSignals, Decision
src/fnv.ts              FNV-1a hash (as circom_runtime computes it)
Dockerfile              Node 20 slim, port 8080
.env.example            variable names only (no secrets)
circuits/               gatekeeper.wasm, gatekeeper_final.zkey,
                        gatekeeper.vkey.json (~2 MB, committed)
scripts/download-circuits.sh   re-fetch + verify the circuit artifacts
scripts/generate-test-fixtures.mjs  generate test proofs once
test/                   decide.test.mjs (24 unit tests),
                        http.test.mjs (27 integration tests),
                        fixtures/ (7 locally generated proofs)
```

## Setup

```bash
npm install
npm run build
```

Copy `.env.example` to `.env` and fill it in (see below). Then:

```bash
npm start          # node dist/index.js, listens on $PORT (default 8080)
```

### Where the secret comes from

The HMAC secret is generated at agent registration on the Agent Games
dashboard (**My Agents → Rotate Secret**) and shown **exactly once**.
Copy it into `AGENT_GAMES_HMAC_SECRET` (or set it as an environment
variable on the host). **Never commit it, never paste it in chat, never put
it in the repo.** Without a secret the server runs in **test mode**
(HMAC verification skipped, responses unsigned) and logs a warning — never
register an agent in that mode.

The Kurier API key (`KURIER_API_KEY`) is optional. Without it, proof
finalization via Kurier is skipped and local snarkjs verification gates
APPROVE; `proof_tx` is then absent from APPROVE responses. With a key, the
agent submits the proof to Kurier and requires `Finalized` before APPROVE
(`proof_not_finalized` otherwise).

### Environment

| Variable | Required | Notes |
|---|---|---|
| `AGENT_GAMES_HMAC_SECRET` | yes (prod) | Dashboard → Rotate Secret, shown once |
| `ZKVERIFY_RPC_URL` | no | zkVerify RPC (reserved; not used yet) |
| `AGENT_ENDPOINT_URL` | no | This agent's public URL (informational) |
| `KURIER_API_KEY` | no | Enables Kurier finalization + `proof_tx` |
| `PORT` | no | Default `8080` |
| `REGISTERED_VK` | no | The vk hash this agent registered (0x...); tasks with a different `registered_vk` are rejected (`unregistered_vk`) |
| `POLICY_MAX_TRANSFER_CAP` | no | Refuse approvals above this amount |
| `POLICY_MIN_BALANCE` | no | Refuse unless `publicBalance` ≥ this |
| `POLICY_REQUIRE_BALANCE_COVERS_AMOUNT` | no | `1` to refuse when `publicBalance < amount` (opt-in; the circuit does not check this) |
| `TASK_MAX_AGE_SECONDS` | no | Default `300` |
| `KURIER_TIMEOUT_MS` | no | Default `30000` |
| `REQUEST_TIMEOUT_MS` | no | Default `55000` (must stay under 60 s) |
| `CIRCUITS_DIR` / `DATA_DIR` | no | Defaults `./circuits` / `./data` |

## Testing the endpoints

Health:

```bash
curl http://localhost:8080/health
# {"ok":true,"protocolVersion":"v1"}
```

Preflight (the platform sends this before marking the agent active; the
reply must carry a valid `x-agent-games-signature` header):

```bash
BODY='{"type":"agent-games.preflight.v1","agent_id":"ag_test","timestamp":1730000000,"challenge":"preflight_test"}'
SIG=$(printf '%s' "$BODY" | openssl dgst -sha256 -hmac "$AGENT_GAMES_HMAC_SECRET" | cut -d' ' -f2)
curl -X POST http://localhost:8080/agent \
  -H 'Content-Type: application/json' \
  -H "x-agent-games-signature: $SIG" \
  -d "$BODY"
# {"ok":true,"protocolVersion":"v1"}
```

Task (APPROVE path — use a fixture from `test/fixtures/approve.json`;
`task_id` must match the proof's `taskId`, here `12345`):

```bash
# Build a task envelope from the fixture (jq):
jq '{type:"agent-games.proof-gatekeeper.v1",task_id:.inputs.taskId,mode:"practice",
  input:{registered_vk:.inputs.registeredVkHash,task_vk:.inputs.proofVkHash,
  amount:(.inputs.amount|tonumber),recipient:.inputs.recipient,
  proof:.proof,public_signals:.publicSignals},
  timestamp:(now|floor)}' test/fixtures/approve.json > /tmp/gk-task.json
BODY=$(cat /tmp/gk-task.json)
SIG=$(printf '%s' "$BODY" | openssl dgst -sha256 -hmac "$AGENT_GAMES_HMAC_SECRET" | cut -d' ' -f2)
curl -X POST http://localhost:8080/agent \
  -H 'Content-Type: application/json' \
  -H "x-agent-games-signature: $SIG" \
  -d "$BODY"
# {"decision":"APPROVE","reason_code":"ok","proof":{...},"public_signals":[...]}
```

Expected responses:

| Situation | HTTP | Body |
|---|---|---|
| Health | 200 | `{ok:true, protocolVersion:"v1"}` |
| Valid preflight | 200 | `{ok:true, protocolVersion:"v1"}` (signed) |
| Missing/invalid HMAC | 401 | `{error:"invalid_signature"}` |
| Malformed JSON / unknown type / task without id or input | 400 | `{error:"..."}` |
| Valid task, all checks pass | 200 | `{decision:"APPROVE", reason_code:"ok", proof, public_signals, proof_tx?}` |
| Valid task, a check fails | 200 | `{decision:"REJECT", reason_code:"<snake_case>", proof?, public_signals?}` |
| Timeout / internal error | 200 | `{decision:"REJECT", reason_code:"timeout" \| "internal_error"}` |

## Decision rules (`decide()` in `src/gatekeeper.ts`)

APPROVE only when every check passes; otherwise REJECT with a snake_case
`reason_code` (first failure wins). In order:

`malformed_task` · `stale_task` · `missing_proof` ·
`invalid_public_signals` · `invalid_proof` · `proof_not_finalized` ·
`vk_substitution` (task's `registered_vk` ≠ `task_vk`) · `vk_mismatch`
(proof's registered vk ≠ task's) · `unregistered_vk` (task's registered vk
is not this agent's) · `task_vk_mismatch` (proof's vk ≠ task's `task_vk`) ·
`recipient_mismatch` · `condition_recipient_mismatch` · `amount_mismatch` ·
`invalid_task_id` · `balance_below_minimum` · `amount_above_max_transfer` ·
`expired` · `decision_not_approve` · `policy_max_transfer_exceeded` ·
`policy_min_balance_not_met` · `policy_balance_below_amount` → `ok`.

Dedup / idempotency: a proof is identified by the hash of
(proof + publicSignals), not by `publicSignals[0]` alone (that value
depends only on salt+taskId, so two different proofs of one task share
it). A platform retry of the same task with the same proof and the same
bindings replays the original decision; the same proof under a different
task, or the same task with a different proof/bindings, is REJECTed as
`proof_reused`. Records persist in `data/seen-proofs.json` across restarts.

For REJECT, the proof + public_signals are included whenever the task has
a proof; they are omitted only when the task has no proof at all.

## Running the tests

```bash
npm run build
npm run test:fixtures   # generate the 7 test proofs once (~5 s total)
npm test                 # 51 tests: 24 decide() unit + 27 HTTP integration
```

Measured locally (this VM): witness 58–138 ms, `groth16.prove`
273–1126 ms, `groth16.verify` ~100–200 ms, full APPROVE round-trip
~850 ms — far inside the 60 s deadline. The tests spawn real servers on
localhost with a test secret; no Kurier key is needed (local-only mode).

Note: `snarkjs` leaves the Node event loop alive after proving, so CLI
scripts that prove (the fixture generator) call `process.exit(0)`
explicitly. The server is unaffected (it never exits by design).

## Deploy

### Railway (same flow as the Steal-the-VFY agent)

1. Push this repo to GitHub (public repo, no secrets).
2. Railway → New Project → Deploy from GitHub repo.
3. Set the environment variables (at minimum `AGENT_GAMES_HMAC_SECRET`;
   add `KURIER_API_KEY` when available, `REGISTERED_VK` after
   registration, and the policy caps if wanted).
4. The `Dockerfile` builds Node 20 + TypeScript and serves on `$PORT`.
5. Verify: `curl https://<your-app>.up.railway.app/health`.

### Fly.io

```bash
fly launch --dockerfile Dockerfile
fly secrets set AGENT_GAMES_HMAC_SECRET=... KURIER_API_KEY=...
fly deploy
```

After deploy: register the agent on the Agent Games dashboard (name
**RYZ-GK**, track Proof Gatekeeper, repo URL, endpoint URL), copy the
HMAC secret from Rotate Secret into the host env (never into the repo),
then run a practice-mode task and confirm an APPROVE/REJECT with a valid
signature. See `build-report-gatekeeper.md` for the full checklist.

## Assumptions & open items

- **`task_id` → field mapping is assumed**: the platform never published
  how the `gk_...` task_id string maps to the circuit's `taskId` field.
  The agent uses integer-as-is for numeric/hex strings, else
  `keccak256(UTF-8)` mod p. Validate against the first real practice
  envelope; a mismatch surfaces as `invalid_task_id`.
- **Kurier response shapes are assumed**: the `/build` page documents the
  endpoints but not the response JSON. The code accepts `jobId`/`job_id`/
  `id`, `status`/`state`, and `txHash`/`proofTx`/`transactionHash`
  spellings; an unrecognised response is treated as "not finalized".
- **The second Poseidon template's role is undetermined**: the circuit
  contains two Poseidon templates; only one output (`Poseidon(salt,
  taskId)`) is public. The other's output is internal and does not affect
  the agent's decision logic (the observable checks are fully mapped).
- **The IsZero nonzero check is inferred**: the circuit has one `IsZero`
  component; the observed failures for zero `taskId`/`salt`/`recipient`/
  `vkHash` are consistent with a single IsZero over their product, but
  the exact internal form is not proven. The agent relies on snarkjs
  verification for this (a valid proof guarantees the constraints held).
- **No Kurier key yet**: finalization is local-only until a key exists.
- The agent never generates proofs in production; `src/witness.ts` is a
  test/dev utility only.
