// Runtime configuration from environment variables. The HMAC secret comes
// from the Agent Games dashboard (My Agents -> Rotate Secret, shown once).
// It must NEVER be committed; local runs use a test secret instead.

import path from "node:path";

export interface AgentConfig {
  /** Platform HMAC secret. Empty => test mode: signatures are NOT enforced
   *  (a warning is logged); never run like this against the real platform. */
  hmacSecret: string;
  zkverifyRpcUrl: string;
  agentEndpointUrl: string;
  port: number;
  /** Optional Kurier API key. Without it, proof finalization via Kurier is
   *  skipped and local snarkjs verification gates APPROVE. */
  kurierApiKey: string;
  /** Optional policy caps (applied on top of the circuit's own checks):
   *  refuse any approval whose amount exceeds this (decimal string). */
  policyMaxTransferCap: bigint | null;
  /** Optional policy floor: refuse unless the statement's publicBalance is
   *  at least this (decimal string). */
  policyMinBalance: bigint | null;
  /** Opt-in stricter gate: refuse when the statement's publicBalance is
   *  below the amount. The circuit does NOT check this (verified); default
   *  off. Set POLICY_REQUIRE_BALANCE_COVERS_AMOUNT=1 to enable. */
  policyRequireBalanceCoversAmount: boolean;
  /** Max age (seconds) of a task timestamp before it is REJECTed as stale. */
  taskMaxAgeSeconds: number;
  /** How long (ms) to wait for Kurier Finalized before REJECTing. */
  kurierTimeoutMs: number;
  /** Hard per-request deadline (ms); must stay under the platform's 60 s. */
  requestTimeoutMs: number;
  /** Directory holding the circuit artifacts (wasm/zkey/vkey). */
  circuitsDir: string;
  /** Directory holding the seen-proof store (dedup persistence). */
  dataDir: string;
  /** The registered vk hash for this agent's statements (0x...). Defaults to
   *  the gatekeeper circuit vkHash; override when the registered statement
   *  vk differs. */
  registeredVk: string;
}

function envInt(name: string, fallback: number): number {
  const raw = process.env[name];
  if (!raw) return fallback;
  const n = parseInt(raw, 10);
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

function envBigint(name: string): bigint | null {
  const raw = process.env[name];
  if (!raw || !/^\d+$/.test(raw.trim())) return null;
  try {
    return BigInt(raw.trim());
  } catch {
    return null;
  }
}

export function loadConfig(): AgentConfig {
  const root = process.cwd();
  return {
    hmacSecret: process.env.AGENT_GAMES_HMAC_SECRET ?? "",
    zkverifyRpcUrl: process.env.ZKVERIFY_RPC_URL ?? "",
    agentEndpointUrl: process.env.AGENT_ENDPOINT_URL ?? "",
    port: envInt("PORT", 8080),
    kurierApiKey: process.env.KURIER_API_KEY ?? "",
    policyMaxTransferCap: envBigint("POLICY_MAX_TRANSFER_CAP"),
    policyMinBalance: envBigint("POLICY_MIN_BALANCE"),
    policyRequireBalanceCoversAmount:
      process.env.POLICY_REQUIRE_BALANCE_COVERS_AMOUNT === "1" ||
      process.env.POLICY_REQUIRE_BALANCE_COVERS_AMOUNT === "true",
    taskMaxAgeSeconds: envInt("TASK_MAX_AGE_SECONDS", 300),
    kurierTimeoutMs: envInt("KURIER_TIMEOUT_MS", 30000),
    requestTimeoutMs: envInt("REQUEST_TIMEOUT_MS", 55000),
    circuitsDir: process.env.CIRCUITS_DIR ?? path.join(root, "circuits"),
    dataDir: process.env.DATA_DIR ?? path.join(root, "data"),
    registeredVk: process.env.REGISTERED_VK ?? "",
  };
}
