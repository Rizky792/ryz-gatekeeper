// File-backed store of processed proof references (dedup / idempotency).
// Two indexes, both persisted to a single JSON file so they survive restarts:
//   - byTaskId: task_id -> record (replay the SAME decision on a platform
//     retry of the same task with the same proof)
//   - byProofHash: keccak256(proof + publicSignals) -> task_id (the exact
//     same proof reused under a DIFFERENT task_id is REJECTed as
//     proof_reused)
//
// NOTE: the store deliberately does NOT dedup on publicSignals[0]
// (Poseidon(salt, taskId)) alone. That value depends only on (salt, taskId),
// so two different proofs of the same task (same salt, same taskId, different
// amounts) share it. The unique proof reference is the proofHash. The
// statementHash is still recorded for traceability.
// The store is deliberately small and synchronous; the agent processes tasks
// one at a time (Express is single-threaded), so no locking is needed.

import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import type { DecisionKind, SeenProofRecord } from "./types.js";

export class SeenProofStore {
  private filePath: string;
  private byTaskId = new Map<string, SeenProofRecord>();
  private byProofHash = new Map<string, string>(); // proofHash -> taskId

  constructor(dataDir: string) {
    fs.mkdirSync(dataDir, { recursive: true });
    this.filePath = path.join(dataDir, "seen-proofs.json");
    this.load();
  }

  private load(): void {
    try {
      if (!fs.existsSync(this.filePath)) return;
      const raw = JSON.parse(fs.readFileSync(this.filePath, "utf8")) as SeenProofRecord[];
      if (!Array.isArray(raw)) return;
      for (const r of raw) {
        if (!r || typeof r.taskId !== "string" || typeof r.proofHash !== "string") continue;
        this.byTaskId.set(r.taskId, r);
        this.byProofHash.set(r.proofHash, r.taskId);
      }
    } catch {
      // Corrupt store file: start empty rather than crash the agent. The
      // file is rewritten on the next record.
      this.byTaskId.clear();
      this.byProofHash.clear();
    }
  }

  private save(): void {
    try {
      fs.writeFileSync(this.filePath, JSON.stringify([...this.byTaskId.values()], null, 2));
    } catch {
      // Persistence failure must not break request handling; dedup degrades
      // to in-memory only for this process lifetime.
    }
  }

  byTask(taskId: string): SeenProofRecord | undefined {
    return this.byTaskId.get(taskId);
  }

  taskIdForProofHash(proofHash: string): string | undefined {
    return this.byProofHash.get(proofHash);
  }

  record(r: SeenProofRecord): void {
    this.byTaskId.set(r.taskId, r);
    this.byProofHash.set(r.proofHash, r.taskId);
    this.save();
  }

  size(): number {
    return this.byTaskId.size;
  }
}

/** Canonical hash of a proof + its public signals (dedup key aid). */
export function proofHash(proof: unknown, publicSignals: string[] | undefined | null): string {
  return createHash("sha256")
    .update(JSON.stringify({ proof: proof ?? null, public_signals: publicSignals ?? null }))
    .digest("hex");
}

export type { DecisionKind };
