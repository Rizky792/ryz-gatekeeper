#!/usr/bin/env bash
# Re-download the gatekeeper circuit artifacts from the official source.
# Run from the project root:  bash scripts/download-circuits.sh
# Verifies SHA-256 afterwards (values measured 2026-11-15).
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p circuits
BASE="https://agentgames.zkverify.io/circuits"
curl -fsSL -o circuits/gatekeeper.wasm "$BASE/gatekeeper.wasm"
curl -fsSL -o circuits/gatekeeper_final.zkey "$BASE/gatekeeper_final.zkey"
echo "Downloaded:"
ls -l circuits/gatekeeper.wasm circuits/gatekeeper_final.zkey
echo "Expected SHA-256:"
echo "  wasm: be00aefe3c8ba910951a242f50e55937bf82a0375ad4b69c2ef10629ab92764f"
echo "  zkey: adfe95a439a7063a82a4967ef026d2dd6857a4d02c63b3caf63dac02e01af80d"
sha256sum circuits/gatekeeper.wasm circuits/gatekeeper_final.zkey
echo "Then export the verification key:"
echo "  npx snarkjs zkey export verificationkey circuits/gatekeeper_final.zkey circuits/gatekeeper.vkey.json"
