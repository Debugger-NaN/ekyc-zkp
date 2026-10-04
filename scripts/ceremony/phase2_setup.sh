#!/usr/bin/env bash
# Coordinator. Compiles the circuit and creates zkey_0000. Send r1cs + final ptau + zkey_0000 to contributor #1.
source "$(dirname "$0")/common.sh"; cd "$ROOT"; need "$PTAU_FINAL"
$CIRCOM "$CIRCUIT" --r1cs --wasm --sym -l node_modules -o build
$SNARKJS groth16 setup "$R1CS" "$PTAU_FINAL" "$CER/circuit_0000.zkey"
$SNARKJS zkey verify "$R1CS" "$PTAU_FINAL" "$CER/circuit_0000.zkey"
log_hash "$R1CS" "$PTAU_FINAL" "$CER/circuit_0000.zkey"
