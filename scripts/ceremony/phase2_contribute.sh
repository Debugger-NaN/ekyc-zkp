#!/usr/bin/env bash
# Each contributor, own machine: phase2_contribute.sh <in.zkey> <out.zkey> <name>
# Needs build/selective_disclosure.r1cs and build/ceremony/pot16_final.ptau from the coordinator
# (check their sha256 against the published transcript first).
[ $# -eq 3 ] || { echo "usage: $0 <in.zkey> <out.zkey> <name>"; exit 1; }
source "$(dirname "$0")/common.sh"; IN=$(abs "$1"); OUT=$(abs "$2"); NAME="$3"; cd "$ROOT"
need "$IN"; need "$R1CS"; need "$PTAU_FINAL"
$SNARKJS zkey contribute "$IN" "$OUT" --name="$NAME" -v
$SNARKJS zkey verify "$R1CS" "$PTAU_FINAL" "$OUT"
log_hash "$OUT"
echo "Publish the sha256 above, then securely destroy the entropy/toxic waste."
