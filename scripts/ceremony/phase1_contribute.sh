#!/usr/bin/env bash
# Each contributor, on their OWN machine: phase1_contribute.sh <in.ptau> <out.ptau> <name>
# snarkjs prompts for random text (mixed with system randomness). Do not pass entropy on the command line.
[ $# -eq 3 ] || { echo "usage: $0 <in.ptau> <out.ptau> <name>"; exit 1; }
source "$(dirname "$0")/common.sh"; IN=$(abs "$1"); OUT=$(abs "$2"); NAME="$3"; cd "$ROOT"; need "$IN"
$SNARKJS powersoftau contribute "$IN" "$OUT" --name="$NAME" -v
$SNARKJS powersoftau verify "$OUT"
log_hash "$OUT"
echo "Publish the sha256 above, then securely destroy the entropy/toxic waste (reboot / wipe)."
