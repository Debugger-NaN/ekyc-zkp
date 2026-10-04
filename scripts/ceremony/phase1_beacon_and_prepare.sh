#!/usr/bin/env bash
# Coordinator, after >=3 phase-1 contributions: phase1_beacon_and_prepare.sh <last.ptau> <beaconHex> [iterExp=10]
# beaconHex = public randomness value announced in advance (see CEREMONY.md), hex string, no 0x.
[ $# -ge 2 ] || { echo "usage: $0 <last.ptau> <beaconHex> [iterExp]"; exit 1; }
source "$(dirname "$0")/common.sh"; IN=$(abs "$1"); BEACON="$2"; EXP="${3:-10}"; cd "$ROOT"; need "$IN"
[[ "$BEACON" =~ ^[0-9a-fA-F]+$ ]] || { echo "beacon must be hex"; exit 1; }
$SNARKJS powersoftau beacon "$IN" "$CER/pot${POWER}_beacon.ptau" "$BEACON" "$EXP" -n="Final Beacon"
$SNARKJS powersoftau prepare phase2 "$CER/pot${POWER}_beacon.ptau" "$PTAU_FINAL" -v
$SNARKJS powersoftau verify "$PTAU_FINAL"
echo "beacon=$BEACON iterExp=$EXP" | tee -a "$CER/transcript.txt"
log_hash "$CER/pot${POWER}_beacon.ptau" "$PTAU_FINAL"
