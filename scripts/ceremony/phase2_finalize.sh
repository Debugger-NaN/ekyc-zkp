#!/usr/bin/env bash
# Coordinator, after >=3 phase-2 contributions: phase2_finalize.sh <last.zkey> <beaconHex> [iterExp=10]
[ $# -ge 2 ] || { echo "usage: $0 <last.zkey> <beaconHex> [iterExp]"; exit 1; }
source "$(dirname "$0")/common.sh"; IN=$(abs "$1"); BEACON="$2"; EXP="${3:-10}"; cd "$ROOT"
need "$IN"; need "$R1CS"; need "$PTAU_FINAL"
[[ "$BEACON" =~ ^[0-9a-fA-F]+$ ]] || { echo "beacon must be hex"; exit 1; }
$SNARKJS zkey beacon "$IN" build/circuit_final.zkey "$BEACON" "$EXP" -n="Final Beacon phase2"
$SNARKJS zkey verify "$R1CS" "$PTAU_FINAL" build/circuit_final.zkey        # against r1cs AND final ptau
$SNARKJS zkey export verificationkey build/circuit_final.zkey build/verification_key.json
$SNARKJS zkey export solidityverifier build/circuit_final.zkey contracts/Groth16Verifier.sol
echo "beacon2=$BEACON iterExp=$EXP" | tee -a "$CER/transcript.txt"
log_hash build/circuit_final.zkey build/verification_key.json contracts/Groth16Verifier.sol
