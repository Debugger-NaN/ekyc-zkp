#!/usr/bin/env bash
# Anyone (auditor, examiner): re-checks the whole ceremony from the public files.
source "$(dirname "$0")/common.sh"; cd "$ROOT"
need "$R1CS"; need "$PTAU_FINAL"; need build/circuit_final.zkey; need build/verification_key.json; need contracts/Groth16Verifier.sol
echo "== r1cs rebuilt from source must match published hash =="
$CIRCOM "$CIRCUIT" --r1cs -l node_modules -o "$CER/recheck" >/dev/null
[ "$(sha256sum < "$CER/recheck/selective_disclosure.r1cs")" = "$(sha256sum < "$R1CS")" ] || { echo "FAIL: r1cs differs from circuit source"; exit 1; }
echo "== phase 1: full ptau transcript =="
P1=$($SNARKJS powersoftau verify "$PTAU_FINAL" 2>&1 | tee /dev/stderr)
[ "$(count_contribs "$P1")" -ge $((MIN_CONTRIBS+1)) ] || { echo "FAIL: <$MIN_CONTRIBS contributors + beacon in ptau"; exit 1; }
echo "== phase 2: zkey vs r1cs and final ptau =="
P2=$($SNARKJS zkey verify "$R1CS" "$PTAU_FINAL" build/circuit_final.zkey 2>&1 | tee /dev/stderr)
[ "$(count_contribs "$P2")" -ge $((MIN_CONTRIBS+1)) ] || { echo "FAIL: <$MIN_CONTRIBS contributors + beacon in zkey"; exit 1; }
echo "== exported artefacts match the final zkey =="
$SNARKJS zkey export verificationkey build/circuit_final.zkey "$CER/vk_recheck.json" >/dev/null
$SNARKJS zkey export solidityverifier build/circuit_final.zkey "$CER/Verifier_recheck.sol" >/dev/null
diff -q "$CER/vk_recheck.json" build/verification_key.json
diff -q "$CER/Verifier_recheck.sol" contracts/Groth16Verifier.sol
echo "== hashes to compare with the published transcript =="
log_hash "$R1CS" "$PTAU_FINAL" build/circuit_final.zkey build/verification_key.json contracts/Groth16Verifier.sol
echo "ALL CHECKS PASSED"
