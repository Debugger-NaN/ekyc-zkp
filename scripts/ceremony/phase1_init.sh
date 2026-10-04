#!/usr/bin/env bash
# Coordinator. Creates the empty Powers of Tau (power 16). Send the output to contributor #1.
source "$(dirname "$0")/common.sh"; cd "$ROOT"; mkdir -p "$CER"
$SNARKJS powersoftau new bn128 $POWER "$CER/pot${POWER}_0000.ptau" -v
log_hash "$CER/pot${POWER}_0000.ptau"
