# sourced by all ceremony scripts. Run scripts from anywhere; paths in args are resolved first.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
POWER=16                                   # 2^16 = 65536 >= 37791 constraints (+ public inputs)
CIRCUIT=circuits/selective_disclosure.circom
CER=build/ceremony
R1CS=build/selective_disclosure.r1cs
PTAU_FINAL=$CER/pot${POWER}_final.ptau
CIRCOM=${CIRCOM:-circom}
SNARKJS="npx snarkjs"
MIN_CONTRIBS=${MIN_CONTRIBS:-3}            # independent contributors (beacon counted separately)
abs()  { realpath -m "$1"; }
need() { [ -f "$1" ] || { echo "missing file: $1" >&2; exit 1; }; }
log_hash() { mkdir -p "$ROOT/$CER"; for f in "$@"; do
  echo "$(date -u +%FT%TZ) $(sha256sum "$f" | cut -d' ' -f1)  $(basename "$f")" | tee -a "$ROOT/$CER/transcript.txt"; done; }
count_contribs() { grep -cE "^\[INFO\].*contribution #|contribution #[0-9]+" <<<"$1" || true; }
