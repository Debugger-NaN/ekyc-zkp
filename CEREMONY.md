# Trusted-setup ceremony (Groth16, BN128, power 16, 37,791 constraints)
All scripts: `scripts/ceremony/`. Same circom 2.1.9 + `package-lock.json` everywhere. Contributors: 3+ people on 3+ separate machines.

| # | Who | Command |
|---|-----|---------|
| 1 | Coordinator | `phase1_init.sh` → send `pot16_0000.ptau` |
| 2 | Contributor 1..3 (sequential) | `phase1_contribute.sh <in> <out> <name>` → pass `<out>` on |
| 3 | Coordinator | `phase1_beacon_and_prepare.sh <last.ptau> <beaconHex>` |
| 4 | Coordinator | `phase2_setup.sh` → send r1cs + `pot16_final.ptau` + `circuit_0000.zkey` |
| 5 | Contributor 1..3 (sequential) | `phase2_contribute.sh <in> <out> <name>` |
| 6 | Coordinator | `phase2_finalize.sh <last.zkey> <beaconHex>` → vkey + `contracts/Groth16Verifier.sol` |
| 7 | Anyone | `verify_all.sh` |

**Files between machines:** phase 1 only the `.ptau` (hundreds of MB; use scp/USB). Phase 2: `selective_disclosure.r1cs` and `pot16_final.ptau` once, then the `.zkey` hop to hop. Never send entropy. Each recipient checks the sender's published sha256 before contributing.

**Beacon:** pick a public randomness source nobody can predict or grind at announcement time, e.g. the hash of a Bitcoin block at a height ~24h ahead, or a drand round at a fixed future time. Commit the source and height/round in a signed git commit/timestamp BEFORE it exists; after it exists, use its hash (hex, no `0x`) as `<beaconHex>`. Use a new future value for phase 2.

**Transcript hashes:** every script appends `time sha256 file` to `build/ceremony/transcript.txt`. Each contributor posts their own output hash on a channel they control (GitHub gist, personal site, signed message) right after contributing. Coordinator commits the transcript, beacon announcement, and final hashes (r1cs, ptau, zkey, vkey, verifier) and tags the release; `verify_all.sh` must reproduce them.
