# Privacy-Preserving Selectively Disclosed eKYC (Merkle Tree + zk-SNARK)

Implementation of the system in *"A Privacy-Preserving Selectively Disclosed eKYC System Using Merkle Tree and
Zero-Knowledge Proofs"* (Ahmed et al., APCC 2025).

## What it does
A student/citizen holds a credential with 6 attributes (name, birth year, nationality, national ID, address,
university). To pass KYC they reveal **name + university** and prove **age >= 18** without revealing the birth year,
using **one** Groth16 proof instead of one Merkle proof per attribute.

| Paper element | File |
|---|---|
| Alg. 1 – salted Poseidon leaves, Merkle tree (depth 3, 8 leaves), EdDSA-signed root | `scripts/issuer.js` |
| Alg. 2 – R1CS circuit: 3 Merkle inclusions + age check (+ nonce) | `circuits/selective_disclosure.circom`, `scripts/holder.js` |
| Alg. 3 – verify signature, Groth16 proof, root consistency | `scripts/verifier.js` |
| Solidity verifier (exported) + issuer registry / root anchoring | `contracts/Groth16Verifier.sol`, `contracts/EKYCRegistry.sol` |
| Table V replay protection (unique nonce per proof) | public `nonce` signal + `usedNonce` in the registry |

## Run
Prereqs: Node 20+, [circom 2.1.x](https://docs.circom.io/getting-started/installation/) on PATH, `openssl`.

```bash
npm install
npm run demo          # issue -> prove -> verify, hybrid PQ signatures required (prebuilt keys in build/)
# optional: rebuild circuit + trusted setup (regenerates keys and contracts/Groth16Verifier.sol)
npm run setup
```
`npm run prove -- <nonce> <minAge> <currentYear>` and `npm run verify -- <nonce> <minAge>` accept custom values.

Public signals order: `[merkleRoot, currentYear, minAge, nameValue, uniValue, nonce]`.

## v2 additions

### 1. Wallet UI abstraction
- `src/wallet-core.mjs` – UI-free wallet (browser + Node). Storage, prover and **consent** are injected, so the same core
  powers the CLI (`scripts/holder.js`), the browser UI and tests. Credentials are stored **AES-256-GCM encrypted**
  (PBKDF2, 250k iterations). The core shows *reveals / proves / hidden* to a consent callback before any proof is computed.
- `wallet/index.html` – browser wallet: unlock, import credential, review-and-approve screen, proof generated locally
  with snarkjs (wasm), result shown. Try it: `npm run issue && npm run gateway:demo`, open http://localhost:3000/wallet,
  passphrase of your choice, "Load demo credential", "Start verification".

### 2. Post-quantum crypto (what is and isn't covered)
- **Covered:** issuer signature is now **hybrid EdDSA + ML-DSA-65 (FIPS 204)** (`src/crypto-suite.js`). The gateway
  requires both by default (`REQUIRE_PQ=0` to relax); stripping or forging the PQ signature is rejected (tested).
  Merkle/Poseidon commitments are hash-based.
- **Not covered:** the **Groth16 proof is pairing-based and breakable by a large quantum computer** (soundness, and
  the on-chain verifier). Full PQ needs a hash-based proof system (STARK, e.g. RISC Zero/Winterfell/Cairo). The
  verifier logic is isolated in `src/verify-core.js` so a backend can be swapped, but that backend is not written here.
- ML-DSA signatures are ~3.3 KB, so they are verified off-chain in the gateway, not in the Solidity contract.

### 3. Legacy integration
- `gateway/server.js` – REST gateway: `GET /api/kyc/challenge`, `POST /api/kyc/verify`. Legacy callers need no crypto:
  JSON or XML (`Accept: application/xml`), optional `expect: {name, university}` to cross-check against the legacy
  DB record, optional `LEGACY_WEBHOOK_URL` callback. Sessions are single-use with a 5-minute TTL. See `legacy/curl-examples.sh`.
- `scripts/import-legacy.js` – bulk-issues credentials from an existing customer CSV; column mapping in
  `legacy/mapping.json` (`npm run import:legacy`).
- **Security fix vs v1:** the verifier now checks the issuer's key against a trust anchor (`data/issuer-public.json`;
  in production the on-chain registry). v1 trusted whatever key came in the presentation, so anyone could self-issue.

`npm test` runs 13 end-to-end checks (replay, nonce swap, PQ downgrade/forgery, self-issued credential, legacy
mismatch, XML, consent decline, underage, wallet encryption).

## Measured here (sandbox CPU, not the paper's hardware)
2,923 constraints; proof gen ~1.4 s (incl. witness + wasm load); Groth16 verify ~0.2–0.3 s; proof ~800 B JSON.
Negative tests pass: wrong nonce, tampered public input, and policy failure (minAge 40) are all rejected.

## Deviations / caveats
- The paper's prose says ZoKrates in Remix, but its Algorithms 2–3 use `snarkjs groth16` and Poseidon/EdDSA
  (circom-style), so I built it with circom + snarkjs. Same scheme, different toolchain.
- The keys in `build/` come from a **single-party demo ceremony** (toxic waste not properly destroyed). Do a real
  multi-party ceremony before any real use.
- Padding leaves are `0`; the current year is a public input supplied by the prover, so the verifier must
  check it (scripts/verifier.js checks nonce and minAge; add a currentYear check for production).
- The `EKYCRegistry` contract compiles but I did not deploy it or measure gas; the paper's gas figures (e.g. 20k gas to
  verify a Groth16 proof) look too low for a real EVM, since pairing checks alone cost far more.
- The browser wallet page was **not run in a real browser** here (no browser in the sandbox). Its logic is the tested `wallet-core`, and I checked the page's script syntax and that the gateway serves all its assets, but expect to fix small UI glitches.
- Gateway has no TLS, auth or rate limiting; put it behind a reverse proxy. DID/SSI resolution and biometric KYC are still out of scope.
