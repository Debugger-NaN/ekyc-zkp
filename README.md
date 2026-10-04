# 🛡️ Privacy-Preserving Selectively Disclosed eKYC System
* **Threat**: Alice gives her credential JSON file to Bob so Bob can pass an age check.
* **Defense**: The credential contains leaf 6: $\text{holderCommit} = \text{Poseidon}(\text{holderSecret})$. To generate a valid Groth16 proof, the circuit demands the preimage `holderSecret`. Giving Bob the credential file without the secret renders it useless; giving Bob the secret transfers complete ownership of all Alice's credentials and nullifiers.

### 3. Self-Issuance / Impersonation
* **Threat**: An attacker creates their own keys, issues a fake credential stating they are 25 years old, and presents it.
* **Defense**: The verifier checks public signals `(issuerAx, issuerAy)` against the authorized trust anchor (`data/issuer-public.json` or the on-chain `issuerKeys` mapping in `EKYCRegistry.sol`). Proofs with unknown issuer keys are immediately rejected.

### 4. Front-Running on Ethereum
* **Threat**: In an on-chain deployment, an attacker watches the Ethereum mempool for a user's `verifyCredentialProof()` transaction, extracts the proof, and submits it from their own address with a higher gas price.
* **Defense**: The circuit requires public input `verifierId`, which `EKYCRegistry.sol` strictly enforces:
  ```solidity
  require(pub[7] == uint256(uint160(msg.sender)), "verifierId != caller");
  ```
  The front-runner's transaction fails because their `msg.sender` does not match the proof's `verifierId`.

### 5. Biometric Deepfakes & Replay
* **Threat**: An attacker holds up a tablet playing a video of someone else or uses a 3D avatar.
* **Defense**: Temporal micro-motion flux analysis rejects static frames, high-frequency digital displays, and synthetic video loops. Face verification requires interactive temporal responses (blinking/movement).

---

## ❓ Frequently Asked Questions (FAQ) & Troubleshooting

#### Q1: Does the verifier ever see my Date of Birth?
**No.** Your Date of Birth is passed as a **private witness input** to the client-side circuit. It is never emitted in public signals, never recorded in the proof JSON, and never sent over the network. The verifier only learns that `dob <= today - minAge * 10000` is true.

#### Q2: What happens if my credential is revoked?
When an issuer revokes your credential, your `credId` is added to the 20-level Revocation Sparse Merkle Tree (SMT). When you attempt to present your credential, your wallet queries `/api/revocation/:credId` to obtain a non-membership proof. Because your `credId` is present in the tree, the server returns `403 Revoked`, and the circuit cannot compute a valid proof.

#### Q3: Why is Groth16 used instead of STARKs?
Groth16 generates the smallest proofs (~800 bytes) and lowest verification gas costs on Ethereum (~250k gas). While STARKs are naturally post-quantum, STARK proofs are significantly larger (40–100 KB), making client-side in-browser generation and on-chain verification significantly more resource-intensive. Our hybrid model uses Groth16 for succinct disclosure combined with ML-DSA-65 for quantum-safe issuance.

#### Q4: Why do I see port conflicts on port 3000?
If you already have a service running on port 3000, specify an alternative port using the environment variable:
```bash
PORT=3055 npm start
```

#### Q5: Can I re-compile the Circom circuits myself?
Yes! If you have `circom 2.1.9` installed on your PATH:
```bash
npm run setup
```
This re-compiles `circuits/selective_disclosure.circom`, generates the R1CS constraints, produces the WASM calculator, and rebuilds the keys in `build/`.

---

## 📜 References & Citation

If you use this system or build upon its architecture in academic research or commercial products, please cite the foundational research paper:

```bibtex
@inproceedings{ahmed2025ekyc,
  author    = {Ahmed, et al.},
  title     = {A Privacy-Preserving Selectively Disclosed eKYC System Using Merkle Tree and Zero-Knowledge Proofs},
  booktitle = {Proceedings of the Asia-Pacific Conference on Communications (APCC)},
  year      = {2025}
}
```

---

## 📄 License

This project is open-source software.