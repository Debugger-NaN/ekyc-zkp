// Crypto-agility layer: the issuer signs the Merkle root with a HYBRID of
//   - EdDSA-Poseidon (BabyJubJub, fast, zk-friendly, NOT quantum-safe)
//   - ML-DSA-65 (FIPS 204 / Dilithium3, quantum-safe lattice signature)
// A verifier in "requirePQ" mode accepts only if BOTH verify, so forging needs breaking both.
const { lib } = require("./../scripts/common");
const PQ_SUITE = "ml-dsa-65";
const DOMAIN = Buffer.from("ekyc-root-v1:");

let _ml;
async function mldsa() { return (_ml ||= (await import("@noble/post-quantum/ml-dsa.js")).ml_dsa65); }

const rootBytes = (root) => Buffer.concat([DOMAIN, Buffer.from(BigInt(root).toString(16).padStart(64, "0"), "hex")]);

async function pqKeygen(seedHex) {
  const a = await mldsa();
  const seed = seedHex ? Buffer.from(seedHex, "hex") : require("crypto").randomBytes(32);
  const { publicKey, secretKey } = a.keygen(seed);
  return { seed: seed.toString("hex"), publicKey: Buffer.from(publicKey).toString("hex"), secretKey };
}
async function pqSignRoot(secretKey, root) {
  const a = await mldsa();
  return Buffer.from(a.sign(rootBytes(root), secretKey)).toString("hex");
}
async function pqVerifyRoot(publicKeyHex, sigHex, root) {
  try { const a = await mldsa(); return a.verify(Buffer.from(sigHex, "hex"), rootBytes(root), Buffer.from(publicKeyHex, "hex")); }
  catch { return false; }
}
async function eddsaVerifyRoot(pubKey, sig, root) {
  const { eddsa, F } = await lib();
  return eddsa.verifyPoseidon(F.e(BigInt(root)), { R8: sig.R8.map((x) => F.e(BigInt(x))), S: BigInt(sig.S) }, pubKey.map((x) => F.e(BigInt(x))));
}
module.exports = { PQ_SUITE, pqKeygen, pqSignRoot, pqVerifyRoot, eddsaVerifyRoot };
