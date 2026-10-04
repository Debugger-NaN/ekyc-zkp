// Verifier core (SPEC). The Groth16 proof is the ONLY evidence: root and signatures are private and never seen here.
// (ML-DSA-65 is checked by the wallet at import, not here.)
const snarkjs = require("snarkjs");
const fs = require("fs");
const { toField } = require("../scripts/common");

// Public-signal order (SPEC, 10): [nullifier, issuerAx, issuerAy, today, minAge, nameValue, uniValue, verifierId, nonce, revocationRoot]
const SIG = { nullifier: 0, issuerAx: 1, issuerAy: 2, today: 3, minAge: 4, nameValue: 5, uniValue: 6, verifierId: 7, nonce: 8, revocationRoot: 9 };
const N_SIGNALS = 10;
const ymdUTC = (d) => d.getUTCFullYear() * 10000 + (d.getUTCMonth() + 1) * 100 + d.getUTCDate();
const eq = (a, b) => { try { return BigInt(a) === BigInt(b); } catch { return false; } };   // fail closed on undefined/garbage

/**
 * opts: { vk, trusted:{eddsaPub:[Ax,Ay]}, expectedMinAge, expectedVerifierId, expectedNonce, expectedRevocationRoot,
 *         usedNullifiers: Set<string>, expect?:{name,university}, now?: Date }
 * Returns { ok, checks, claims, nullifier } — the CALLER must persist `nullifier` when ok.
 */
async function verifyPresentation({ proof, publicSignals }, opts) {
  const { vk, trusted, expectedNonce, expectedMinAge, expectedVerifierId, expectedRevocationRoot, usedNullifiers, expect = {}, now = new Date() } = opts;
  const checks = [];
  const step = (name, ok, detail) => { checks.push({ name, ok: !!ok, detail }); return !!ok; };
  const fail = () => ({ ok: false, checks, claims: null, nullifier: null });
  const pub = Array.isArray(publicSignals) ? publicSignals.map(String) : [];

  // 1. Groth16 over exactly the 10 public signals
  let proofOk = false;
  if (pub.length === N_SIGNALS && proof) { try { proofOk = await snarkjs.groth16.verify(vk, pub, proof); } catch { proofOk = false; } }
  if (!step("Groth16 proof (10 public signals)", proofOk)) return fail();

  // 2. issuer key inside the circuit's EdDSA check == our trust anchor
  if (!step("issuer (Ax,Ay) matches trust anchor", trusted && eq(pub[SIG.issuerAx], trusted.eddsaPub[0]) && eq(pub[SIG.issuerAy], trusted.eddsaPub[1]))) return fail();

  // 3. today = yesterday or today by OUR UTC clock (SPEC)
  const okDays = [ymdUTC(now), ymdUTC(new Date(now.getTime() - 864e5))];
  if (!step("today within clock window (UTC yesterday|today)", okDays.some((d) => eq(pub[SIG.today], d)), `accepted ${okDays.join("|")}`)) return fail();

  // 4-7. policy / session bindings
  if (!step("minAge equals policy", eq(pub[SIG.minAge], expectedMinAge))) return fail();
  if (!step("verifierId is ours", eq(pub[SIG.verifierId], expectedVerifierId))) return fail();
  if (!step("nonce equals session nonce", eq(pub[SIG.nonce], expectedNonce), "replay protection")) return fail();
  if (!step("revocationRoot equals registry's current root", eq(pub[SIG.revocationRoot], expectedRevocationRoot))) return fail();

  // 8. nullifier unused (canonical decimal form)
  const nullifier = BigInt(pub[SIG.nullifier]).toString();
  if (!step("nullifier not used before", !!usedNullifiers && !usedNullifiers.has(nullifier), "caller stores it on success")) return fail();

  // optional: compare proven name/university fields with a legacy record (both are public signals, so they ARE proven)
  if (expect.name !== undefined && !step("name matches legacy record", eq(pub[SIG.nameValue], toField(expect.name)))) return fail();
  if (expect.university !== undefined && !step("university matches legacy record", eq(pub[SIG.uniValue], toField(expect.university)))) return fail();

  // claims = only what the circuit proved (age >= minAge as of `today`, not expired, not revoked, issuer-signed, holder-bound)
  return { ok: true, checks, nullifier, claims: { minAgeProven: Number(pub[SIG.minAge]), nameField: pub[SIG.nameValue], universityField: pub[SIG.uniValue] } };
}
const loadVk = () => JSON.parse(fs.readFileSync("build/verification_key.json"));
const loadTrusted = (dir = "data") => JSON.parse(fs.readFileSync(`${dir}/issuer-public.json`));
module.exports = { verifyPresentation, loadVk, loadTrusted, SIG, ymdUTC };