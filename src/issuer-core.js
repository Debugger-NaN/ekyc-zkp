// Issuer: Poseidon Merkle tree (depth 4) over the SPEC leaves, EdDSA-Poseidon signature on the root.
// The issuer NEVER sees holderSecret; it receives only holderCommit = Poseidon(holderSecret) from the holder.
//
// Issue request:  { "holderCommit": "<decimal field element>",
//                   "attributes": { "name", "dob": YYYYMMDD, "nationality", "nid", "address", "university" },
//                   "expiry": YYYYMMDD }
const fs = require("fs");
const { P, ATTRS, toField, randSalt, lib, buildTree, getPath, S } = require("../scripts/common");
const { PQ_SUITE, pqKeygen, pqSignRoot } = require("./crypto-suite");
const MAX_CRED_ID = (1 << 20) - 1;   // credId is the 20-level revocation SMT key (range-checked in the circuit)

async function loadIssuerKeys(dir = "data") {
  const { eddsa, F } = await lib();
  fs.mkdirSync(dir, { recursive: true });
  const edPath = `${dir}/issuer.key`, pqPath = `${dir}/issuer.pq.seed`;
  if (!fs.existsSync(edPath)) fs.writeFileSync(edPath, require("crypto").randomBytes(32).toString("hex"));
  const prv = Buffer.from(fs.readFileSync(edPath, "utf8"), "hex");
  const pub = eddsa.prv2pub(prv);
  const pq = await pqKeygen(fs.existsSync(pqPath) ? fs.readFileSync(pqPath, "utf8") : undefined);
  fs.writeFileSync(pqPath, pq.seed);
  const keys = { prv, pubKey: [F.toObject(pub[0]), F.toObject(pub[1])], pq };
  // public trust anchor (production: on-chain issuer registry)
  fs.writeFileSync(`${dir}/issuer-public.json`, JSON.stringify(S({ eddsaPub: keys.pubKey, pqSuite: PQ_SUITE, pqPub: pq.publicKey }), null, 2));
  return keys;
}

// Sequential credId from data/state.json (sync read-modify-write, atomic rename).
function nextCredId(dir = "data") {
  const f = `${dir}/state.json`;
  const st = fs.existsSync(f) ? JSON.parse(fs.readFileSync(f, "utf8")) : { nextCredId: 1 };
  const id = st.nextCredId;
  if (id > MAX_CRED_ID) throw new Error(`credId space exhausted (circuit/SMT supports 1..${MAX_CRED_ID})`);
  fs.writeFileSync(f + ".tmp", JSON.stringify({ nextCredId: id + 1 }));
  fs.renameSync(f + ".tmp", f);
  return id;
}

function validDate(d) {
  if (!Number.isInteger(d) || d < 19000101 || d > 21001231) return false;
  const m = Math.floor(d / 100) % 100, day = d % 100;
  return m >= 1 && m <= 12 && day >= 1 && day <= 31;
}

function validateRequest(req) {
  if (!req || typeof req !== "object") throw new Error("bad request");
  if ("holderSecret" in req || (req.attributes && "holderSecret" in req.attributes)) throw new Error("holderSecret must never be sent to the issuer");
  let hc; try { hc = BigInt(req.holderCommit); } catch { throw new Error("holderCommit must be a decimal field element"); }
  if (hc <= 0n || hc >= P) throw new Error("holderCommit out of field range");
  const a = req.attributes || {};
  for (const k of ["name", "nationality", "nid", "address", "university"]) if (typeof a[k] !== "string" || !a[k]) throw new Error(`attributes.${k} required`);
  if (!validDate(a.dob)) throw new Error("attributes.dob must be a valid YYYYMMDD integer");
  if (!validDate(req.expiry)) throw new Error("expiry must be a valid YYYYMMDD integer");
  return hc;
}

async function issueCredential(req, keys, { dir = "data" } = {}) {
  const holderCommit = validateRequest(req);
  const { poseidon, eddsa, F } = await lib();
  const a = req.attributes, credId = nextCredId(dir);
  // slot order = ATTRS (SPEC): 0 name,1 dob,2 nationality,3 nid,4 address,5 university,6 holderCommit,7 expiry,8 credId
  const values = [toField(a.name), BigInt(a.dob), toField(a.nationality), toField(a.nid), toField(a.address), toField(a.university), holderCommit, BigInt(req.expiry), BigInt(credId)];
  const salts = values.map(() => randSalt());
  const leaves = values.map((v, i) => F.toObject(poseidon([v, salts[i]])));   // slots 9-15: zero padding leaves
  const { levels, root } = await buildTree(leaves);

  const sig = eddsa.signPoseidon(keys.prv, F.e(root));          // verified IN-CIRCUIT by the proof
  const pqSignature = await pqSignRoot(keys.pq.secretKey, root);
  return S({
    attrOrder: ATTRS, attributes: { ...a, expiry: req.expiry, credId }, fields: values, salts,
    paths: ATTRS.map((_, i) => getPath(levels, i)),              // sibling hashes only; directions are circuit constants
    merkleRoot: root, credId, expiry: req.expiry,
    signature: { R8: [F.toObject(sig.R8[0]), F.toObject(sig.R8[1])], S: sig.S },
    issuerPubKey: keys.pubKey,
    // ML-DSA-65: the root is private in proofs, so verifiers cannot check this. WALLET checks it at import only.
    pq: { suite: PQ_SUITE, publicKey: keys.pq.publicKey, signature: pqSignature, use: "wallet-import-verification-only" },
  });
}
module.exports = { loadIssuerKeys, issueCredential, validateRequest };