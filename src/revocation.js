// Revocation registry: circomlibjs sparse Merkle tree (Poseidon) keyed by credId, 20 levels.
// State = list of revoked credIds in data/revocation.json; the tree is rebuilt on load (root is order-independent).
const fs = require("fs");
const { newMemEmptyTrie } = require("circomlibjs");
const LEVELS = 20, MAX_CRED_ID = (1 << LEVELS) - 1;

async function load(dir = "data") {
  const f = `${dir}/revocation.json`;
  const revoked = fs.existsSync(f) ? JSON.parse(fs.readFileSync(f, "utf8")).revoked : [];
  const tree = await newMemEmptyTrie();
  for (const id of revoked) await tree.insert(BigInt(id), 1n);
  return { tree, revoked, f, dir };
}
const rootOf = (t) => t.F.toObject(t.root).toString();
function save(st) {
  fs.mkdirSync(st.dir, { recursive: true });
  fs.writeFileSync(st.f + ".tmp", JSON.stringify({ revoked: st.revoked, root: rootOf(st.tree) }, null, 2));
  fs.renameSync(st.f + ".tmp", st.f);
}

/** Revoke credId; returns the new root (decimal string) to publish via EKYCRegistry.setRevocationRoot. */
async function revoke(credId, { dir = "data" } = {}) {
  credId = Number(credId);
  if (!Number.isInteger(credId) || credId < 1 || credId > MAX_CRED_ID) throw new Error(`credId must be in [1, ${MAX_CRED_ID}]`);
  const st = await load(dir);
  if (!st.revoked.includes(credId)) { await st.tree.insert(BigInt(credId), 1n); st.revoked.push(credId); st.revoked.sort((a, b) => a - b); save(st); }
  return rootOf(st.tree);
}

async function root({ dir = "data" } = {}) { return rootOf((await load(dir)).tree); }

/** Circuit inputs { revocationRoot, siblings[20], oldKey, oldValue, isOld0 }; throws if credId is revoked. */
async function getNonMembershipProof(credId, { dir = "data" } = {}) {
  const { tree } = await load(dir), F = tree.F;
  const r = await tree.find(BigInt(credId));
  if (r.found) throw new Error(`credId ${credId} is revoked`);
  const siblings = r.siblings.map((x) => F.toObject(x));
  if (siblings.length > LEVELS) throw new Error("SMT path deeper than 20 levels");
  while (siblings.length < LEVELS) siblings.push(0n);
  return {
    revocationRoot: rootOf(tree).toString(),
    siblings: siblings.map(String),
    oldKey: r.isOld0 ? "0" : F.toObject(r.notFoundKey).toString(),
    oldValue: r.isOld0 ? "0" : F.toObject(r.notFoundValue).toString(),
    isOld0: r.isOld0 ? "1" : "0",
  };
}
module.exports = { revoke, getNonMembershipProof, root, LEVELS, MAX_CRED_ID };