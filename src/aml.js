// Zero-Knowledge AML & Sanctions Registry
// Implements cryptographic non-membership proofs over an OFAC/UN/PEP sanctions Sparse Merkle Tree (SMT).
// A user proves they are NOT on the sanctions list without revealing their Name or Date of Birth.

const fs = require("fs");
const path = require("path");
const { newMemEmptyTrie } = require("circomlibjs");
const { toField, lib } = require("../scripts/common");

const LEVELS = 20;
const MAX_KEY = (1n << BigInt(LEVELS)) - 1n;

// Default test sanctions list (simulating OFAC Specially Designated Nationals & PEPs)
const DEFAULT_SANCTIONS = [
  { name: "VLADIMIR ILLYICH", dob: 19700101, reason: "OFAC SDN Test Entry #1" },
  { name: "JOHN CORRUPTUS", dob: 19650315, reason: "PEP Bribery Watchlist" },
  { name: "ANONYMOUS FRAUDSTER", dob: 19821130, reason: "Interpol Red Notice Mock" }
];

async function computeIdentityKey(name, dob) {
  const { poseidon, F } = await lib();
  const nameField = toField(name.trim().toUpperCase());
  const dobField = BigInt(dob);
  const hash = F.toObject(poseidon([nameField, dobField]));
  return (BigInt(hash) % MAX_KEY) + 1n;
}

async function load(dir = "data") {
  const f = path.join(dir, "sanctions.json");
  let records = DEFAULT_SANCTIONS;
  if (fs.existsSync(f)) {
    try { records = JSON.parse(fs.readFileSync(f, "utf8")).sanctions || DEFAULT_SANCTIONS; } catch { }
  } else {
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(f, JSON.stringify({ sanctions: DEFAULT_SANCTIONS }, null, 2));
  }

  const tree = await newMemEmptyTrie();
  for (const item of records) {
    const key = await computeIdentityKey(item.name, item.dob);
    await tree.insert(key, 1n);
  }

  return { tree, records, f, dir };
}

const rootOf = (t) => t.F.toObject(t.root).toString();

async function root({ dir = "data" } = {}) {
  const st = await load(dir);
  return rootOf(st.tree);
}

/**
 * Returns a cryptographic non-membership proof proving identityKey is NOT in the sanctions tree.
 * Throws if the identity is found on the sanctions list!
 */
async function getNonMembershipProof(identityKey, { dir = "data" } = {}) {
  const { tree } = await load(dir);
  const F = tree.F;
  const key = BigInt(identityKey);
  const r = await tree.find(key);

  if (r.found) {
    throw new Error("Identity matches an entry on the AML/Sanctions watchlist!");
  }

  const siblings = r.siblings.map((x) => F.toObject(x));
  while (siblings.length < LEVELS) siblings.push(0n);

  return {
    sanctionsRoot: rootOf(tree).toString(),
    key: key.toString(),
    siblings: siblings.slice(0, LEVELS).map(String),
    oldKey: r.isOld0 ? "0" : F.toObject(r.notFoundKey).toString(),
    oldValue: r.isOld0 ? "0" : F.toObject(r.notFoundValue).toString(),
    isOld0: r.isOld0 ? "1" : "0",
  };
}

module.exports = {
  load,
  root,
  computeIdentityKey,
  getNonMembershipProof,
  LEVELS,
  DEFAULT_SANCTIONS
};
