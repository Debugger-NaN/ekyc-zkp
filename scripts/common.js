const crypto = require("crypto");
const { buildPoseidon, buildEddsa } = require("circomlibjs");

const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const DEPTH = 4;   // 16 leaves
// SPEC slot order (index = leaf position, hard-coded in the circuit). Slots 9-15 are zero padding leaves.
const ATTRS = ["name", "dob", "nationality", "nid", "address", "university", "holderCommit", "expiry", "credId"];

// string / number -> field element (SHA-256 mod p for strings; ints used directly)
function toField(v) {
  if (typeof v === "number" || typeof v === "bigint") return BigInt(v);
  return BigInt("0x" + crypto.createHash("sha256").update(String(v)).digest("hex")) % P;
}
const randSalt = () => BigInt("0x" + crypto.randomBytes(31).toString("hex"));

let _p, _e;
async function lib() {
  if (!_p) { _p = await buildPoseidon(); _e = await buildEddsa(); }
  return { poseidon: _p, eddsa: _e, F: _p.F };
}

async function buildTree(leaves) {
  const { poseidon, F } = await lib();
  const size = 1 << DEPTH;
  if (leaves.length > size) throw new Error("too many leaves");
  const levels = [leaves.concat(Array(size - leaves.length).fill(0n))];
  while (levels[levels.length - 1].length > 1) {
    const prev = levels[levels.length - 1], next = [];
    for (let i = 0; i < prev.length; i += 2) next.push(F.toObject(poseidon([prev[i], prev[i + 1]])));
    levels.push(next);
  }
  return { levels, root: levels[levels.length - 1][0] };
}
// Sibling hashes only: path directions are fixed by slot index and hard-coded in the circuit.
function getPath(levels, index) {
  const pathElements = [];
  let idx = index;
  for (let l = 0; l < DEPTH; l++) { pathElements.push(levels[l][idx ^ 1]); idx >>= 1; }
  return pathElements;
}
const S = (o) => JSON.parse(JSON.stringify(o, (_, v) => (typeof v === "bigint" ? v.toString() : v)));
module.exports = { P, DEPTH, ATTRS, toField, randSalt, lib, buildTree, getPath, S };