// Wallet abstraction layer. Isomorphic (browser + Node): no UI, no fs, no snarkjs/circomlibjs import.
// Injected: storage, prover(input), poseidon(bigint[])->bigint|field, pqVerify(pubHex, sigHex, rootDec)->bool,
//           trusted = { eddsaPub:[Ax,Ay], pqPub } (issuer trust anchor), consent callback (per present()).

export class MemoryStorage { constructor() { this.m = new Map(); } async get(k) { return this.m.get(k) ?? null; } async set(k, v) { this.m.set(k, v); } }
export class LocalStorageBackend { async get(k) { return localStorage.getItem(k); } async set(k, v) { localStorage.setItem(k, v); } }

const enc = new TextEncoder(), dec = new TextDecoder();
const b64 = (u8) => btoa(String.fromCharCode(...new Uint8Array(u8)));
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

// SPEC leaf positions: hard-coded constants (same as the circuit). Slots 9-15 are zero padding.
const SLOT = Object.freeze({ name: 0, dob: 1, nationality: 2, nid: 3, address: 4, university: 5, holderCommit: 6, expiry: 7, credId: 8 });
const SPEC_ORDER = Object.keys(SLOT), DEPTH = 4, REV_LEVELS = 20;
const same = (a, b) => { try { return BigInt(a) === BigInt(b); } catch { return false; } };

async function deriveKey(pass, salt) {
  const base = await crypto.subtle.importKey("raw", enc.encode(pass), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({ name: "PBKDF2", salt, iterations: 250000, hash: "SHA-256" }, base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}

export class Wallet {
  #holderSecret = null;   // private field: lives only in memory + inside the AES-GCM blob; no getter, never exported

  constructor({ storage, prover, poseidon, pqVerify, trusted, key = "ekyc-wallet-v2" }) {
    if (!poseidon || !pqVerify || !trusted?.eddsaPub || !trusted?.pqPub) throw new Error("wallet needs poseidon, pqVerify and the issuer trust anchor");
    Object.assign(this, { storage, prover, pqVerify, trusted, storeKey: key });
    this.H = (a) => BigInt(poseidon(a));
    this.creds = null; this.pass = null;
  }

  async unlock(pass) {
    const raw = await this.storage.get(this.storeKey);
    if (!raw) {   // first run: generate holderSecret locally (31 bytes < field modulus) and persist it encrypted
      const b = crypto.getRandomValues(new Uint8Array(31));
      this.#holderSecret = BigInt("0x" + [...b].map((x) => x.toString(16).padStart(2, "0")).join(""));
      this.creds = {}; this.pass = pass; await this._save(); return true;
    }
    const { salt, iv, ct } = JSON.parse(raw);
    try {
      const k = await deriveKey(pass, unb64(salt));
      const d = JSON.parse(dec.decode(await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(iv) }, k, unb64(ct))));
      this.#holderSecret = BigInt(d.holderSecret); this.creds = d.creds; this.pass = pass; return true;
    } catch { return false; }   // wrong passphrase
  }
  async _save() {
    const salt = crypto.getRandomValues(new Uint8Array(16)), iv = crypto.getRandomValues(new Uint8Array(12));
    const plain = JSON.stringify({ holderSecret: this.#holderSecret.toString(), creds: this.creds });
    const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, await deriveKey(this.pass, salt), enc.encode(plain));
    await this.storage.set(this.storeKey, JSON.stringify({ salt: b64(salt), iv: b64(iv), ct: b64(ct) }));
  }
  _need() { if (!this.creds) throw new Error("wallet locked"); }

  /** holderCommit = Poseidon(holderSecret): the ONLY thing sent to the issuer (decimal string). */
  holderCommit() { this._need(); return this.H([this.#holderSecret]).toString(); }

  /** Import: trust anchor, ML-DSA-65 on the root (the verifier can no longer check it), holder binding, Merkle paths. */
  async addCredential(cred) {
    this._need(); const t = this.trusted, f = cred.fields;
    if (cred.attrOrder?.join() !== SPEC_ORDER.join()) throw new Error("credential slot layout differs from SPEC");
    if (!same(cred.issuerPubKey?.[0], t.eddsaPub[0]) || !same(cred.issuerPubKey?.[1], t.eddsaPub[1])) throw new Error("issuer EdDSA key is not the trusted issuer");
    if (!cred.pq || cred.pq.publicKey !== t.pqPub) throw new Error("ML-DSA key is not the trusted issuer's");
    if (!(await this.pqVerify(cred.pq.publicKey, cred.pq.signature, cred.merkleRoot))) throw new Error("ML-DSA-65 signature on root is invalid");
    if (!same(f[SLOT.holderCommit], this.H([this.#holderSecret]))) throw new Error("holderCommit != Poseidon(holderSecret): not issued to this wallet");
    for (const [name, i] of Object.entries(SLOT)) {      // every path must lead to the signed root (fixed direction bits)
      let cur = this.H([BigInt(f[i]), BigInt(cred.salts[i])]);
      for (let l = 0; l < DEPTH; l++) { const s = BigInt(cred.paths[i][l]); cur = (i >> l) & 1 ? this.H([s, cur]) : this.H([cur, s]); }
      if (cur !== BigInt(cred.merkleRoot)) throw new Error(`Merkle path of slot ${name} does not reach the signed root`);
    }
    const id = String(cred.merkleRoot).slice(0, 12); this.creds[id] = cred; await this._save(); return id;
  }
  list() { this._need(); return Object.entries(this.creds).map(([id, c]) => ({ id, credId: String(c.fields[SLOT.credId]), issuer: `hybrid EdDSA+${c.pq.suite}`, attributes: c.attrOrder })); }

  /** What a proof request exposes — shown to the user BEFORE anything is computed. */
  describeRequest(id, challenge) {
    this._need(); const c = this.creds[id], reveals = ["name", "university"];
    return {
      reveals: reveals.map((k) => ({ attribute: k, value: c.attributes[k] })),
      proves: [`age >= ${challenge.minAge} (date of birth stays hidden)`, "credential not expired", "credential not revoked", "bound to this verifier + session (nullifier)"],
      hidden: SPEC_ORDER.filter((k) => !reveals.includes(k)),
    };
  }

  /**
   * challenge: { nonce, minAge, today, verifierId, revocationRoot } from the verifier (today = YYYYMMDD, UTC).
   * revocationProof: { revocationRoot, siblings[20], oldKey, oldValue, isOld0 } for THIS credential's credId.
   * consent: async (description) => boolean — the UI decides; core never bypasses it.
   */
  async present(id, challenge, consent, revocationProof) {
    this._need(); const c = this.creds[id]; if (!c) throw new Error("unknown credential");
    for (const k of ["nonce", "minAge", "today", "verifierId", "revocationRoot"]) if (challenge?.[k] === undefined) throw new Error(`challenge.${k} missing`);
    const rp = revocationProof;
    if (!rp || !same(rp.revocationRoot, challenge.revocationRoot) || rp.siblings?.length !== REV_LEVELS) throw new Error("revocation proof missing or for a different root than the challenge");
    const f = c.fields, today = BigInt(challenge.today), minAge = BigInt(challenge.minAge);
    if (today < 19000101n || today > 21001231n || minAge < 0n || minAge > 255n) throw new Error("bad challenge date/minAge");
    if (BigInt(f[SLOT.expiry]) <= today) throw new Error("credential expired");                       // circuit would fail: fail early
    if (BigInt(f[SLOT.dob]) > today - minAge * 10000n) throw new Error("age requirement not met");
    if (!(await consent(this.describeRequest(id, challenge)))) throw new Error("user declined");

    const input = {
      // public inputs
      issuerAx: String(c.issuerPubKey[0]), issuerAy: String(c.issuerPubKey[1]), today: String(challenge.today), minAge: String(challenge.minAge),
      nameValue: f[SLOT.name], uniValue: f[SLOT.university], verifierId: String(challenge.verifierId), nonce: String(challenge.nonce), revocationRoot: String(challenge.revocationRoot),
      // private inputs (root + signature never leave the wallet)
      merkleRoot: String(c.merkleRoot), sigR8x: c.signature.R8[0], sigR8y: c.signature.R8[1], sigS: c.signature.S,
      holderSecret: this.#holderSecret.toString(),
      dob: f[SLOT.dob], expiry: f[SLOT.expiry], credId: f[SLOT.credId],
      nameSalt: c.salts[SLOT.name], dobSalt: c.salts[SLOT.dob], uniSalt: c.salts[SLOT.university],
      holderSalt: c.salts[SLOT.holderCommit], expirySalt: c.salts[SLOT.expiry], credIdSalt: c.salts[SLOT.credId],
      namePath: c.paths[SLOT.name], dobPath: c.paths[SLOT.dob], uniPath: c.paths[SLOT.university],
      holderPath: c.paths[SLOT.holderCommit], expiryPath: c.paths[SLOT.expiry], credIdPath: c.paths[SLOT.credId],   // siblings only; directions are circuit constants
      siblings: rp.siblings.map(String), oldKey: String(rp.oldKey), oldValue: String(rp.oldValue), isOld0: String(rp.isOld0),
    };
    const { proof, publicSignals } = await this.prover(input);
    return { proof, publicSignals };   // nothing else: no root, no signature, no attributes, no salts, no paths
  }
}
