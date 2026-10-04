// Algorithm 2 (CLI holder) built on the same wallet core the browser UI uses.
// usage: node scripts/holder.js [nonce] [minAge] [currentYear]
const fs = require("fs");
const snarkjs = require("snarkjs");
const { lib } = require("../scripts/common");
const { pqVerifyRoot } = require("../src/crypto-suite");
const { loadTrusted } = require("../src/verify-core");

// Helper to get YYYYMMDD as an integer
const ymdUTC = (date) => parseInt(date.toISOString().split("T")[0].replace(/-/g, ""));

async function getStorage(pass) {
  const { MemoryStorage } = await import("../src/wallet-core.mjs");
  const storage = new MemoryStorage();
  if (fs.existsSync("data/holder.secret")) {
    const sec = fs.readFileSync("data/holder.secret", "utf8").trim();
    const enc = new TextEncoder();
    const salt = require("crypto").randomBytes(16), iv = require("crypto").randomBytes(12);
    const base = await crypto.subtle.importKey("raw", enc.encode(pass), "PBKDF2", false, ["deriveKey"]);
    const k = await crypto.subtle.deriveKey({ name: "PBKDF2", salt, iterations: 250000, hash: "SHA-256" }, base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
    const plain = JSON.stringify({ holderSecret: sec, creds: {} });
    const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, k, enc.encode(plain));
    await storage.set("ekyc-wallet-v2", JSON.stringify({ salt: Buffer.from(salt).toString("base64"), iv: Buffer.from(iv).toString("base64"), ct: Buffer.from(ct).toString("base64") }));
  }
  return storage;
}

(async () => {
  const { poseidon, F } = await lib();
  const trusted = loadTrusted("data");
  const revocation = require("../src/revocation");
  const revRoot = (await revocation.root({ dir: "data" })).toString();

  const { Wallet } = await import("../src/wallet-core.mjs");
  const { toField } = require("./common");
  const challenge = {
    nonce: process.argv[2] || Date.now().toString(),
    minAge: process.argv[3] || "18",
    today: ymdUTC(new Date()),
    verifierId: toField("ekyc-gateway-local").toString(),
    revocationRoot: revRoot
  };

  const storage = await getStorage("cli");
  const w = new Wallet({
    storage,
    prover: (i) => snarkjs.groth16.fullProve(i, "build/selective_disclosure_js/selective_disclosure.wasm", "build/circuit_final.zkey"),
    poseidon: (a) => F.toObject(poseidon(a)),
    pqVerify: pqVerifyRoot,
    trusted
  });

  await w.unlock("cli");
  const cred = JSON.parse(fs.readFileSync("data/credential.json"));
  const id = await w.addCredential(cred);
  const revProof = await revocation.getNonMembershipProof(cred.credId, { dir: "data" });
  const t = Date.now();
  const out = await w.present(id, challenge, async (d) => {
    console.log("Revealing:", d.reveals.map((r) => r.attribute).join(", "), "| Proving:", d.proves.join("; "), "| Hidden:", d.hidden.join(", "));
    return true;
  }, revProof);

  console.log(`Proof generated in ${Date.now() - t} ms`);
  fs.writeFileSync("data/proof.json", JSON.stringify(out.proof, null, 2));
  fs.writeFileSync("data/public.json", JSON.stringify(out.publicSignals, null, 2));
  fs.writeFileSync("data/presentation.json", JSON.stringify(out, null, 2));
})().then(() => process.exit(0)).catch((e) => { console.error("FAILED:", e.message); process.exit(1); });