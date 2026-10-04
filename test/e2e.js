const fs = require("fs"), path = require("path"), { spawn } = require("child_process"), snarkjs = require("snarkjs");
const { loadIssuerKeys, issueCredential } = require("../src/issuer-core");
const { lib } = require("../scripts/common");
const { pqVerifyRoot } = require("../src/crypto-suite");
const { loadTrusted } = require("../src/verify-core");

const H = "http://localhost:3055";
let pass = 0, fail = 0;
const t = (name, ok) => { console.log(`${ok ? "PASS" : "FAIL"}  ${name}`); ok ? pass++ : fail++; };
const post = (b, hdr = {}) => fetch(H + "/api/kyc/verify", { method: "POST", headers: { "content-type": "application/json", ...hdr }, body: JSON.stringify(b) });
const chal = async (minAge = 18) => (await fetch(`${H}/api/kyc/challenge?minAge=${minAge}`)).json();

(async () => {
  const { Wallet, MemoryStorage } = await import("../src/wallet-core.mjs");
  const prover = (i) => snarkjs.groth16.fullProve(i, "build/selective_disclosure_js/selective_disclosure.wasm", "build/circuit_final.zkey");

  const { poseidon, F } = await lib();
  const trusted = loadTrusted("data");
  const keys = await loadIssuerKeys();
  const yes = async () => true;

  const mk = async (issuerKeys) => {
    const w = new Wallet({
      storage: new MemoryStorage(),
      prover,
      poseidon: (a) => F.toObject(poseidon(a)),
      pqVerify: pqVerifyRoot,
      trusted
    });
    await w.unlock("pw");
    const cred = await issueCredential({
      holderCommit: w.holderCommit(),
      attributes: { name: "Ahmed", dob: 19890826, nationality: "Japan", nid: "N1", address: "x", university: "Osaka Metropolitan University" },
      expiry: 20301231
    }, issuerKeys);
    return [w, await w.addCredential(cred), cred];
  };

  const srv = spawn("node", ["gateway/server.js"], { env: { ...process.env, PORT: "3055" }, stdio: "ignore" });
  await new Promise((r) => setTimeout(r, 1500));
  try {
    const [w, id, cred] = await mk(keys);
    const getRev = async (credId) => (await fetch(`${H}/api/revocation/${credId}`)).json();
    const rp = await getRev(cred.credId);

    // happy path (hybrid sigs required by default)
    let ch = await chal(), b = await w.present(id, ch, yes, rp);
    let r = await post({ sessionId: ch.sessionId, ...b }); let j = await r.json();
    t("valid proof accepted (EdDSA + ML-DSA required)", j.verified === true);
    t("presentation leaks no attributes/salts", !JSON.stringify(b).includes("1989") && !JSON.stringify(b).includes("Japan"));

    // replay: same session again
    r = await post({ sessionId: ch.sessionId, ...b }); t("session replay rejected", (await r.json()).verified === false);

    // proof bound to a different session's nonce
    const ch2 = await chal(); r = await post({ sessionId: ch2.sessionId, ...b });
    t("proof for another nonce rejected", (await r.json()).reason === "nonce equals session nonce");

    // ML-DSA signature check at wallet import
    let pqRejected = false;
    try {
      const badCred = { ...cred, pq: { ...cred.pq, signature: cred.pq.signature.replace(/^../, "00") } };
      const [wBad] = await mk(keys);
      await wBad.addCredential(badCred);
    } catch (e) {
      pqRejected = /ML-DSA/.test(e.message);
    }
    t("forged ML-DSA signature rejected at wallet import", pqRejected);

    // attacker self-issues a credential with their own keys
    const evilDir = path.join(__dirname, "../data/evil");
    fs.mkdirSync(evilDir, { recursive: true });
    const evilKeys = await loadIssuerKeys(evilDir);
    let untrustedRejected = false;
    try {
      const [we] = await mk(keys);
      const evilCred = await issueCredential({
        holderCommit: we.holderCommit(),
        attributes: { name: "Ahmed", dob: 19890826, nationality: "Japan", nid: "N1", address: "x", university: "Osaka Metropolitan University" },
        expiry: 20301231
      }, evilKeys, { dir: evilDir });
      await we.addCredential(evilCred);
    } catch (e) {
      untrustedRejected = /not the trusted issuer/.test(e.message);
    }
    t("self-issued credential (untrusted issuer) rejected at wallet import", untrustedRejected);

    // legacy cross-check
    ch = await chal(); b = await w.present(id, ch, yes, rp);
    r = await post({ sessionId: ch.sessionId, ...b, expect: { name: "Ahmed", university: "Osaka Metropolitan University" } });
    t("legacy 'expect' match accepted", (await r.json()).verified === true);
    ch = await chal(); b = await w.present(id, ch, yes, rp);
    r = await post({ sessionId: ch.sessionId, ...b, expect: { name: "Someone Else" } });
    t("legacy 'expect' mismatch rejected", (await r.json()).verified === false);

    // XML output for old systems
    ch = await chal(); b = await w.present(id, ch, yes, rp);
    r = await post({ sessionId: ch.sessionId, ...b }, { accept: "application/xml" }); const x = await r.text();
    t("XML response for legacy clients", x.includes("<verified>true</verified>"));

    // wallet-level behaviour
    let declined = false; try { await w.present(id, await chal(), async () => false, rp); } catch (e) { declined = /declined/.test(e.message); }
    t("wallet honours consent decline (no proof made)", declined);
    let under = false; try { await w.present(id, await chal(40), yes, rp); } catch { under = true; }
    t("cannot prove age >= 40 for a 37-year-old", under);

    const st = new MemoryStorage();
    const w1 = new Wallet({
      storage: st,
      prover,
      poseidon: (a) => F.toObject(poseidon(a)),
      pqVerify: pqVerifyRoot,
      trusted
    });
    await w1.unlock("secret");
    const cred1 = await issueCredential({
      holderCommit: w1.holderCommit(),
      attributes: { name: "Ahmed", dob: 19890826, nationality: "Japan", nid: "N1", address: "x", university: "Osaka Metropolitan University" },
      expiry: 20301231
    }, keys);
    await w1.addCredential(cred1);

    const w2 = new Wallet({
      storage: st,
      prover,
      poseidon: (a) => F.toObject(poseidon(a)),
      pqVerify: pqVerifyRoot,
      trusted
    });
    t("wallet storage encrypted, wrong passphrase refused", !JSON.stringify([...st.m.values()]).includes("Ahmed") && (await w2.unlock("nope")) === false && (await w2.unlock("secret")) === true && w2.list().length === 1);
  } finally { srv.kill(); }
  console.log(`\n${pass} passed, ${fail} failed`); process.exit(fail ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });