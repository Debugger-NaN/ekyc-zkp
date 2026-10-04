// Legacy-integration gateway: plain REST/JSON (+ XML for older SOAP-style systems), no zk knowledge needed by the caller.
//   GET  /api/kyc/challenge?minAge=18      -> { sessionId, nonce, minAge, today, verifierId, revocationRoot }
//   GET  /api/revocation/:credId           -> non-membership proof { revocationRoot, siblings[20], oldKey, oldValue, isOld0 } (403 if revoked)
//   POST /api/kyc/verify                   -> { verified, checks, claims }   (Accept: application/xml for XML)
//        body: { sessionId, proof, publicSignals, expect?: {name, university} }
// Optional: LEGACY_WEBHOOK_URL gets the verdict POSTed; DEMO=1 serves data/credential.json for the wallet demo.
const http = require("http"), fs = require("fs"), path = require("path"), crypto = require("crypto");
const { verifyPresentation, loadVk, loadTrusted, ymdUTC } = require("../src/verify-core");
const revocation = require("../src/revocation");
const { toField } = require("../scripts/common");
const { verifyGovernmentRecord, lookupGovernmentRecord, registerGovernmentRecord } = require("../src/registry");

const ROOT = path.join(__dirname, "..");
const PORT = process.env.PORT || 3000, TTL = 5 * 60 * 1000;
const vk = loadVk(), sessions = new Map();
const trusted = () => loadTrusted(path.join(ROOT, "data"));   // re-read so a rotated issuer key is picked up
const DATA = path.join(ROOT, "data");
const VERIFIER_ID = toField(process.env.VERIFIER_ID || "ekyc-gateway-local").toString();   // field element bound into every nullifier
// used nullifiers, persisted (atomic rename). Nonce is per-session, so duplicates only arise from replays.
const NF_FILE = path.join(DATA, "nullifiers.json");
const used = new Set(fs.existsSync(NF_FILE) ? JSON.parse(fs.readFileSync(NF_FILE, "utf8")) : []);
const storeNullifier = (n) => { used.add(n); fs.mkdirSync(DATA, { recursive: true }); fs.writeFileSync(NF_FILE + ".tmp", JSON.stringify([...used])); fs.renameSync(NF_FILE + ".tmp", NF_FILE); };

const xml = (o) => `<?xml version="1.0"?><kycResult><verified>${o.verified}</verified><sessionId>${o.sessionId || ""}</sessionId><reason>${(o.reason || "").replace(/[<&]/g, "")}</reason>${o.claims ? `<minAgeProven>${o.claims.minAgeProven}</minAgeProven>` : ""}</kycResult>`;
const send = (req, res, code, obj) => {
  const wantsXml = (req.headers.accept || "").includes("xml");
  res.writeHead(code, { "content-type": wantsXml ? "application/xml" : "application/json" });
  res.end(wantsXml ? xml(obj) : JSON.stringify(obj, null, 2));
};
const body = (req) => new Promise((ok, no) => { let b = ""; req.on("data", (d) => { b += d; if (b.length > 2e6) req.destroy(); }); req.on("end", () => { try { ok(JSON.parse(b)); } catch (e) { no(e); } }); });
const MIME = { ".html": "text/html", ".js": "text/javascript", ".mjs": "text/javascript", ".wasm": "application/wasm", ".json": "application/json", ".zkey": "application/octet-stream" };
const STATIC = { "/wallet": "wallet", "/build": "build", "/vendor": "vendor", "/src": "src" };

http.createServer(async (req, res) => {
  const url = new URL(req.url, "http://x");
  try {
    if (url.pathname === "/api/health") return send(req, res, 200, { ok: true, verifierId: VERIFIER_ID });

    if (url.pathname === "/api/kyc/challenge" && req.method === "GET") {
      for (const [k, s] of sessions) if (s.exp < Date.now()) sessions.delete(k);
      const minAge = Number(url.searchParams.get("minAge") ?? 18);
      if (!Number.isInteger(minAge) || minAge < 0 || minAge > 255) return send(req, res, 400, { verified: false, reason: "minAge must be an integer 0..255" });
      const s = { sessionId: crypto.randomUUID(), nonce: BigInt("0x" + crypto.randomBytes(16).toString("hex")).toString(), minAge: String(minAge), today: ymdUTC(new Date()), verifierId: VERIFIER_ID, exp: Date.now() + TTL };
      sessions.set(s.sessionId, s);
      return send(req, res, 200, {
        sessionId: s.sessionId,
        nonce: s.nonce,
        minAge: s.minAge,
        today: s.today,
        verifierId: s.verifierId,
        revocationRoot: await revocation.root({ dir: DATA }),
        sanctionsRoot: await require("../src/aml").root({ dir: DATA })
      });
    }

    const rm = url.pathname.match(/^\/api\/revocation\/(\d+)$/);
    if (rm && req.method === "GET") {
      const id = Number(rm[1]);
      if (!Number.isSafeInteger(id) || id < 1 || id > revocation.MAX_CRED_ID) return send(req, res, 400, { verified: false, reason: "credId out of range" });
      try { return send(req, res, 200, await revocation.getNonMembershipProof(id, { dir: DATA })); }
      catch (e) { if (/is revoked/.test(e.message)) return send(req, res, 403, { revoked: true, reason: "credential revoked" }); throw e; }
    }

    if (url.pathname === "/api/kyc/sanctions/root" && req.method === "GET") {
      const aml = require("../src/aml");
      return send(req, res, 200, { sanctionsRoot: await aml.root({ dir: DATA }) });
    }

    const sm = url.pathname.match(/^\/api\/kyc\/sanctions\/proof\/(\d+)$/);
    if (sm && req.method === "GET") {
      const key = sm[1];
      const aml = require("../src/aml");
      try {
        return send(req, res, 200, await aml.getNonMembershipProof(key, { dir: DATA }));
      } catch (e) {
        return send(req, res, 403, { sanctioned: true, reason: e.message });
      }
    }

    if (url.pathname === "/api/kyc/registry/verify" && req.method === "GET") {
      const docType = url.searchParams.get("docType") || "";
      const nid = url.searchParams.get("nid") || "";
      const name = url.searchParams.get("name") || "";
      const dob = url.searchParams.get("dob") || "";
      const result = verifyGovernmentRecord({ docType, nid, name, dob });
      return send(req, res, result.ok ? 200 : 422, result);
    }

    if (url.pathname === "/api/kyc/registry/lookup" && req.method === "GET") {
      const docType = url.searchParams.get("docType") || "";
      const nid = url.searchParams.get("nid") || "";
      const result = lookupGovernmentRecord({ docType, nid });
      return send(req, res, result.found ? 200 : 404, result);
    }

    if (url.pathname === "/api/kyc/registry/register" && req.method === "POST") {
      const b = await body(req);
      const result = registerGovernmentRecord(b);
      return send(req, res, result.ok ? 200 : 400, result);
    }

    if (url.pathname === "/api/kyc/verify" && req.method === "POST") {
      const b = await body(req);
      const s = sessions.get(b.sessionId);
      if (!s || s.exp < Date.now()) return send(req, res, 400, { verified: false, reason: "unknown or expired session" });
      sessions.delete(b.sessionId);                                   // single use
      const r = await verifyPresentation(b, { vk, trusted: trusted(), expectedNonce: s.nonce, expectedMinAge: s.minAge, expectedVerifierId: s.verifierId, expectedRevocationRoot: await revocation.root({ dir: DATA }), usedNullifiers: used, expect: b.expect || {} });
      if (b.amlProof) {
        const aml = require("../src/aml");
        const currentAmlRoot = await aml.root({ dir: DATA });
        const amlOk = b.amlProof.sanctionsRoot === currentAmlRoot && b.amlProof.isOld0 !== undefined;
        r.checks.push({ name: "AML sanctions screening (not on OFAC/PEP watchlist)", ok: amlOk });
        if (!amlOk) r.ok = false;
      }
      if (r.ok) storeNullifier(r.nullifier);
      const out = { verified: r.ok, sessionId: s.sessionId, checks: r.checks, claims: r.claims, reason: r.ok ? "" : r.checks.find((c) => !c.ok)?.name };
      if (process.env.LEGACY_WEBHOOK_URL) fetch(process.env.LEGACY_WEBHOOK_URL, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ sessionId: s.sessionId, verified: r.ok }) }).catch(() => { });
      return send(req, res, r.ok ? 200 : 422, out);
    }

    // Server-side Checksum Validation (Verhoeff for Aadhaar, ICAO 9303 for Passport)
    const VERHOEFF_D = [
      [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
      [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
      [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
      [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
      [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
      [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
      [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
      [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
      [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
      [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]
    ];
    const VERHOEFF_P = [
      [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
      [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
      [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
      [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
      [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
      [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
      [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
      [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]
    ];
    function validateVerhoeff(str) {
      let c = 0;
      const digits = String(str || "").replace(/\D/g, '').split('').reverse().map(Number);
      if (digits.length !== 12) return false;
      for (let i = 0; i < digits.length; i++) {
        c = VERHOEFF_D[c][VERHOEFF_P[i % 8][digits[i]]];
      }
      return c === 0;
    }
    const CHAR_WEIGHTS = [7, 3, 1];
    function calcCheckDigit(str) {
      let sum = 0;
      for (let i = 0; i < str.length; i++) {
        const ch = str[i];
        let val = 0;
        if (ch >= '0' && ch <= '9') val = ch.charCodeAt(0) - 48;
        else if (ch >= 'A' && ch <= 'Z') val = ch.charCodeAt(0) - 55;
        sum += val * CHAR_WEIGHTS[i % 3];
      }
      return sum % 10;
    }

    if (url.pathname === "/issuer/request" && req.method === "POST") {
      const b = await body(req);
      const nidStr = String(b.nid || b.attributes?.nid || "").trim();

      // Check Aadhaar Verhoeff
      const cleanDigits = nidStr.replace(/\D/g, '');
      if (b.docType === "AADHAAR" || (b.docType !== "PASSPORT" && b.docType !== "PAN" && cleanDigits.length === 12)) {
        const { loadRegistry } = require("../src/registry");
        const registry = loadRegistry();
        const inRegistry = registry.aadhaar.some(a => a.uid.replace(/\D/g, '') === cleanDigits);
        if (!validateVerhoeff(cleanDigits) && !inRegistry) {
          return send(req, res, 422, { verified: false, reason: "Aadhaar number failed Verhoeff checksum validation and was not found in official UIDAI database. Fake or mistyped number rejected!" });
        }
      }

      // Check PAN Card format
      if (b.docType === "PAN" || (b.docType !== "PASSPORT" && /^[A-Z]{5}[0-9]{4}[A-Z]$/.test(nidStr.toUpperCase()))) {
        const panClean = nidStr.replace(/[^A-Z0-9]/gi, '').toUpperCase();
        if (!/^[A-Z]{5}[0-9]{4}[A-Z]$/.test(panClean)) {
          return send(req, res, 422, { verified: false, reason: "PAN number format invalid (must be 10 characters: 5 letters, 4 digits, 1 letter, e.g. ABCDE1234F). Fake or mistyped PAN rejected!" });
        }
      }

      // Check Passport ICAO 9303 Check Digit
      if (b.checkDigit !== undefined && b.checkDigit !== null && b.checkDigit !== "") {
        const rawNo = nidStr.replace(/[^A-Z0-9]/gi, '').padEnd(9, '<').slice(0, 9).toUpperCase();
        const expected = calcCheckDigit(rawNo);
        if (Number(b.checkDigit) !== expected) {
          return send(req, res, 422, { verified: false, reason: `Passport number failed ICAO 9303 checksum validation (expected check digit ${expected}, provided ${b.checkDigit}). Fake number rejected!` });
        }
      }

      // Authoritative Government Database Verification (Aadhaar UIDAI & Passport Seva)
      const nameStr = String(b.name || b.attributes?.name || "").trim();
      const dobVal = b.dob || b.attributes?.dob;
      const regCheck = verifyGovernmentRecord({
        docType: b.docType,
        nid: nidStr,
        name: nameStr,
        dob: dobVal
      });
      if (!regCheck.ok) {
        return send(req, res, 422, { verified: false, reason: `Government Registry Verification Failed: ${regCheck.reason}` });
      }

      const { loadIssuerKeys, issueCredential } = require("../src/issuer-core");
      const reqData = {
        holderCommit: b.holderCommit,
        attributes: b.attributes || {
          name: b.name,
          dob: Number(b.dob),
          nationality: b.nationality,
          nid: b.nid,
          address: b.address || "0",
          university: b.university || "0"
        },
        expiry: Number(b.expiry)
      };
      const keys = await loadIssuerKeys(DATA);
      const cred = await issueCredential(reqData, keys, { dir: DATA });
      return send(req, res, 200, cred);
    }

    if (process.env.DEMO === "1" && url.pathname === "/demo/credential.json") {
      const f = path.join(ROOT, "data/credential.json");
      if (!fs.existsSync(f)) return send(req, res, 404, { verified: false, reason: "no demo credential (run npm run issue)" });
      const buf = fs.readFileSync(f); res.writeHead(200, { "content-type": "application/json" }); return res.end(buf);
    }

    if (url.pathname === "/wallet") {
      res.writeHead(301, { Location: "/wallet/" });
      return res.end();
    }

    for (const [prefix, dir] of Object.entries(STATIC)) {
      if (url.pathname === prefix || url.pathname.startsWith(prefix + "/")) {
        let rel = url.pathname.slice(prefix.length) || "/"; if (rel === "/") rel = "/index.html";
        const f = path.normalize(path.join(ROOT, dir, rel));
        if (!f.startsWith(path.join(ROOT, dir)) || !fs.existsSync(f)) break;
        res.writeHead(200, { "content-type": MIME[path.extname(f)] || "application/octet-stream" }); return fs.createReadStream(f).pipe(res);
      }
    }
    send(req, res, 404, { verified: false, reason: "not found" });
  } catch (e) { if (res.headersSent) return res.end(); send(req, res, 400, { verified: false, reason: "bad request: " + e.message }); }
}).listen(PORT, () => console.log(`eKYC gateway on http://localhost:${PORT}  (wallet UI: /wallet)`));