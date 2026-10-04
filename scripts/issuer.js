// usage: node scripts/issuer.js [issue-request.json]   (default data/issue-request.json)
// Request format (holderSecret is never sent or seen here):
//   { "holderCommit": "<Poseidon(holderSecret) as decimal>",
//     "attributes": { "name": "Ahmed", "dob": 19890826, "nationality": "Japan", "nid": "NP842000111",
//                     "address": "1-1 Gakuen-cho, Sakai, Osaka", "university": "Osaka Metropolitan University" },
//     "expiry": 20301231 }
const fs = require("fs");
const { loadIssuerKeys, issueCredential } = require("../src/issuer-core");
(async () => {
  const req = JSON.parse(fs.readFileSync(process.argv[2] || "data/issue-request.json", "utf8"));
  const cred = await issueCredential(req, await loadIssuerKeys());
  fs.mkdirSync("data/credentials", { recursive: true });
  const out = `data/credentials/${cred.credId}.json`;
  fs.writeFileSync(out, JSON.stringify(cred, null, 2));
  console.log(`credId ${cred.credId} issued -> ${out}\nroot ${cred.merkleRoot}\nEdDSA-Poseidon signed (verified in-circuit); ML-DSA-65 included for wallet-import verification only`);
})().catch((e) => { console.error("ISSUE FAILED:", e.message); process.exit(1); });