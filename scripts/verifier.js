// Algorithm 3 (CLI). usage: node scripts/verifier.js [expectedNonce] [expectedMinAge]
const fs = require("fs");
const { verifyPresentation, loadVk, loadTrusted, SIG } = require("../src/verify-core");
const { toField } = require("./common");
const revocation = require("../src/revocation");

(async () => {
  const publicSignals = JSON.parse(fs.readFileSync("data/public.json"));
  const expectedNonce = process.argv[2] || publicSignals[SIG.nonce];
  const expectedMinAge = process.argv[3] || "18";
  const expectedVerifierId = toField(process.env.VERIFIER_ID || "ekyc-gateway-local").toString();
  const expectedRevocationRoot = (await revocation.root({ dir: "data" })).toString();

  const r = await verifyPresentation({
    presentation: JSON.parse(fs.readFileSync("data/presentation.json")),
    proof: JSON.parse(fs.readFileSync("data/proof.json")),
    publicSignals,
  }, {
    vk: loadVk(),
    trusted: loadTrusted(),
    expectedNonce,
    expectedMinAge,
    expectedVerifierId,
    expectedRevocationRoot,
    usedNullifiers: new Set()
  });
  r.checks.forEach((c, i) => console.log(`${i + 1}. ${c.name}: ${c.ok ? "OK" : "FAILED"}`));
  console.log(r.ok ? "ACCEPTED" : "REJECTED");
  process.exit(r.ok ? 0 : 1);
})();
