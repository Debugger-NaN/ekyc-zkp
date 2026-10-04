const aml = require("../src/aml");
const assert = require("assert");

(async () => {
  console.log("Running zk-AML Sanctions Unit Tests...");

  // 1. Root computation
  const root = await aml.root();
  assert(typeof root === "string" && root.length > 10, "Sanctions root must be a non-empty string");
  console.log("PASS  Sanctions SMT root calculated:", root.slice(0, 16) + "...");

  // 2. Non-membership proof for unsanctioned user
  const cleanKey = await aml.computeIdentityKey("KARA SINGH", 20051125);
  const proof = await aml.getNonMembershipProof(cleanKey);
  assert.strictEqual(proof.sanctionsRoot, root);
  assert.strictEqual(proof.siblings.length, aml.LEVELS);
  console.log("PASS  Valid non-membership proof generated for clean user");

  // 3. Blocked entry for sanctioned individual
  let blocked = false;
  try {
    const sanctionedKey = await aml.computeIdentityKey("VLADIMIR ILLYICH", 19700101);
    await aml.getNonMembershipProof(sanctionedKey);
  } catch (err) {
    blocked = true;
    assert(/matches an entry on the AML\/Sanctions watchlist/i.test(err.message));
  }
  assert.strictEqual(blocked, true, "Sanctioned user must be rejected");
  console.log("PASS  Sanctioned person correctly identified and rejected from proof generation");

  console.log("ALL AML TESTS PASSED!");
})().catch(err => {
  console.error("FAIL AML TESTS:", err);
  process.exit(1);
});
