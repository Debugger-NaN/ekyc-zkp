const assert = require("assert");
const { verifyGovernmentRecord, normalizeName, lookupGovernmentRecord, registerGovernmentRecord } = require("../src/registry");

(async () => {
  console.log("Running Government Registry Unit Tests...\n");

  // 1. Name normalization test
  assert.strictEqual(normalizeName("Karan Singh Negi"), "KARAN NEGI SINGH");
  assert.strictEqual(normalizeName("NEGI  KARAN   SINGH"), "KARAN NEGI SINGH");
  assert.strictEqual(normalizeName("Ahmed"), "AHMED");
  console.log("PASS  normalizeName word order insensitive matching works");

  // 2. Genuine Aadhaar Match
  const genuineAadhaar = verifyGovernmentRecord({
    docType: "AADHAAR",
    nid: "485487689665",
    name: "Karan Singh Negi",
    dob: 20051125
  });
  assert.strictEqual(genuineAadhaar.ok, true);
  assert.strictEqual(genuineAadhaar.source, "UIDAI_GOV_REGISTRY");
  console.log("PASS  Genuine Aadhaar record verified against UIDAI database");

  // 3. Reversed Name Order Aadhaar Match
  const reverseNameAadhaar = verifyGovernmentRecord({
    docType: "AADHAAR",
    nid: "4854 8768 9665",
    name: "NEGI KARAN SINGH",
    dob: "2005/11/25"
  });
  assert.strictEqual(reverseNameAadhaar.ok, true);
  console.log("PASS  Aadhaar matched despite surname/given-name order variation");

  // 3b. User Aadhaar UID 5222 6688 7818 Match (Suryansh Sapehia)
  const userAadhaar = verifyGovernmentRecord({
    docType: "AADHAAR",
    nid: "5222 6688 7818",
    name: "Suryansh Sapehia"
  });
  assert.strictEqual(userAadhaar.ok, true);
  assert.strictEqual(userAadhaar.source, "UIDAI_GOV_REGISTRY");
  console.log("PASS  User Aadhaar 5222 6688 7818 verified for Suryansh Sapehia in UIDAI database");

  // 3c. No name hint leak test
  const leakTest = verifyGovernmentRecord({
    docType: "AADHAAR",
    nid: "5222 6688 7818",
    name: "Someone Else"
  });
  assert.strictEqual(leakTest.ok, false);
  assert.strictEqual(leakTest.error, "NAME_MISMATCH");
  assert(!leakTest.reason.includes("Suryansh"), "Reason must not leak registered name!");
  console.log("PASS  Mismatch error does not leak registered name hints");

  // 4. Fake Aadhaar UID
  const fakeAadhaar = verifyGovernmentRecord({
    docType: "AADHAAR",
    nid: "999988887777",
    name: "Karan Singh Negi",
    dob: 20051125
  });
  assert.strictEqual(fakeAadhaar.ok, false);
  assert.strictEqual(fakeAadhaar.error, "UID_NOT_FOUND");
  console.log("PASS  Non-existent Aadhaar UID rejected with UID_NOT_FOUND");

  // 5. Wrong Name on Genuine Aadhaar
  const wrongNameAadhaar = verifyGovernmentRecord({
    docType: "AADHAAR",
    nid: "485487689665",
    name: "Fake Imposter",
    dob: 20051125
  });
  assert.strictEqual(wrongNameAadhaar.ok, false);
  assert.strictEqual(wrongNameAadhaar.error, "NAME_MISMATCH");
  console.log("PASS  Imposter name on genuine Aadhaar rejected with NAME_MISMATCH");

  // 6. Wrong DOB on Genuine Aadhaar
  const wrongDobAadhaar = verifyGovernmentRecord({
    docType: "AADHAAR",
    nid: "485487689665",
    name: "Karan Singh Negi",
    dob: 19990101
  });
  assert.strictEqual(wrongDobAadhaar.ok, false);
  assert.strictEqual(wrongDobAadhaar.error, "DOB_MISMATCH");
  console.log("PASS  Wrong DOB on genuine Aadhaar rejected with DOB_MISMATCH");

  // 7. Genuine Passport Match (AS456127)
  const genuinePassport = verifyGovernmentRecord({
    docType: "PASSPORT",
    nid: "AS456127",
    name: "Karan Singh Negi",
    dob: 20051125
  });
  assert.strictEqual(genuinePassport.ok, true);
  assert.strictEqual(genuinePassport.source, "PASSPORT_SEVA_REGISTRY");
  console.log("PASS  Genuine Passport record verified against Passport Seva database");

  // 8. Fake Passport Number (AS456128)
  const fakePassport = verifyGovernmentRecord({
    docType: "PASSPORT",
    nid: "AS456128",
    name: "Karan Singh Negi",
    dob: 20051125
  });
  assert.strictEqual(fakePassport.ok, false);
  assert.strictEqual(fakePassport.error, "PASSPORT_NOT_FOUND");
  console.log("PASS  Fake Passport AS456128 rejected with PASSPORT_NOT_FOUND");

  // 9. Wrong Name on Genuine Passport
  const wrongNamePass = verifyGovernmentRecord({
    docType: "PASSPORT",
    nid: "AS456127",
    name: "John Doe",
    dob: 20051125
  });
  assert.strictEqual(wrongNamePass.ok, false);
  assert.strictEqual(wrongNamePass.error, "NAME_MISMATCH");
  console.log("PASS  Wrong name on genuine passport rejected with NAME_MISMATCH");

  // 10. Genuine PAN Card Match (NEGPK1234N - Karan Singh Negi)
  const genuinePan = verifyGovernmentRecord({
    docType: "PAN",
    nid: "NEGPK1234N",
    name: "Karan Singh Negi",
    dob: 20051125
  });
  assert.strictEqual(genuinePan.ok, true);
  assert.strictEqual(genuinePan.source, "NSDL_PAN_REGISTRY");
  console.log("PASS  Genuine PAN NEGPK1234N verified for Karan Singh Negi in NSDL database");

  // 11. User Suryansh Sapehia PAN Card Match (SAPPK5678S)
  const suryanshPan = verifyGovernmentRecord({
    docType: "PAN",
    nid: "SAPPK5678S",
    name: "Suryansh Sapehia"
  });
  assert.strictEqual(suryanshPan.ok, true);
  assert.strictEqual(suryanshPan.source, "NSDL_PAN_REGISTRY");
  console.log("PASS  User PAN SAPPK5678S verified for Suryansh Sapehia in NSDL database");

  // 12. Fake / Unregistered PAN Card
  const fakePan = verifyGovernmentRecord({
    docType: "PAN",
    nid: "FAKEP9999F",
    name: "Fake User"
  });
  assert.strictEqual(fakePan.ok, false);
  assert.strictEqual(fakePan.error, "PAN_NOT_FOUND");
  console.log("PASS  Unregistered PAN card rejected with PAN_NOT_FOUND");

  // 13. Wrong Name on Genuine PAN (No hint leak)
  const wrongNamePan = verifyGovernmentRecord({
    docType: "PAN",
    nid: "NEGPK1234N",
    name: "Another Person"
  });
  assert.strictEqual(wrongNamePan.ok, false);
  assert.strictEqual(wrongNamePan.error, "NAME_MISMATCH");
  assert(!wrongNamePan.reason.includes("Karan"), "PAN error must not leak registered name!");
  console.log("PASS  Wrong name on PAN rejected without leaking registered name");

  // 14. Authoritative Lookup Tests (Aadhaar, Passport, PAN)
  const aadhaarLookup = lookupGovernmentRecord({ docType: "AADHAAR", nid: "5222 6688 7818" });
  assert.strictEqual(aadhaarLookup.found, true);
  assert.strictEqual(aadhaarLookup.record.name, "Suryansh Sapehia");
  console.log("PASS  lookupGovernmentRecord correctly resolved Aadhaar 5222 6688 7818 to Suryansh Sapehia");

  const panLookup = lookupGovernmentRecord({ docType: "PAN", nid: "NEGPK1234N" });
  assert.strictEqual(panLookup.found, true);
  assert.strictEqual(panLookup.record.name, "Karan Singh Negi");
  console.log("PASS  lookupGovernmentRecord correctly resolved PAN NEGPK1234N to Karan Singh Negi");

  const passLookup = lookupGovernmentRecord({ docType: "PASSPORT", nid: "SP881234" });
  assert.strictEqual(passLookup.found, true);
  assert.strictEqual(passLookup.record.name, "Suryansh Sapehia");
  console.log("PASS  lookupGovernmentRecord correctly resolved Passport SP881234 to Suryansh Sapehia");

  // 15. Dynamic Registration Test
  const regResult = registerGovernmentRecord({
    docType: "AADHAAR",
    nid: "888877776666",
    name: "Test Dynamic Citizen",
    dob: 19991231,
    address: "Shimla, HP, India"
  });
  assert.strictEqual(regResult.ok, true);
  console.log("PASS  registerGovernmentRecord dynamically registered new citizen");

  const dynamicVerify = verifyGovernmentRecord({
    docType: "AADHAAR",
    nid: "888877776666",
    name: "Test Dynamic Citizen",
    dob: 19991231
  });
  assert.strictEqual(dynamicVerify.ok, true);
  console.log("PASS  Dynamically registered citizen immediately verified in government registry");

  console.log("\nALL GOVERNMENT REGISTRY TESTS PASSED!");
})().catch(err => {
  console.error("FAIL REGISTRY TESTS:", err);
  process.exit(1);
});
