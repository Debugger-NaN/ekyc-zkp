const assert = require("assert");
const { verifyGovernmentRecord, normalizeName, lookupGovernmentRecord, registerGovernmentRecord } = require("../src/registry");

(async () => {
  console.log("Running Government Registry Unit Tests...\n");

  // 1. Name normalization test
  assert.strictEqual(normalizeName("Xyz Abc Pqr"), "ABC PQR XYZ");
  assert.strictEqual(normalizeName("PQR ABC XYZ"), "ABC PQR XYZ");
  assert.strictEqual(normalizeName("Xyz"), "XYZ");
  console.log("PASS normalizeName word order insensitive matching works");

  // 2. Genuine Aadhaar Match
  const genuineAadhaar = verifyGovernmentRecord({
    docType: "AADHAAR",
    nid: "123456789012",
    name: "Xyz Abc Pqr",
    dob: 20000101
  });
  assert.strictEqual(genuineAadhaar.ok, true);
  assert.strictEqual(genuineAadhaar.source, "UIDAI_GOV_REGISTRY");
  console.log("PASS Genuine Aadhaar record verified against UIDAI database");

  // 3. Reversed Name Order Aadhaar Match
  const reverseNameAadhaar = verifyGovernmentRecord({
    docType: "AADHAAR",
    nid: "1234 5678 9012",
    name: "PQR ABC XYZ",
    dob: "2000/01/01"
  });
  assert.strictEqual(reverseNameAadhaar.ok, true);
  console.log("PASS Aadhaar matched despite surname/given-name order variation");

  // 3b. Second Aadhaar UID Match
  const userAadhaar = verifyGovernmentRecord({
    docType: "AADHAAR",
    // ... rest of the test (sanitize the same way)
