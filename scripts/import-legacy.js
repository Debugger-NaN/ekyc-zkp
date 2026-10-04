// Legacy integration (issuing side): turn rows of an existing customer CSV/export into signed credentials.
// usage: node scripts/import-legacy.js legacy/sample-customers.csv
// Column names are mapped in legacy/mapping.json so old schemas don't need code changes.
const fs = require("fs");
const { loadIssuerKeys, issueCredential } = require("../src/issuer-core");
(async () => {
  const csvFile = process.argv[2] || "legacy/sample-customers.csv";
  const map = JSON.parse(fs.readFileSync("legacy/mapping.json"));
  const [head, ...rows] = fs.readFileSync(csvFile, "utf8").trim().split(/\r?\n/).map((l) => l.split(",").map((s) => s.trim()));
  const keys = await loadIssuerKeys();
  fs.mkdirSync("data/credentials", { recursive: true });
  for (const r of rows) {
    const rec = Object.fromEntries(head.map((h, i) => [h, r[i]]));
    const attrs = {};
    for (const [attr, col] of Object.entries(map.columns)) attrs[attr] = rec[col];
    attrs.dobYear = Number(String(rec[map.dobColumn]).slice(map.dobYearSlice[0], map.dobYearSlice[1]));
    if (!attrs.dobYear) { console.log("skip (bad DOB):", rec[map.idColumn]); continue; }
    const cred = await issueCredential(attrs, keys);
    fs.writeFileSync(`data/credentials/${rec[map.idColumn]}.json`, JSON.stringify(cred, null, 2));
    console.log(`issued ${rec[map.idColumn]} (${attrs.name})`);
  }
})();
