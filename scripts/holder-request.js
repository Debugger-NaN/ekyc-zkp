// HOLDER side: creates holderSecret locally (data/holder.secret, never sent) and writes the issue request.
const fs = require("fs"), crypto = require("crypto");
const { lib, S } = require("./common");
(async () => {
    const { poseidon, F } = await lib();
    fs.mkdirSync("data", { recursive: true });
    if (!fs.existsSync("data/holder.secret")) fs.writeFileSync("data/holder.secret", BigInt("0x" + crypto.randomBytes(31).toString("hex")).toString());
    const holderCommit = F.toObject(poseidon([BigInt(fs.readFileSync("data/holder.secret", "utf8"))]));
    fs.writeFileSync("data/issue-request.json", JSON.stringify(S({
        holderCommit,
        attributes: { name: "Ahmed", dob: 19890826, nationality: "Japan", nid: "NP842000111", address: "1-1 Gakuen-cho, Sakai, Osaka", university: "Osaka Metropolitan University" },
        expiry: 20301231,
    }), null, 2));
    console.log("wrote data/issue-request.json (holderCommit only; secret stays in data/holder.secret)");
})();