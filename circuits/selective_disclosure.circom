pragma circom 2.1.9;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/eddsaposeidon.circom";
include "circomlib/circuits/smt/smtverifier.circom";

// Merkle inclusion with the leaf position FIXED at compile time (index is a template
// parameter, so the path direction bits are constants, never witness inputs).
template FixedMerkleInclusion(depth, index) {
    assert(index < (1 << depth));
    signal input leaf;
    signal input pathElements[depth];
    signal output root;

    component h[depth];
    signal cur[depth + 1];
    cur[0] <== leaf;
    for (var i = 0; i < depth; i++) {
        h[i] = Poseidon(2);
        if (((index >> i) & 1) == 0) {
            h[i].inputs[0] <== cur[i];
            h[i].inputs[1] <== pathElements[i];
        } else {
            h[i].inputs[0] <== pathElements[i];
            h[i].inputs[1] <== cur[i];
        }
        cur[i + 1] <== h[i].out;
    }
    root <== cur[depth];
}

// leaf = Poseidon(value, salt) at slot `index`, returns the root it implies.
template AttributeAt(depth, index) {
    signal input value;
    signal input salt;
    signal input pathElements[depth];
    signal output root;

    component lh = Poseidon(2);
    lh.inputs[0] <== value;
    lh.inputs[1] <== salt;

    component m = FixedMerkleInclusion(depth, index);
    m.leaf <== lh.out;
    for (var i = 0; i < depth; i++) m.pathElements[i] <== pathElements[i];
    root <== m.root;
}

template SelectiveDisclosure(depth) {
    // ---- slot layout (SPEC): 0 name, 1 dob, 5 university, 6 holderCommit, 7 expiry, 8 credId ----
    var IDX_NAME = 0;
    var IDX_DOB = 1;
    var IDX_UNI = 5;
    var IDX_HOLDER = 6;
    var IDX_EXPIRY = 7;
    var IDX_CREDID = 8;
    var REV_LEVELS = 20;

    // ---- public inputs: declaration order = public-signal order (nullifier output comes first) ----
    signal input issuerAx;     // issuer EdDSA-Poseidon public key (BabyJubJub); verifier checks it against its trusted issuer
    signal input issuerAy;
    signal input today;        // YYYYMMDD
    signal input minAge;
    signal input nameValue;
    signal input uniValue;
    signal input verifierId;
    signal input nonce;
    signal input revocationRoot; // SMT root of revoked credIds; verifier compares to the registry's current root
    signal output nullifier;

    // ---- private inputs ----
    signal input merkleRoot;   // private, never revealed; authenticated by the issuer signature below
    signal input sigR8x;
    signal input sigR8y;
    signal input sigS;
    signal input holderSecret;
    signal input dob;          // YYYYMMDD
    signal input expiry;       // YYYYMMDD
    signal input nameSalt;
    signal input dobSalt;
    signal input uniSalt;
    signal input holderSalt;
    signal input expirySalt;
    signal input namePath[depth];
    signal input dobPath[depth];
    signal input uniPath[depth];
    signal input holderPath[depth];
    signal input expiryPath[depth];
    signal input credId;       // leaf 8, also the SMT key
    signal input credIdSalt;
    signal input credIdPath[depth];
    // SMT non-inclusion witness (circomlibjs find(): siblings padded to 20, oldKey/oldValue/isOld0)
    signal input siblings[REV_LEVELS];
    signal input oldKey;
    signal input oldValue;
    signal input isOld0;

    // ---- issuer signature over the private merkleRoot, verified in-circuit (enabled = 1) ----
    component sig = EdDSAPoseidonVerifier();
    sig.enabled <== 1;
    sig.Ax <== issuerAx;
    sig.Ay <== issuerAy;
    sig.R8x <== sigR8x;
    sig.R8y <== sigR8y;
    sig.S <== sigS;
    sig.M <== merkleRoot;

    // ---- holder binding: leaf 6 value == Poseidon(holderSecret) ----
    component hc = Poseidon(1);
    hc.inputs[0] <== holderSecret;

    // ---- Merkle inclusion at fixed slots, all must reach the same root ----
    component aName = AttributeAt(depth, IDX_NAME);
    aName.value <== nameValue;  aName.salt <== nameSalt;
    component aDob = AttributeAt(depth, IDX_DOB);
    aDob.value <== dob;         aDob.salt <== dobSalt;
    component aUni = AttributeAt(depth, IDX_UNI);
    aUni.value <== uniValue;    aUni.salt <== uniSalt;
    component aHolder = AttributeAt(depth, IDX_HOLDER);
    aHolder.value <== hc.out;   aHolder.salt <== holderSalt;
    component aExpiry = AttributeAt(depth, IDX_EXPIRY);
    aExpiry.value <== expiry;   aExpiry.salt <== expirySalt;
    component aCred = AttributeAt(depth, IDX_CREDID);
    aCred.value <== credId;     aCred.salt <== credIdSalt;
    for (var i = 0; i < depth; i++) {
        aCred.pathElements[i] <== credIdPath[i];
        aName.pathElements[i] <== namePath[i];
        aDob.pathElements[i] <== dobPath[i];
        aUni.pathElements[i] <== uniPath[i];
        aHolder.pathElements[i] <== holderPath[i];
        aExpiry.pathElements[i] <== expiryPath[i];
    }
    aName.root === merkleRoot;
    aDob.root === merkleRoot;
    aUni.root === merkleRoot;
    aHolder.root === merkleRoot;
    aExpiry.root === merkleRoot;
    aCred.root === merkleRoot;

    // ---- range checks (valid 32-bit values) ----
    component rToday = Num2Bits(32);  rToday.in <== today;
    component rDob = Num2Bits(32);    rDob.in <== dob;
    component rExp = Num2Bits(32);    rExp.in <== expiry;
    component rAge = Num2Bits(8);     rAge.in <== minAge;       // minAge in [0,255]

    // ---- age: dob <= today - minAge*10000 ----
    signal threshold;
    threshold <== today - minAge * 10000;
    component rThr = Num2Bits(32);    rThr.in <== threshold;    // fails if negative (field wrap)
    component ageOk = LessEqThan(32);
    ageOk.in[0] <== dob;
    ageOk.in[1] <== threshold;
    ageOk.out === 1;

    // ---- expiry: expiry > today ----
    component expOk = GreaterThan(32);
    expOk.in[0] <== expiry;
    expOk.in[1] <== today;
    expOk.out === 1;

    // ---- revocation: credId NOT in the SMT with public root `revocationRoot` (20 levels) ----
    component rCred = Num2Bits(20);   rCred.in <== credId;      // key must fit the 20 SMT levels
    isOld0 * (1 - isOld0) === 0;                                // boolean (not enforced inside SMTVerifier)
    component smt = SMTVerifier(REV_LEVELS);
    smt.enabled <== 1;
    smt.fnc <== 1;                                              // 1 = non-inclusion
    smt.root <== revocationRoot;
    for (var i = 0; i < REV_LEVELS; i++) smt.siblings[i] <== siblings[i];
    smt.oldKey <== oldKey;
    smt.oldValue <== oldValue;
    smt.isOld0 <== isOld0;
    smt.key <== credId;
    smt.value <== 0;                                            // ignored for non-inclusion

    // ---- nullifier = Poseidon(holderSecret, verifierId, nonce); also constrains nonce ----
    component nf = Poseidon(3);
    nf.inputs[0] <== holderSecret;
    nf.inputs[1] <== verifierId;
    nf.inputs[2] <== nonce;
    nullifier <== nf.out;
}

component main {public [issuerAx, issuerAy, today, minAge, nameValue, uniValue, verifierId, nonce, revocationRoot]} = SelectiveDisclosure(4);