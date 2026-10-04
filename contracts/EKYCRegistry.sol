// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

interface IGroth16Verifier {
    function verifyProof(
        uint[2] calldata _pA, uint[2][2] calldata _pB, uint[2] calldata _pC, uint[10] calldata _pubSignals
    ) external view returns (bool);
}

/// Public signals (SPEC order):
/// [0 nullifier, 1 issuerAx, 2 issuerAy, 3 today, 4 minAge, 5 nameValue, 6 uniValue, 7 verifierId, 8 nonce, 9 revocationRoot]
contract EKYCRegistry {
    IGroth16Verifier public immutable verifier;
    address public owner;
    mapping(address => bool) public issuers;          // may publish revocation roots
    mapping(bytes32 => bool) public issuerKeys;       // keccak256(Ax, Ay) of trusted EdDSA issuer keys
    uint256 public revocationRoot;                    // SMT root of revoked credIds (0 = empty tree)
    mapping(uint256 => bool) public usedNullifier;

    event IssuerSet(address indexed issuer, bool ok);
    event IssuerKeySet(bytes32 indexed keyHash, bool ok);
    event RevocationRootUpdated(uint256 indexed oldRoot, uint256 indexed newRoot, address indexed by);
    event Verified(uint256 indexed nullifier, uint256 verifierId, uint256 minAge);

    constructor(address _verifier) { verifier = IGroth16Verifier(_verifier); owner = msg.sender; }

    modifier onlyOwner() { require(msg.sender == owner, "owner only"); _; }

    function setIssuer(address a, bool ok) external onlyOwner { issuers[a] = ok; emit IssuerSet(a, ok); }

    function setIssuerKey(uint256 ax, uint256 ay, bool ok) external onlyOwner {
        bytes32 h = keccak256(abi.encodePacked(ax, ay));
        issuerKeys[h] = ok; emit IssuerKeySet(h, ok);
    }

    function setRevocationRoot(uint256 newRoot) external {
        require(issuers[msg.sender], "not an issuer");
        emit RevocationRootUpdated(revocationRoot, newRoot, msg.sender);
        revocationRoot = newRoot;
    }

    function verifyCredentialProof(
        uint[2] calldata a, uint[2][2] calldata b, uint[2] calldata c, uint[10] calldata pub
    ) external returns (bool) {
        require(pub[9] == revocationRoot, "stale revocation root");
        require(issuerKeys[keccak256(abi.encodePacked(pub[1], pub[2]))], "issuer key not registered");
        require(_dateOk(pub[3]), "today out of range");
        // verifierId is a public input of the proof: binding it to the caller stops a front-runner
        // from replaying someone else's proof as their own verification.
        require(pub[7] == uint256(uint160(msg.sender)), "verifierId != caller");
        require(!usedNullifier[pub[0]], "nullifier used");
        usedNullifier[pub[0]] = true;
        require(verifier.verifyProof(a, b, c, pub), "bad proof");
        emit Verified(pub[0], pub[7], pub[4]);
        return true;
    }

    /// SPEC: `today` must equal the UTC date of block.timestamp or of the previous day (YYYYMMDD).
    function _dateOk(uint256 today) internal view returns (bool) {
        return today == _ymd(block.timestamp) || today == _ymd(block.timestamp - 1 days);
    }

    /// days-since-epoch -> civil date (H. Hinnant), returned as YYYYMMDD.
    function _ymd(uint256 ts) internal pure returns (uint256) {
        int256 z = int256(ts / 1 days) + 719468;
        int256 era = z / 146097;
        int256 doe = z - era * 146097;
        int256 yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
        int256 y = yoe + era * 400;
        int256 doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        int256 mp = (5 * doy + 2) / 153;
        int256 d = doy - (153 * mp + 2) / 5 + 1;
        int256 m = mp < 10 ? mp + 3 : mp - 9;
        if (m <= 2) y += 1;
        return uint256(y) * 10000 + uint256(m) * 100 + uint256(d);
    }
}