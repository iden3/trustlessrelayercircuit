const snarkjs = require("snarkjs");
const mimc7 = require("circomlib").mimc7;
const bigInt = snarkjs.bigInt;


exports.buildClaim_AuthorizeKey = (obj) => {
    const res = Object.assign({}, obj);

    const CLAIMTYPE = 1;
    let i2 = bigInt(CLAIMTYPE);
    const sign = obj.publicKey[0].greater(snarkjs.bn128.Fr.q.shr(1)) ? bigInt.one : bigInt.zero;
    i2 = i2.add(sign.shl(96));
    const i1 = obj.publicKey[1];

    res.hi = mimc7.multiHash([i1, i2]);

    const v1 = bigInt(0);
    const v2 = bigInt(0);

    res.hv = mimc7.multiHash([v1, v2]);
    return res;
};

exports.buildClaim_RevokeKey = (obj) => {
    const res = Object.assign({}, obj);

    const CLAIMTYPE = 1;
    let i2 = bigInt(CLAIMTYPE);
    const sign = obj.publicKey[0].greater(snarkjs.bn128.Fr.q.shr(1)) ? bigInt.one : bigInt.zero;
    i2 = i2.add(bigInt.one.shl(64));
    i2 = i2.add(sign.shl(96));
    const i1 = obj.publicKey[1];

    res.hi = mimc7.multiHash([i1, i2]);

    const v1 = bigInt(0);
    const v2 = bigInt(0);

    res.hv = mimc7.multiHash([v1, v2]);
    return res;
};

exports.buildClaim_UserRoot = (obj)  => {
    const res = Object.assign({}, obj);

    const CLAIMTYPE = 2;
    let i2 = bigInt(CLAIMTYPE);
    i2 = i2.add(bigInt(obj.version).shl(64));
    i2 = i2.add(bigInt(obj.era).shl(96));

    const i1 = bigInt(obj.idIdentity);

    res.hi = mimc7.multiHash([i1, i2]);

    const v1 = bigInt(0);
    const v2 = bigInt(obj.root);

    res.hv = mimc7.multiHash([v1, v2]);
    return res;
};
