const chai = require("chai");
const snarkjs = require("snarkjs");
const smt = require("circomlib").smt;
const eddsa = require("circomlib").eddsa;
const mimc7 = require("circomlib").mimc7;
const iden3 = require("../src/iden3");

const assert = chai.assert;
const expect = chai.expect;

const bigInt = snarkjs.bigInt;

describe("Claim test vectors", function () {

    it("Test claim set root key", () => {
        idIdentity = bigInt("0x393939393939393939393939393939393939393a");
        //idIdentity = bigInt("0x3a39393939393939393939393939393939393939");
        const userRootClaim = iden3.buildClaim_UserRoot({
            idIdentity: idIdentity,
            era: 1,
            version: 1,
            root: "0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0c"
            //root: "0x0c0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
        });
        expect("0x" + userRootClaim.hi.toString(16)).to.be.equal(
            "0xf92abb8209409736929512c2018467a497ed35f409bb90579c62b9a4e0b2aa8");
        expect("0x" + userRootClaim.hv.toString(16)).to.be.equal(
            "0xad7edbf562757b1ad2282c44e2c248f95e9e6b09ba0d32809aa724fbf148e0c");
    });
});
