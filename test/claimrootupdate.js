const chai = require("chai");
const path = require("path");
const snarkjs = require("snarkjs");
const compiler = require("circom");
const smt = require("circomlib").smt;
const eddsa = require("circomlib").eddsa;
const mimc7 = require("circomlib").mimc7;
const fs = require("fs");
const iden3 = require("../src/iden3");

const assert = chai.assert;

const bigInt = snarkjs.bigInt;

describe("Claim root update TX", function () {
    let circuit;
    let relayTree;
    let userTree;
    let idIdentity;
    let prvKey1;
    let pubKey1;
    let prvKey2;
    let pubKey2;
    let prvKey3;
    let pubKey3;
    this.timeout(10000000);
    before( async() => {
        const cirDef = await compiler(path.join(__dirname, "circuits", "claimrootupdate_test.circom"));

//        fs.writeFileSync("claimrootupdate_test.json", JSON.stringify(cirDef, null, 1), "utf8");

//        const cirDef = JSON.parse(fs.readFileSync("claimrootupdate_test.json", "utf8"));

        circuit = new snarkjs.Circuit(cirDef);

        console.log("NConstrains ClaimRootUpdate: " + circuit.nConstraints);

        relayTree = await smt.newMemEmptyTrie();
        userTree = await smt.newMemEmptyTrie();
        idIdentity = bigInt("1234");
        prvKey1 = Buffer.from("0001020304050607080900010203040506070809000102030405060708090001", "hex");
        pubKey1 = eddsa.prv2pub(prvKey1);
        prvKey2 = Buffer.from("0001020304050607080900010203040506070809000102030405060708090002", "hex");
        pubKey2 = eddsa.prv2pub(prvKey2);
        prvKey3 = Buffer.from("0001020304050607080900010203040506070809000102030405060708090003", "hex");
        pubKey3 = eddsa.prv2pub(prvKey3);

    });

    it("Should create a new tree for a new identity", async () => {

        const authorizeKeyClaim = iden3.buildClaim_AuthorizeKey({
            publicKey: pubKey1
        });
        await userTree.insert(authorizeKeyClaim.hi, authorizeKeyClaim.hv);

        const userRootClaim = iden3.buildClaim_UserRoot({
            idIdentity: idIdentity,
            era: 0,
            version: 0,
            root: userTree.root
        });

        const res = await relayTree.insert(userRootClaim.hi, userRootClaim.hv);

        const m = mimc7.multiHash([bigInt("1234123412341234"),userRootClaim.hi, userRootClaim.hv ]);
        const signature = eddsa.signMiMC(prvKey1, m);

        const zeroSiblings10 = new Array(10).fill(0);
        let relayerInsert_siblings = res.siblings;
        while (relayerInsert_siblings.length<10) relayerInsert_siblings.push(bigInt(0));

        const input = {
            oldRelayerRoot: res.oldRoot,
            newRelayerRoot: res.newRoot,
            oldUserRoot: 0,
            idIdentity: idIdentity,
            era: 0,
            newUserRoot: userTree.root,
            newUserRootVersion: 0,
            sigKeyX: pubKey1[0],
            sigKeyY: pubKey1[1],
            sigS: signature.S,
            sigR8x: signature.R8[0],
            sigR8y: signature.R8[1],
            signingKeyInclussion_siblings: zeroSiblings10,
            signingKeyExclusion_siblings: zeroSiblings10,
            signingKeyExclusion_oldKey: 0,
            signingKeyExclusion_oldValue: 0,
            signingKeyExclusion_isOld0: 0,
            oldRootInclusion_siblings: zeroSiblings10,
            relayerInsert_siblings: relayerInsert_siblings,
            relayerInsert_oldKey: res.isOld0 ? 0 : res.oldKey,
            relayerInsert_oldValue: res.isOld0 ? 0 : res.oldValue,
            relayerInsert_isOld0: res.isOld0 ? 1 : 0,
        };

        const w = circuit.calculateWitness(input);

        assert(circuit.checkWitness(w));

    });

    it("Should check an insert to a new root", async () => {


        const signingKeyClaim = iden3.buildClaim_AuthorizeKey({
            publicKey: pubKey1
        });
        const revokeKeyClaim = iden3.buildClaim_RevokeKey({
            publicKey: pubKey1
        });
        const newAuthorizedKeyClaim = iden3.buildClaim_AuthorizeKey({
            publicKey: pubKey2
        });

        const resKeyInclusion = await userTree.find(signingKeyClaim.hi);
        let signingKeyInclussion_siblings = resKeyInclusion.siblings;
        while (signingKeyInclussion_siblings.length<10) signingKeyInclussion_siblings.push(bigInt(0));

        const resKeyExclusion = await userTree.find(revokeKeyClaim.hi);
        let signingKeyExclussion_siblings = resKeyExclusion.siblings;
        while (signingKeyExclussion_siblings.length<10) signingKeyExclussion_siblings.push(bigInt(0));

        const resUser = await userTree.insert(newAuthorizedKeyClaim.hi, newAuthorizedKeyClaim.hv);

        const newUserRootClaim = iden3.buildClaim_UserRoot({
            idIdentity: idIdentity,
            era: 0,
            version: 1,
            root: resUser.newRoot
        });
        const oldUserRootClaim = iden3.buildClaim_UserRoot({
            idIdentity: idIdentity,
            era: 0,
            version: 0,
            root: resUser.oldRoot
        });

        const resOldRootInclusion = await relayTree.find(oldUserRootClaim.hi);
        let oldRootInclusion_siblings = resOldRootInclusion.siblings;
        while (oldRootInclusion_siblings.length<10) oldRootInclusion_siblings.push(bigInt(0));

        const resRelay = await relayTree.insert(newUserRootClaim.hi, newUserRootClaim.hv);

        const m = mimc7.multiHash([bigInt("1234123412341234"),newUserRootClaim.hi, newUserRootClaim.hv ]);
        const signature = eddsa.signMiMC(prvKey1, m);



        let relayerInsert_siblings = resRelay.siblings;
        while (relayerInsert_siblings.length<10) relayerInsert_siblings.push(bigInt(0));

        const input = {
            oldRelayerRoot: resRelay.oldRoot,
            newRelayerRoot: resRelay.newRoot,
            oldUserRoot: resUser.oldRoot,
            idIdentity: idIdentity,
            era: 0,
            newUserRoot: resUser.newRoot,
            newUserRootVersion: 1,
            sigKeyX: pubKey1[0],
            sigKeyY: pubKey1[1],
            sigS: signature.S,
            sigR8x: signature.R8[0],
            sigR8y: signature.R8[1],
            signingKeyInclussion_siblings: signingKeyInclussion_siblings,
            signingKeyExclusion_siblings: signingKeyExclussion_siblings,
            signingKeyExclusion_oldKey: resKeyExclusion.isOld0 ? 0 : resKeyExclusion.notFoundKey,
            signingKeyExclusion_oldValue: resKeyExclusion.isOld0 ? 0 : resKeyExclusion.notFoundValue,
            signingKeyExclusion_isOld0: resKeyExclusion.isOld0 ? 1 : 0,
            oldRootInclusion_siblings: oldRootInclusion_siblings,
            relayerInsert_siblings: relayerInsert_siblings,
            relayerInsert_oldKey: resRelay.isOld0 ? 0 : resRelay.oldKey,
            relayerInsert_oldValue: resRelay.isOld0 ? 0 : resRelay.oldValue,
            relayerInsert_isOld0: resRelay.isOld0 ? 1 : 0,
        };

        const w = circuit.calculateWitness(input);

        assert(circuit.checkWitness(w));

    });

    it("Revoke key 1 with key 2", async () => {
        const signingKeyClaim = iden3.buildClaim_AuthorizeKey({
            publicKey: pubKey2
        });
        const revokeKeyClaim = iden3.buildClaim_RevokeKey({
            publicKey: pubKey2
        });
        const newRevocationKeyClaim = iden3.buildClaim_RevokeKey({
            publicKey: pubKey1
        });

        const resKeyInclusion = await userTree.find(signingKeyClaim.hi);
        let signingKeyInclussion_siblings = resKeyInclusion.siblings;
        while (signingKeyInclussion_siblings.length<10) signingKeyInclussion_siblings.push(bigInt(0));

        const resKeyExclusion = await userTree.find(revokeKeyClaim.hi);
        let signingKeyExclussion_siblings = resKeyExclusion.siblings;
        while (signingKeyExclussion_siblings.length<10) signingKeyExclussion_siblings.push(bigInt(0));

        const resUser = await userTree.insert(newRevocationKeyClaim.hi, newRevocationKeyClaim.hv);

        const newUserRootClaim = iden3.buildClaim_UserRoot({
            idIdentity: idIdentity,
            era: 0,
            version: 2,
            root: resUser.newRoot
        });
        const oldUserRootClaim = iden3.buildClaim_UserRoot({
            idIdentity: idIdentity,
            era: 0,
            version: 1,
            root: resUser.oldRoot
        });

        const resOldRootInclusion = await relayTree.find(oldUserRootClaim.hi);
        let oldRootInclusion_siblings = resOldRootInclusion.siblings;
        while (oldRootInclusion_siblings.length<10) oldRootInclusion_siblings.push(bigInt(0));

        const resRelay = await relayTree.insert(newUserRootClaim.hi, newUserRootClaim.hv);

        const m = mimc7.multiHash([bigInt("1234123412341234"),newUserRootClaim.hi, newUserRootClaim.hv ]);
        const signature = eddsa.signMiMC(prvKey2, m);



        let relayerInsert_siblings = resRelay.siblings;
        while (relayerInsert_siblings.length<10) relayerInsert_siblings.push(bigInt(0));

        const input = {
            oldRelayerRoot: resRelay.oldRoot,
            newRelayerRoot: resRelay.newRoot,
            oldUserRoot: resUser.oldRoot,
            idIdentity: idIdentity,
            era: 0,
            newUserRoot: resUser.newRoot,
            newUserRootVersion: 2,
            sigKeyX: pubKey2[0],
            sigKeyY: pubKey2[1],
            sigS: signature.S,
            sigR8x: signature.R8[0],
            sigR8y: signature.R8[1],
            signingKeyInclussion_siblings: signingKeyInclussion_siblings,
            signingKeyExclusion_siblings: signingKeyExclussion_siblings,
            signingKeyExclusion_oldKey: resKeyExclusion.isOld0 ? 0 : resKeyExclusion.notFoundKey,
            signingKeyExclusion_oldValue: resKeyExclusion.isOld0 ? 0 : resKeyExclusion.notFoundValue,
            signingKeyExclusion_isOld0: resKeyExclusion.isOld0 ? 1 : 0,
            oldRootInclusion_siblings: oldRootInclusion_siblings,
            relayerInsert_siblings: relayerInsert_siblings,
            relayerInsert_oldKey: resRelay.isOld0 ? 0 : resRelay.oldKey,
            relayerInsert_oldValue: resRelay.isOld0 ? 0 : resRelay.oldValue,
            relayerInsert_isOld0: resRelay.isOld0 ? 1 : 0,
        };

        const w = circuit.calculateWitness(input);

        assert(circuit.checkWitness(w));

    });

    it("Try to authorize key 3 with key 1 and fail", async () => {
        const signingKeyClaim = iden3.buildClaim_AuthorizeKey({
            publicKey: pubKey1
        });
        const revokeKeyClaim = iden3.buildClaim_RevokeKey({
            publicKey: pubKey1
        });
        const newAuthorizedKeyClaim = iden3.buildClaim_AuthorizeKey({
            publicKey: pubKey3
        });

        const resKeyInclusion = await userTree.find(signingKeyClaim.hi);
        let signingKeyInclussion_siblings = resKeyInclusion.siblings;
        while (signingKeyInclussion_siblings.length<10) signingKeyInclussion_siblings.push(bigInt(0));

        // Force a different key.
        const resKeyExclusion = await userTree.find(revokeKeyClaim.hi.add(bigInt.one));
        let signingKeyExclussion_siblings = resKeyExclusion.siblings;
        while (signingKeyExclussion_siblings.length<10) signingKeyExclussion_siblings.push(bigInt(0));

        const resUser = await userTree.insert(newAuthorizedKeyClaim.hi, newAuthorizedKeyClaim.hv);

        const newUserRootClaim = iden3.buildClaim_UserRoot({
            idIdentity: idIdentity,
            era: 0,
            version: 3,
            root: resUser.newRoot
        });
        const oldUserRootClaim = iden3.buildClaim_UserRoot({
            idIdentity: idIdentity,
            era: 0,
            version: 2,
            root: resUser.oldRoot
        });

        const resOldRootInclusion = await relayTree.find(oldUserRootClaim.hi);
        let oldRootInclusion_siblings = resOldRootInclusion.siblings;
        while (oldRootInclusion_siblings.length<10) oldRootInclusion_siblings.push(bigInt(0));

        const resRelay = await relayTree.insert(newUserRootClaim.hi, newUserRootClaim.hv);

        const m = mimc7.multiHash([bigInt("1234123412341234"),newUserRootClaim.hi, newUserRootClaim.hv ]);
        const signature = eddsa.signMiMC(prvKey1, m);



        let relayerInsert_siblings = resRelay.siblings;
        while (relayerInsert_siblings.length<10) relayerInsert_siblings.push(bigInt(0));

        const input = {
            oldRelayerRoot: resRelay.oldRoot,
            newRelayerRoot: resRelay.newRoot,
            oldUserRoot: resUser.oldRoot,
            idIdentity: idIdentity,
            era: 0,
            newUserRoot: resUser.newRoot,
            newUserRootVersion: 3,
            sigKeyX: pubKey1[0],
            sigKeyY: pubKey1[1],
            sigS: signature.S,
            sigR8x: signature.R8[0],
            sigR8y: signature.R8[1],
            signingKeyInclussion_siblings: signingKeyInclussion_siblings,
            signingKeyExclusion_siblings: signingKeyExclussion_siblings,
            signingKeyExclusion_oldKey: resKeyExclusion.isOld0 ? 0 : resKeyExclusion.notFoundKey,
            signingKeyExclusion_oldValue: resKeyExclusion.isOld0 ? 0 : resKeyExclusion.notFoundValue,
            signingKeyExclusion_isOld0: resKeyExclusion.isOld0 ? 1 : 0,
            oldRootInclusion_siblings: oldRootInclusion_siblings,
            relayerInsert_siblings: relayerInsert_siblings,
            relayerInsert_oldKey: resRelay.isOld0 ? 0 : resRelay.oldKey,
            relayerInsert_oldValue: resRelay.isOld0 ? 0 : resRelay.oldValue,
            relayerInsert_isOld0: resRelay.isOld0 ? 1 : 0,
        };

        try {
            circuit.calculateWitness(input);
            assert(false);
        } catch(err) {
            assert.equal(err.message, "Constraint doesn't match: 1 != 0");
        }

    });
});
