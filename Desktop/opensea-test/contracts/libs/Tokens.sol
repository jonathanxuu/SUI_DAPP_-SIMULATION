pragma solidity >=0.8.0 <0.9.0;

//SPDX-License-Identifier: MIT
library Tokens {
    bytes32 public constant MINT_TYPEHASH =
        keccak256(
            "signature(address recipient,bytes32 ctype,bytes32 programHash,bytes32 digest,address verifier,address attester,uint64[] output,uint64 issuanceTimestamp,expirationTimestamp,bytes2 vcVersion,string sbtFigure)"
        );
    struct Token {
        address recipient;
        bytes32 ctype;
        bytes32 programHash;
        bytes32 digest;
        address verifier;
        address attester;
        uint64[] output;
        uint64 issuanceTimestamp;
        uint64 expirationTimestamp; // todo: optional one? maybe revoked by some special registry
        bytes2 vcVersion;
        string sbtFigure;
    }

    struct TokenOnChain {
        address recipient;
        bytes32 ctype;
        bytes32 programHash;
        bytes32 digest;
        address attester;
        uint64[] output;
        uint64 mintTimestamp;
        uint64 issuanceTimestamp;
        uint64 expirationTimestamp; //todo: optional one? maybe revoked by some special registry
        bytes2 vcVersion;
        string sbtFigure;
    }

   // todo: function sbt mint to a contract 


    function fillTokenOnChain(
        Token memory token,
        uint64 time,
        address realRecipient
    ) public pure returns (TokenOnChain memory tokenOnchain) {
        tokenOnchain.recipient = realRecipient;
        tokenOnchain.ctype = token.ctype;
        tokenOnchain.programHash = token.programHash;
        tokenOnchain.digest = token.digest;
        tokenOnchain.attester = token.attester;
        tokenOnchain.output = token.output;
        tokenOnchain.issuanceTimestamp = token.issuanceTimestamp;
        tokenOnchain.expirationTimestamp = token.expirationTimestamp;
        tokenOnchain.vcVersion = token.vcVersion;
        tokenOnchain.sbtFigure = token.sbtFigure;
        tokenOnchain.mintTimestamp = time;
    }

    function getRecipient(
        Token memory tokenDetail
    ) public pure returns (address) {
        return tokenDetail.recipient;
    }

    function verifySignature(
        Token memory tokenDetail,
        bytes memory signature
    ) public pure returns (bool) {
        bytes32 structHash = keccak256(
            abi.encode(
                MINT_TYPEHASH,
                tokenDetail.recipient,
                tokenDetail.ctype,
                tokenDetail.programHash,
                tokenDetail.digest,
                tokenDetail.verifier,
                tokenDetail.attester,
                tokenDetail.output,
                tokenDetail.issuanceTimestamp,
                tokenDetail.expirationTimestamp,
                tokenDetail.vcVersion,
                tokenDetail.sbtFigure
            )
        );

        if (_recover(structHash, signature) != tokenDetail.verifier) {
            return false;
        }
        return true;
    }

    /**
     * @dev parse the signature, and recover the signer address
     * @param hash, the messageHash which the signer signed
     * @param sig, the signature
     */
    function _recover(
        bytes32 hash,
        bytes memory sig
    ) internal pure returns (address) {
        bytes32 r;
        bytes32 s;
        uint8 v;

        // Check the signature length
        if (sig.length != 65) {
            return (address(0));
        }

        // Divide the signature in r, s and v variables
        // ecrecover takes the signature parameters, and the only way to get them
        // currently is to use assembly.
        // solium-disable-next-line security/no-inline-assembly
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }

        // Version of signature should be 27 or 28, but 0 and 1 are also possible versions
        if (v < 27) {
            v += 27;
        }

        // If the version is correct return the signer address
        if (v != 27 && v != 28) {
            return (address(0));
        } else {
            // solium-disable-next-line arg-overflow
            return ecrecover(hash, v, r, s);
        }
    }
}
