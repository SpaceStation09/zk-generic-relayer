// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {WebAuthn} from "./lib/WebAuthn.sol";

struct Signature {
    bytes authenticatorData;
    string clientDataJSON;
    uint256 challengeLocation;
    uint256 responseTypeLocation;
    uint r;
    uint s;
}

contract SignatureVerifier {
    uint[2] pubkey;

    constructor(uint[2] memory _pubkey) {
        pubkey = _pubkey;
    }

    function verifySig(
        bytes calldata signature,
        bytes memory message
    ) public view returns (bool) {
        Signature memory sig = abi.decode(signature, (Signature));

        return
            WebAuthn.verifySignature({
                challenge: message,
                authenticatorData: sig.authenticatorData,
                requireUserVerification: true,
                clientDataJSON: sig.clientDataJSON,
                challengeLocation: sig.challengeLocation,
                responseTypeLocation: sig.responseTypeLocation,
                r: sig.r,
                s: sig.s,
                x: uint(pubkey[0]),
                y: uint(pubkey[1])
            });
    }
}
