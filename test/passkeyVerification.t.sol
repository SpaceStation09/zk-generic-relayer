// SPDX-License-Identifier: MIT

pragma solidity ^0.8.22;

import {Test} from "forge-std/Test.sol";
import "../src/Wallet.sol";
import "../src/lib/P256.sol";
import "../src/test/P256Verifier.sol";
import "../src/lib/WebAuthn.sol";

contract WalletTest is Test {
    Wallet account;
    uint256[2] public pubkey = [
        0xaa3067e5e558f595b522eda47a4528f987ba4487ddb110b26fdb426e9b36eb56,
        0x0ad8b9eb183479970810e841806fe70142b503d2b7784feb690ac5dfc05ccb32
    ];

    function setUp() public{
        vm.etch(P256.VERIFIER, type(P256Verifier).runtimeCode);
        account = new Wallet(address(0), address(0), address(0)); // Dummy email auth part
        account.addTestPasskey(pubkey);
    }

    function testPasskeyVerification() public {
        string memory clientDataJSON =
            '{"type":"webauthn.get","challenge":"a6827678-a8cf-4469-ae32-b2189855f424","origin":"http://localhost:8081","crossOrigin":false}';
        bytes memory challenge = hex"61363832373637382d613863662d343436392d616533322d623231383938353566343234";
        bytes memory authenticatorData =
            hex"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97630500000000";
        uint256 r =
            0xebb05036a30ddfb87e4cf5a382bf32df58437ffb419da2dc724e9f0bad1473f6;
        uint256 s =
            0xc7e10933183436c8f3c49da790c025ef6d8432c7c16abe0c3b6d1d03777dc3d0;
        uint256 challengeLocation = 23;
        uint256 responseTypeLocation = 1;

        bool ret = account.checkPasskeySig(
            challenge,
            authenticatorData,
            clientDataJSON,
            challengeLocation,
            responseTypeLocation,
            r,
            s
        );
        assertEq(ret, true);
    }
}