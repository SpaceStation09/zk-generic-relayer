// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

struct Signature {
    bytes authenticatorData;
    string clientDataJSON;
    uint256 challengeLocation;
    uint256 responseTypeLocation;
    uint r;
    uint s;
}

struct Call {
    address dest;
    uint value;
    bytes data;
}
